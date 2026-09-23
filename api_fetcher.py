#!/usr/bin/env python3
"""
Veracode Component Matcher - API Data Fetcher

Fetches vulnerability data and SBOM information from all Veracode applications
using getbuildinfo.do and SBOM API endpoints for component matching analysis.
"""

import os
import json
import logging
import datetime
import argparse
import configparser
from typing import Dict, List, Optional, Tuple
from uuid import UUID
from veracode_api_py.api import VeracodeAPI as vapi

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress verbose logging from veracode_api_py library
for lib_name in ['veracode_api_py', 'urllib3', 'requests', 'httpie']:
    logging.getLogger(lib_name).setLevel(logging.CRITICAL)


def load_credentials_from_file() -> Tuple[Optional[str], Optional[str]]:
    """Load API credentials from ~/.veracode/credentials file (default section)"""
    creds_path = os.path.expanduser('~/.veracode/credentials')
    try:
        if os.path.exists(creds_path):
            config = configparser.ConfigParser()
            config.read(creds_path)
            if config.has_section('default'):
                api_id = config.get('default', 'veracode_api_key_id', fallback=None)
                api_key = config.get('default', 'veracode_api_key_secret', fallback=None)
                if api_id and api_key:
                    logger.debug("Loaded credentials from ~/.veracode/credentials (default section)")
                    return api_id, api_key
    except Exception as e:
        logger.debug(f"Failed to load credentials from file: {e}")
    return None, None


def check_credentials_expiration():
    """Check if credentials are valid, expired, or expiring soon"""
    try:
        creds = vapi().get_creds()

        # Check for error responses (invalid credentials)
        if isinstance(creds, dict) and 'error' in creds:
            error_desc = creds.get('error_description', creds.get('error', 'Unknown error'))
            logger.info(f"❌ API credentials are invalid or expired: {error_desc}")
            return False

        # Handle different response types (could be dict, Response object, or other)
        expiration_ts = None
        if isinstance(creds, dict):
            expiration_ts = creds.get('expiration_ts')
        elif hasattr(creds, 'get'):
            try:
                expiration_ts = creds.get('expiration_ts')
            except Exception:
                pass
        elif hasattr(creds, '__getitem__'):
            try:
                expiration_ts = creds['expiration_ts']
            except (KeyError, TypeError):
                logger.debug(f"Could not access expiration_ts from credentials object of type {type(creds)}")
                return False

        if not expiration_ts:
            logger.debug("No expiration_ts found in credentials")
            return False

        exp = datetime.datetime.strptime(expiration_ts, "%Y-%m-%dT%H:%M:%S.%f%z")
        delta = exp - datetime.datetime.now().astimezone()

        if delta.total_seconds() < 0:
            # Credentials are expired
            logger.info(f"❌ API credentials are expired as of {expiration_ts}")
            return False
        elif delta.days < 7:
            # Credentials expiring soon
            logger.info(f"⚠️  API credentials expire in {delta.days} day(s): {expiration_ts}")
            return True
        else:
            # Credentials are valid and not expiring soon
            logger.debug(f"✓ API credentials valid, expire in {delta.days} days")
            return True
    except ValueError as e:
        logger.debug(f"Failed to parse credential expiration time: {e}")
        return False
    except Exception as e:
        logger.debug(f"Failed to check credential expiration: {e}")
        return False


class VeracodeApiFetcher:
    """Fetches data from Veracode APIs using veracode_api_py library"""

    def __init__(self, api_id: Optional[str] = None, api_key: Optional[str] = None):
        """Initialize with credentials using precedence:
        1. Arguments passed to __init__
        2. Environment variables (VERACODE_API_KEY_ID, VERACODE_API_KEY_SECRET)
        3. Credentials file (~/.veracode/credentials default section)
        """
        # Determine credentials using precedence order
        final_api_id = api_id or os.getenv('VERACODE_API_KEY_ID')
        final_api_key = api_key or os.getenv('VERACODE_API_KEY_SECRET')

        if not final_api_id or not final_api_key:
            file_api_id, file_api_key = load_credentials_from_file()
            final_api_id = final_api_id or file_api_id
            final_api_key = final_api_key or file_api_key

        # Determine source for logging
        if api_id and api_key:
            source = "command-line arguments"
        elif os.getenv('VERACODE_API_KEY_ID') and os.getenv('VERACODE_API_KEY_SECRET'):
            source = "environment variables"
        elif final_api_id and final_api_key:
            source = "credentials file"
        else:
            source = "unknown"

        if final_api_id and final_api_key:
            logger.info(f"Using credentials from {source}")
            logger.debug(f"API ID (first 10 chars): {final_api_id[:10]}...")
            # Set environment variables for veracode_api_py to use
            os.environ['veracode_api_key_id'] = final_api_id
            os.environ['veracode_api_key_secret'] = final_api_key
        else:
            raise ValueError("No Veracode API credentials found. Please provide via command-line arguments, environment variables, or ~/.veracode/credentials file")

        try:
            # Initialize the API client - this validates credentials
            self.api = vapi()
            logger.info("Veracode API client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Veracode API client: {e}")
            raise

    def get_all_applications(self) -> List[Dict]:
        """Fetch all applications from Veracode"""
        try:
            apps_response = self.api.get_apps()
            logger.info(f"Fetched {len(apps_response)} applications")
            return apps_response
        except Exception as e:
            logger.error(f"Failed to fetch applications: {e}")
            raise

    def get_build_info(self, app_guid: str) -> Optional[Dict]:
        """
        Fetch vulnerability data using the API

        Args:
            app_guid: Application GUID

        Returns:
            Build info data with vulnerabilities, or None if not available
        """
        try:
            # get_build_info returns raw response that needs to be parsed
            response = self.api.get_build_info(app_guid)
            logger.debug(f"get_build_info response type: {type(response)}")

            if isinstance(response, bytes):
                logger.debug(f"Parsing XML response (length: {len(response)} bytes)")
                import xml.etree.ElementTree as ET
                root = ET.fromstring(response)
                logger.debug(f"XML root tag: {root.tag}")
                # Check if this is an error response
                if root.tag == 'error' or (hasattr(root, 'find') and root.find('error') is not None):
                    logger.debug(f"API returned an error response")
                    return None
                # Convert XML to dict
                result = self._xml_to_dict(root)
                logger.debug(f"Converted XML to dict with keys: {list(result.keys()) if isinstance(result, dict) else 'not a dict'}")
                return result
            elif isinstance(response, dict):
                logger.debug(f"Response is already a dict with keys: {list(response.keys())}")
                return response
            elif response is None:
                logger.debug("Response is None")
                return None
            elif isinstance(response, str):
                logger.warning(f"Response is a string: {response[:200]}")
                return None
            logger.warning(f"Unexpected response type for build info: {type(response)}")
            return None
        except Exception as e:
            logger.debug(f"Failed to fetch build info for app {app_guid}: {e}")
            return None

    def get_sbom(self, application_guid: str) -> Optional[Dict]:
        """
        Fetch SBOM data

        Args:
            application_guid: Application GUID

        Returns:
            SBOM data, or None if not available
        """
        try:
            # Try with vulnerability=True first (includes vulnerability data)
            logger.debug(f"Fetching SBOM for {application_guid} with vulnerability data")
            sbom_data = self.api.get_sbom(app_guid=UUID(application_guid), vulnerability=True)
            logger.info(f"Fetched SBOM for application {application_guid}")
            return sbom_data
        except Exception as e:
            error_str = str(e)
            logger.debug(f"SBOM fetch failed (vulnerability=True): {error_str}")

            # If that fails, try without vulnerability data
            try:
                logger.debug(f"Retrying SBOM fetch for {application_guid} without vulnerability data")
                sbom_data = self.api.get_sbom(app_guid=UUID(application_guid), vulnerability=False)
                logger.info(f"Fetched SBOM for application {application_guid} (without vulnerability data)")
                return sbom_data
            except Exception as e2:
                error_str2 = str(e2)
                # Check for expected 404 errors (no recent scans)
                if "404" in error_str2 or "NOT_FOUND" in error_str2:
                    logger.debug(f"SBOM not available for application {application_guid}: no scans")
                    return None
                logger.debug(f"Failed to fetch SBOM for application {application_guid}: {e2}")
                return None

    @staticmethod
    def _xml_to_dict(element) -> Dict:
        """Convert XML element to dictionary"""
        result = {element.tag: {}}
        for child in element:
            if len(child) == 0:
                result[element.tag][child.tag] = child.text
            else:
                result[element.tag][child.tag] = VeracodeApiFetcher._xml_to_dict(child)
        return result

    def extract_sca_vulnerabilities(self, build_info: Dict) -> List[Dict]:
        """
        Extract SCA component vulnerability data from build info response

        Args:
            build_info: Response from getbuildinfo.do

        Returns:
            List of components with vulnerability data
        """
        components = []

        logger.debug(f"extract_sca_vulnerabilities - input type: {type(build_info)}, keys: {list(build_info.keys()) if isinstance(build_info, dict) else 'N/A'}")

        # Navigate to SCA results in the response structure
        # Adjust path based on actual API response structure
        flaws = build_info.get('build', {}).get('vulnerability', [])
        logger.debug(f"Extracted flaws count: {len(flaws) if isinstance(flaws, list) else 'not a list'}")

        for flaw in flaws:
            component_key = (flaw.get('component_name'), flaw.get('component_version'))

            # Aggregate vulnerabilities by component
            component = next(
                (c for c in components if (c['library_name'], c['library_version']) == component_key),
                None
            )

            if not component:
                component = {
                    'library_name': flaw.get('component_name'),
                    'library_version': flaw.get('component_version'),
                    'sha1': flaw.get('sha1'),
                    'library_id': flaw.get('id'),
                    'vulnerabilities': []
                }
                components.append(component)

            component['vulnerabilities'].append({
                'cve_id': flaw.get('cwe', {}).get('id'),
                'severity': flaw.get('severity'),
                'description': flaw.get('description')
            })

        return components

    def extract_sbom_components(self, sbom_data: Dict) -> List[Dict]:
        """
        Extract components from CycloneDX SBOM data

        Args:
            sbom_data: CycloneDX SBOM JSON

        Returns:
            List of components
        """
        components = []

        # CycloneDX format: metadata.component.components[]
        bom = sbom_data.get('bom', {})
        component_list = bom.get('components', [])

        for comp in component_list:
            component = {
                'name': comp.get('name'),
                'version': comp.get('version'),
                'purl': comp.get('purl'),
                'bom-ref': comp.get('bom-ref'),
                'hashes': {}
            }

            # Extract hashes if present
            if 'hashes' in comp:
                for hash_item in comp.get('hashes', []):
                    component['hashes'][hash_item.get('alg')] = hash_item.get('content')

            components.append(component)

        return components

    def save_to_file(self, data: Dict, filename: str) -> None:
        """Save API response to JSON file"""
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved data to {filename}")




def main():
    """Fetch all apps, collect components, and match them"""
    parser = argparse.ArgumentParser(description='Veracode API Data Fetcher')
    parser.add_argument('--veracode_api_key_id', help='Veracode API Key ID')
    parser.add_argument('--veracode_api_key_secret', help='Veracode API Key Secret')
    parser.add_argument('--limit', type=int, help='Limit number of applications to process (for testing)')
    parser.add_argument('--list-profiles', action='store_true', help='List available credential profiles')

    args = parser.parse_args()

    # Handle --list-profiles
    if args.list_profiles:
        list_profiles()
        return

    # Get limit if specified
    app_limit = args.limit
    if app_limit:
        logger.info(f"Limiting to {app_limit} applications for testing")

    try:
        fetcher = VeracodeApiFetcher(api_id=args.veracode_api_key_id, api_key=args.veracode_api_key_secret)

        # Check credential expiration
        check_credentials_expiration()

        # Get all applications
        apps = fetcher.get_all_applications()
        if not apps:
            logger.error("No applications found")
            return

        # Apply limit if specified
        if app_limit:
            apps = apps[:app_limit]
            logger.info(f"Limited to {len(apps)} applications for testing")

        logger.debug(f"Sample app structure: {apps[0] if apps else 'No apps'}")

        all_sca_components = []
        all_sbom_components = []

        # Process each application
        for idx, app in enumerate(apps):
            # Try multiple possible keys for app name and ID
            app_id = app.get('id') or app.get('legacy_id') or app.get('app_id')
            app_name = app.get('name') or app.get('profile', {}).get('name') or 'Unknown'
            app_guid = app.get('guid') or app.get('application_guid')

            logger.debug(f"App {idx}: id={app_id}, name={app_name}, guid={app_guid}, keys={list(app.keys())}")

            if not app_id and not app_guid:
                logger.warning(f"Skipping app {app_name}: no app_id or guid")
                continue

            logger.info(f"Processing app: {app_name} (GUID: {app_guid})")

            # Get SCA components via build info using GUID
            if app_guid:
                try:
                    build_info = fetcher.get_build_info(app_guid)
                    if build_info:
                        sca_components = fetcher.extract_sca_vulnerabilities(build_info)
                        all_sca_components.extend(sca_components)
                        logger.info(f"  Extracted {len(sca_components)} SCA components")
                except Exception as e:
                    logger.warning(f"  Failed to fetch SCA components for {app_name}: {e}")

            # Get SBOM components
            if app_guid:
                try:
                    sbom_data = fetcher.get_sbom(app_guid)
                    if sbom_data:
                        sbom_components = fetcher.extract_sbom_components(sbom_data)
                        all_sbom_components.extend(sbom_components)
                        logger.info(f"  Extracted {len(sbom_components)} SBOM components")
                except Exception as e:
                    logger.warning(f"  Failed to fetch SBOM components for {app_name}: {e}")

        logger.info(f"Total SCA components collected: {len(all_sca_components)}")
        logger.info(f"Total SBOM components collected: {len(all_sbom_components)}")

        # Match components using established criteria
        from vulnerability_matcher import VulnerabilityMatcher

        matcher = VulnerabilityMatcher()
        matcher.load_sbom_data(all_sbom_components)
        matcher.load_sca_data(all_sca_components)
        matcher.match_all()

        # Display results
        matcher.print_summary()

        # Export results
        matcher.export_matched_csv('matched_components.csv')
        matcher.export_unmatched_csv('unmatched_components.csv')

        # Save raw data
        with open('all_sca_components.json', 'w') as f:
            json.dump(all_sca_components, f, indent=2)

        with open('all_sbom_components.json', 'w') as f:
            json.dump(all_sbom_components, f, indent=2)

    except Exception as e:
        logger.error(f"Error: {e}")
        raise


def list_profiles():
    """List available credential profiles from ~/.veracode/credentials"""
    import configparser

    creds_path = os.path.expanduser('~/.veracode/credentials')
    if not os.path.exists(creds_path):
        print(f"Credentials file not found at {creds_path}")
        print("Note: veracode_api_py supports both credentials file and environment variables")
        return

    try:
        config = configparser.ConfigParser()
        config.read(creds_path)
        profiles = config.sections()

        if not profiles:
            print("No profiles found in credentials file")
            return

        print("Available credential profiles in ~/.veracode/credentials:")
        print("(Use with: python3 api_fetcher.py <profile_name>)")
        print()
        for profile in profiles:
            try:
                api_id = config.get(profile, 'veracode_api_key_id', fallback='<missing>')
                print(f"  - {profile:25} {api_id[:10]}...")
            except Exception as e:
                logger.debug(f"Error reading profile {profile}: {e}")
    except Exception as e:
        print(f"Failed to read credentials file: {e}")


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--list-profiles':
        list_profiles()
    else:
        main()
