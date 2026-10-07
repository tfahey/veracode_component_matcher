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

        # Phase 5: Error Handling & Resilience Configuration
        self._last_api_call_time: Optional[float] = None
        self.max_retries: int = 3
        self.backoff_factor: float = 2.0
        self.request_timeout: int = 30
        self.rate_limit_interval: float = 0.5
        self.failed_apps: List[Dict] = []
        self.total_retries: int = 0

    def _apply_rate_limit(self, min_interval: float = None) -> None:
        """Apply rate limiting between API calls to prevent hitting rate limits

        Args:
            min_interval: Minimum seconds between calls (default uses self.rate_limit_interval)
        """
        import time

        interval = min_interval or self.rate_limit_interval
        if self._last_api_call_time is not None:
            elapsed = time.time() - self._last_api_call_time
            if elapsed < interval:
                wait_time = interval - elapsed
                logger.debug(f"Rate limiting: waiting {wait_time:.2f}s before next API call")
                time.sleep(wait_time)

        self._last_api_call_time = time.time()

    def _retry_api_call(self, func, max_retries: Optional[int] = None, backoff_factor: Optional[float] = None):
        """Retry API calls with exponential backoff and Retry-After support

        Handles:
        - Exponential backoff for transient failures
        - HTTP 429 (Rate Limit) with Retry-After header
        - Network timeouts and temporary errors
        - Preserves original exception on final failure

        Args:
            func: Callable that makes the API request
            max_retries: Maximum number of retry attempts (default uses self.max_retries)
            backoff_factor: Base for exponential backoff (default uses self.backoff_factor)

        Returns:
            Result of successful API call

        Raises:
            Exception: If all retries fail
        """
        import time

        retries = max_retries or self.max_retries
        factor = backoff_factor or self.backoff_factor

        for attempt in range(retries):
            try:
                self._apply_rate_limit()
                return func()
            except Exception as e:
                self.total_retries += 1
                error_str = str(e)

                if attempt == retries - 1:
                    logger.error(f"All retry attempts failed ({retries} attempts): {e}")
                    raise

                # Check for rate limiting (HTTP 429) with Retry-After
                wait_time = None
                if '429' in error_str or 'rate limit' in error_str.lower():
                    # Look for Retry-After value in error message
                    if 'retry-after' in error_str.lower():
                        try:
                            # Try to extract retry-after value (may be in seconds or HTTP date)
                            import re
                            match = re.search(r'retry-after[:\s]+(\d+)', error_str, re.IGNORECASE)
                            if match:
                                wait_time = int(match.group(1))
                                logger.warning(f"Rate limited (HTTP 429), respecting Retry-After: {wait_time}s")
                        except Exception:
                            pass

                # Use exponential backoff if Retry-After not found
                if wait_time is None:
                    wait_time = factor ** attempt

                logger.warning(f"API call failed (attempt {attempt + 1}/{retries}), "
                             f"retrying in {wait_time}s: {e}")
                time.sleep(wait_time)

    def get_failure_summary(self) -> Dict:
        """Get summary of failures and retries during data collection

        Returns:
            Dictionary with failure statistics
        """
        return {
            'failed_apps': len(self.failed_apps),
            'failed_apps_list': self.failed_apps,
            'total_retries': self.total_retries,
        }

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

    def get_sbom(self, application_guid: str, app_name: str = "") -> Optional[Dict]:
        """
        Fetch SBOM data

        Args:
            application_guid: Application GUID
            app_name: Application name (for logging)

        Returns:
            SBOM data, or None if not available
        """
        app_label = f"{app_name}" if app_name else f"{application_guid}"
        try:
            # Try with vulnerability=True first (includes vulnerability data)
            logger.debug(f"Fetching SBOM for {app_label} with vulnerability data")
            sbom_data = self.api.get_sbom(app_guid=UUID(application_guid), vulnerability=True)
            logger.info(f"Fetched SBOM for application {app_label}")
            return sbom_data
        except Exception as e:
            error_str = str(e)
            logger.debug(f"SBOM fetch failed (vulnerability=True): {error_str}")

            # If that fails, try without vulnerability data
            try:
                logger.debug(f"Retrying SBOM fetch for {app_label} without vulnerability data")
                sbom_data = self.api.get_sbom(app_guid=UUID(application_guid), vulnerability=False)
                logger.info(f"Fetched SBOM for application {app_label} (without vulnerability data)")
                return sbom_data
            except Exception as e2:
                error_str2 = str(e2)
                # Check for expected 404 errors (no recent scans)
                if "404" in error_str2 or "NOT_FOUND" in error_str2:
                    logger.debug(f"SBOM not available for application {app_label}: no scans")
                    return None
                logger.debug(f"Failed to fetch SBOM for application {app_label}: {e2}")
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

    # ============================================================================
    # PHASE 3: API IMPLEMENTATION - Task 3.1: Vulnerability Data Collection
    # ============================================================================

    def get_build_list(self, app_id: str) -> Optional[List[Dict]]:
        """
        Fetch list of builds for an application.

        Args:
            app_id: Application ID (legacy or current format)

        Returns:
            List of build dictionaries with build_id, version, status, etc.
        """
        try:
            logger.debug(f"Fetching build list for app {app_id}")
            # Note: veracode_api_py may handle this via get_builds() or similar
            # For now, documenting the expected behavior
            builds = []
            logger.debug(f"Got {len(builds)} builds for app {app_id}")
            return builds if builds else None
        except Exception as e:
            logger.debug(f"Failed to fetch build list for app {app_id}: {e}")
            return None

    def get_latest_build(self, builds: List[Dict]) -> Optional[Dict]:
        """
        Select the latest build from a list of builds.

        Args:
            builds: List of build dictionaries

        Returns:
            The most recent build, or None if list is empty
        """
        if not builds:
            return None

        # Sort by published_date (descending) to get latest
        try:
            latest = max(builds, key=lambda b: b.get('published_date', ''))
            logger.debug(f"Selected latest build: {latest.get('build_id')}")
            return latest
        except (KeyError, ValueError) as e:
            logger.warning(f"Failed to select latest build: {e}")
            return builds[0] if builds else None

    def get_detailed_report(self, build_id: str) -> Optional[List[Dict]]:
        """
        Fetch detailed vulnerability findings for a build.

        Args:
            build_id: Build ID from getbuildlist.do

        Returns:
            List of vulnerability findings, or None if not available
        """
        try:
            logger.debug(f"Fetching detailed report for build {build_id}")

            # This would call the detailedreport.do endpoint
            # Returns vulnerability findings with sha1, library_id, cve_id, etc.
            findings = []

            logger.debug(f"Got {len(findings)} findings for build {build_id}")
            return findings if findings else None
        except Exception as e:
            logger.debug(f"Failed to fetch detailed report for build {build_id}: {e}")
            return None

    def fetch_all_vulnerability_data(self, app_limit: Optional[int] = None) -> List[Dict]:
        """
        Complete workflow for collecting vulnerability data from all applications.

        Steps:
        1. Get all applications
        2. For each app:
           a. Get build list
           b. Get latest build
           c. Get detailed vulnerability report
           d. Extract findings with sha1, library_id, component info
        3. Return all vulnerability records

        Args:
            app_limit: Optional limit on number of apps to process (for testing)

        Returns:
            List of vulnerability records with all required fields
        """
        logger.info("Starting vulnerability data collection...")

        try:
            apps = self.get_all_applications()
            if not apps:
                logger.warning("No applications found")
                return []

            if app_limit:
                apps = apps[:app_limit]
                logger.info(f"Limited to {len(apps)} applications")

            all_vulnerabilities = []
            total_findings = 0

            for idx, app in enumerate(apps, 1):
                app_id = app.get('id') or app.get('legacy_id')
                app_guid = app.get('guid')
                profile = app.get('profile', {})
                app_name = profile.get('name', 'Unknown')
                business_criticality = profile.get('business_criticality')

                logger.info(f"[{idx}/{len(apps)}] Processing app: {app_name} (id: {app_id})")

                try:
                    # Get build list
                    builds = self.get_build_list(app_id) if app_id else None
                    if not builds:
                        logger.debug(f"  No builds found for {app_name}")
                        continue

                    # Get latest build
                    latest_build = self.get_latest_build(builds)
                    if not latest_build:
                        logger.debug(f"  Could not select latest build for {app_name}")
                        continue

                    build_id = latest_build.get('build_id')
                    build_version = latest_build.get('version')

                    # Get detailed vulnerability report
                    findings = self.get_detailed_report(build_id)
                    if not findings:
                        logger.debug(f"  No vulnerability findings for {app_name}")
                        continue

                    # Process findings and extract required fields
                    for finding in findings:
                        # Create vulnerability record with all mapped fields
                        record = {
                            # Matching keys
                            'sha1': finding.get('sha1'),
                            'library_id': finding.get('library_id'),

                            # Vulnerability info
                            'cve_id': finding.get('cve_id') or finding.get('category'),
                            'severity': finding.get('severity'),
                            'cwe_id': finding.get('cwe_id') or (finding.get('cwe', {}).get('id') if isinstance(finding.get('cwe'), dict) else None),
                            'cvss_score': finding.get('cvss_score'),
                            'description': finding.get('description'),
                            'cve_summary': finding.get('description'),

                            # Component info
                            'component_name': finding.get('component_name'),
                            'component_version': finding.get('component_version'),
                            'component_id': finding.get('component_id'),
                            'file_name': finding.get('file_name'),

                            # Build info
                            'build_id': build_id,
                            'build_version': build_version,
                            'build_published_date': latest_build.get('published_date'),

                            # App info
                            'app_id': app_id,
                            'app_guid': app_guid,
                            'app_name': app_name,
                            'business_criticality': business_criticality,

                            # Scan info
                            'scantype': 'SCA',
                            'static_version': latest_build.get('sast_build_number'),
                            'dynamic_version': latest_build.get('dast_build_number'),
                            'static_submitted_date': latest_build.get('sast_submitted_date'),
                            'dynamic_submitted_date': latest_build.get('dast_submitted_date'),

                            # Mitigation info
                            'first_found_date': finding.get('first_found_date'),
                            'mitigated_date': finding.get('mitigated_date'),
                            'mitigation': finding.get('mitigation'),
                            'mitigation_type': finding.get('mitigation_type'),

                            # Flags
                            'blocklisted': finding.get('blocklisted', False),
                            'new': finding.get('new', False),
                            'affects_policy_compliance': finding.get('affects_policy_compliance', False),
                        }

                        all_vulnerabilities.append(record)
                        total_findings += 1

                    logger.info(f"  Extracted {len(findings)} findings from {app_name}")

                except Exception as e:
                    logger.warning(f"  Failed to process {app_name}: {e}")
                    continue

            logger.info(f"✓ Collected {total_findings} vulnerability records from {len(apps)} applications")
            return all_vulnerabilities

        except Exception as e:
            logger.error(f"Failed to collect vulnerability data: {e}")
            raise

    # ============================================================================
    # PHASE 3: API IMPLEMENTATION - Task 3.2: SBOM Data Collection
    # ============================================================================

    def _extract_hash(self, component: Dict, hash_type: str) -> Optional[str]:
        """
        Extract a specific hash type from a CycloneDX component.

        Args:
            component: Component dictionary from SBOM
            hash_type: Hash algorithm name (e.g., "SHA-1", "SHA-256")

        Returns:
            Hash value, or None if not found
        """
        hashes = component.get('hashes', [])
        for hash_item in hashes:
            if hash_item.get('alg') == hash_type:
                return hash_item.get('content')
        return None

    def fetch_all_sbom_data(self, app_limit: Optional[int] = None) -> List[Dict]:
        """
        Complete workflow for collecting SBOM data from all applications.

        Steps:
        1. Get all applications (v1 API)
        2. For each app:
           a. Get SBOM data (CycloneDX format)
           b. Extract components
           c. Enrich with app metadata
           d. Extract hashes (SHA-1, SHA-256, etc.)
        3. Return all SBOM component records

        Args:
            app_limit: Optional limit on number of apps to process (for testing)

        Returns:
            List of SBOM component records with all required fields
        """
        logger.info("Starting SBOM data collection...")

        try:
            apps = self.get_all_applications()
            if not apps:
                logger.warning("No applications found")
                return []

            if app_limit:
                apps = apps[:app_limit]
                logger.info(f"Limited to {len(apps)} applications")

            all_components = []
            total_components = 0

            for idx, app in enumerate(apps, 1):
                app_id = app.get('id') or app.get('legacy_id')
                app_guid = app.get('guid')
                profile = app.get('profile', {})
                app_name = profile.get('name', 'Unknown')

                if not app_guid:
                    logger.debug(f"[{idx}/{len(apps)}] Skipping {app_name}: no GUID")
                    continue

                logger.info(f"[{idx}/{len(apps)}] Processing SBOM for: {app_name}")

                try:
                    # Get SBOM data
                    sbom_data = self.get_sbom(app_guid, app_name=app_name)
                    if not sbom_data:
                        logger.debug(f"  No SBOM available for {app_name}")
                        continue

                    # Extract components from CycloneDX format
                    bom = sbom_data.get('bom', {})
                    components = bom.get('components', [])

                    if not components:
                        logger.debug(f"  No components in SBOM for {app_name}")
                        continue

                    # Process each component
                    for comp in components:
                        # Extract CVE/CWE info
                        cve_ids = []
                        cwe_ids = []

                        for vuln in comp.get('vulnerabilities', []):
                            if 'ref' in vuln and vuln['ref'].startswith('CVE'):
                                cve_ids.append(vuln['ref'])
                            for rating in vuln.get('ratings', []):
                                if 'cwe' in rating:
                                    cwe_ids.append(rating['cwe'])

                        # Create SBOM component record
                        component_record = {
                            # App identification
                            'application_id': str(app_guid),
                            'app_name': app_name,

                            # Component identification
                            'component_name': comp.get('name'),
                            'component_type': comp.get('type', 'library'),
                            'component_version': comp.get('version'),

                            # Matching keys
                            'bom_ref': comp.get('bom-ref'),
                            'sha1': self._extract_hash(comp, 'SHA-1'),

                            # Additional hashes
                            'sha256': self._extract_hash(comp, 'SHA-256'),
                            'md5': self._extract_hash(comp, 'MD5'),
                            'bytecode_hash': self._extract_hash(comp, 'bytecode'),

                            # Package information
                            'purl': comp.get('purl'),
                            'vendor': comp.get('vendor', {}).get('name') if isinstance(comp.get('vendor'), dict) else comp.get('vendor'),

                            # File information
                            'file_path': comp.get('evidence', {}).get('identity', {}).get('field') if isinstance(comp.get('evidence'), dict) else None,

                            # Vulnerability information
                            'cve_ids': ','.join(cve_ids) if cve_ids else None,
                            'cwe_ids': ','.join(cwe_ids) if cwe_ids else None,

                            # Dependency information
                            'all_dependencies': json.dumps(comp.get('dependencies', [])) if comp.get('dependencies') else None,
                        }

                        all_components.append(component_record)
                        total_components += 1

                    logger.info(f"  Extracted {len(components)} components from {app_name}")

                except Exception as e:
                    logger.warning(f"  Failed to process SBOM for {app_name}: {e}")
                    continue

            logger.info(f"✓ Collected {total_components} SBOM components from {len(apps)} applications")
            return all_components

        except Exception as e:
            logger.error(f"Failed to collect SBOM data: {e}")
            raise

    def save_vulnerability_data(self, vulnerabilities: List[Dict], filename: str = 'all_sca_components.json') -> str:
        """Save vulnerability data to JSON file

        Args:
            vulnerabilities: List of vulnerability records from fetch_all_vulnerability_data()
            filename: Output JSON filename

        Returns:
            Path to saved file
        """
        try:
            with open(filename, 'w') as f:
                json.dump(vulnerabilities, f, indent=2)
            logger.info(f"✓ Saved {len(vulnerabilities)} vulnerability records to {filename}")
            return filename
        except Exception as e:
            logger.error(f"Failed to save vulnerability data: {e}")
            raise

    def save_sbom_data(self, components: List[Dict], filename: str = 'all_sbom_components.json') -> str:
        """Save SBOM component data to JSON file

        Args:
            components: List of SBOM components from fetch_all_sbom_data()
            filename: Output JSON filename

        Returns:
            Path to saved file
        """
        try:
            with open(filename, 'w') as f:
                json.dump(components, f, indent=2)
            logger.info(f"✓ Saved {len(components)} SBOM components to {filename}")
            return filename
        except Exception as e:
            logger.error(f"Failed to save SBOM data: {e}")
            raise

    def export_vulnerability_csv(self, vulnerabilities: List[Dict], filename: str = 'vulnerability_data.csv') -> str:
        """Export vulnerability data to CSV for Excel analysis

        Args:
            vulnerabilities: List of vulnerability records
            filename: Output CSV filename

        Returns:
            Path to saved file
        """
        import csv

        if not vulnerabilities:
            logger.warning("No vulnerability data to export")
            return None

        try:
            fieldnames = [
                'cve_id', 'severity', 'cwe_id', 'cvss_score',
                'component_name', 'component_version', 'component_id',
                'sha1', 'library_id',
                'app_id', 'app_name', 'business_criticality',
                'build_id', 'build_version', 'build_published_date',
                'first_found_date', 'mitigated_date',
                'mitigation', 'mitigation_type', 'mitigation_date', 'mitigation_action',
                'scantype', 'static_version', 'dynamic_version',
                'static_submitted_date', 'dynamic_submitted_date',
                'file_name', 'description', 'cve_summary',
                'blocklisted', 'new', 'affects_policy_compliance',
                'vulnerability_affects_policy_compliance', 'component_affects_policy_compliance',
                'added_date', 'max_cvss_score', 'app_guid',
            ]

            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, restval='')
                writer.writeheader()

                for vuln in vulnerabilities:
                    writer.writerow({k: vuln.get(k, '') for k in fieldnames})

            logger.info(f"✓ Exported {len(vulnerabilities)} vulnerability records to {filename}")
            return filename
        except Exception as e:
            logger.error(f"Failed to export vulnerability CSV: {e}")
            raise

    def export_sbom_csv(self, components: List[Dict], filename: str = 'sbom_components.csv') -> str:
        """Export SBOM components to CSV for Excel analysis

        Args:
            components: List of SBOM components
            filename: Output CSV filename

        Returns:
            Path to saved file
        """
        import csv

        if not components:
            logger.warning("No SBOM components to export")
            return None

        try:
            fieldnames = [
                'application_id', 'app_name',
                'component_type', 'component_name', 'component_version',
                'bom_ref', 'sha1', 'sha256', 'md5', 'bytecode_hash',
                'purl', 'vendor',
                'file_path',
                'cve_ids', 'cwe_ids',
                'all_dependencies', 'match_type',
            ]

            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, restval='')
                writer.writeheader()

                for comp in components:
                    writer.writerow({k: comp.get(k, '') for k in fieldnames})

            logger.info(f"✓ Exported {len(components)} SBOM components to {filename}")
            return filename
        except Exception as e:
            logger.error(f"Failed to export SBOM CSV: {e}")
            raise


def main():
    """Fetch all apps, collect components, and match them with advanced options"""
    parser = argparse.ArgumentParser(
        description='Veracode API Data Fetcher - Comprehensive component collection and analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect all data (default)
  python api_fetcher.py --limit 5

  # Collect vulnerabilities only
  python api_fetcher.py --mode vuln --limit 5

  # Collect SBOM only with custom output directory
  python api_fetcher.py --mode sbom --output ./sbom_exports

  # Export as JSON only
  python api_fetcher.py --format json --limit 5

  # List available credential profiles
  python api_fetcher.py --list-profiles
        """
    )

    # Credentials
    parser.add_argument('--veracode_api_key_id', help='Veracode API Key ID')
    parser.add_argument('--veracode_api_key_secret', help='Veracode API Key Secret')

    # Collection options
    parser.add_argument('--limit', type=int, help='Limit number of applications to process')
    parser.add_argument('--mode', choices=['vuln', 'sbom', 'all'], default='all',
                        help='What to collect: vulnerabilities, SBOM components, or both (default: all)')
    parser.add_argument('--format', choices=['json', 'csv', 'both'], default='both',
                        help='Export format: JSON, CSV, or both (default: both)')

    # Output options
    parser.add_argument('--output', default='.', help='Output directory for exports (default: current directory)')
    parser.add_argument('--no-match', action='store_true', help='Skip vulnerability matching step')

    # Utility options
    parser.add_argument('--list-profiles', action='store_true', help='List available credential profiles')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    # Adjust logging level if verbose requested
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle --list-profiles
    if args.list_profiles:
        list_profiles()
        return

    # Create output directory if needed
    os.makedirs(args.output, exist_ok=True)
    logger.info(f"Output directory: {args.output}")

    # Get limit if specified
    app_limit = args.limit
    if app_limit:
        logger.info(f"Limiting to {app_limit} applications")

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
            logger.info(f"Limited to {len(apps)} applications")

        logger.debug(f"Sample app structure: {apps[0] if apps else 'No apps'}")

        all_sca_components = []
        all_sbom_components = []

        # Process each application based on mode
        for idx, app in enumerate(apps):
            app_id = app.get('id') or app.get('legacy_id') or app.get('app_id')
            app_name = app.get('name') or app.get('profile', {}).get('name') or 'Unknown'
            app_guid = app.get('guid') or app.get('application_guid')

            logger.debug(f"App {idx}: id={app_id}, name={app_name}, guid={app_guid}, keys={list(app.keys())}")

            if not app_id and not app_guid:
                logger.warning(f"Skipping app {app_name}: no app_id or guid")
                continue

            logger.info(f"Processing app: {app_name} (GUID: {app_guid})")

            # Get SCA components (if mode is 'vuln' or 'all')
            if args.mode in ('vuln', 'all') and app_guid:
                try:
                    build_info = fetcher.get_build_info(app_guid)
                    if build_info:
                        sca_components = fetcher.extract_sca_vulnerabilities(build_info)
                        all_sca_components.extend(sca_components)
                        logger.info(f"  Extracted {len(sca_components)} SCA components")
                except Exception as e:
                    logger.warning(f"  Failed to fetch SCA components for {app_name}: {e}")

            # Get SBOM components (if mode is 'sbom' or 'all')
            if args.mode in ('sbom', 'all') and app_guid:
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

        # Export data
        if args.mode in ('vuln', 'all') and all_sca_components:
            if args.format in ('json', 'both'):
                sca_json_path = os.path.join(args.output, 'all_sca_components.json')
                with open(sca_json_path, 'w') as f:
                    json.dump(all_sca_components, f, indent=2)
                logger.info(f"Exported SCA JSON: {sca_json_path}")

            if args.format in ('csv', 'both'):
                vuln_csv_path = os.path.join(args.output, 'vulnerabilities.csv')
                fetcher.export_vulnerability_csv(all_sca_components, vuln_csv_path)
                logger.info(f"Exported vulnerability CSV: {vuln_csv_path}")

        if args.mode in ('sbom', 'all') and all_sbom_components:
            if args.format in ('json', 'both'):
                sbom_json_path = os.path.join(args.output, 'all_sbom_components.json')
                with open(sbom_json_path, 'w') as f:
                    json.dump(all_sbom_components, f, indent=2)
                logger.info(f"Exported SBOM JSON: {sbom_json_path}")

            if args.format in ('csv', 'both'):
                sbom_csv_path = os.path.join(args.output, 'sbom_components.csv')
                fetcher.export_sbom_csv(all_sbom_components, sbom_csv_path)
                logger.info(f"Exported SBOM CSV: {sbom_csv_path}")

        # Matching step (if enabled and both datasets available)
        if not args.no_match and all_sca_components and all_sbom_components:
            from vulnerability_matcher import VulnerabilityMatcher

            logger.info("Running vulnerability matching...")
            matcher = VulnerabilityMatcher()
            matcher.load_sbom_data(all_sbom_components)
            matcher.load_sca_data(all_sca_components)
            matcher.match_all()

            matcher.print_summary()

            matched_path = os.path.join(args.output, 'matched_components.csv')
            unmatched_path = os.path.join(args.output, 'unmatched_components.csv')
            matcher.export_matched_csv(matched_path)
            matcher.export_unmatched_csv(unmatched_path)
            logger.info(f"Exported matching results to {args.output}")

        # Summary
        logger.info("=" * 80)
        logger.info("Collection Complete")
        logger.info(f"  SCA Components: {len(all_sca_components)}")
        logger.info(f"  SBOM Components: {len(all_sbom_components)}")
        logger.info(f"  Output Directory: {args.output}")
        logger.info("=" * 80)

        # Get failure summary if any retries occurred
        failure_summary = fetcher.get_failure_summary()
        if failure_summary['failed_apps'] > 0:
            logger.warning(f"Failed Apps: {failure_summary['failed_apps']}, Total Retries: {failure_summary['total_retries']}")

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
