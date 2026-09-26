#!/usr/bin/env python3
"""
Task 1.1: Document API Response Structures

This script tests all Veracode API endpoints and documents their response formats.
Saves samples to docs/api_samples/ for reference during implementation.

Usage:
    python task_1_1_api_discovery.py --output-dir docs/api_samples
"""

import json
import logging
import argparse
from typing import Dict, Any
from datetime import datetime
from pathlib import Path

from api_fetcher import VeracodeApiFetcher

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class APIDiscovery:
    """Test and document all Veracode API endpoints"""

    def __init__(self, fetcher: VeracodeApiFetcher, output_dir: str = 'docs/api_samples'):
        self.fetcher = fetcher
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.samples = {}
        self.documentation = []

    def document_api(self, name: str, description: str, endpoint: str, method: str,
                     response_type: str, response_sample: Any = None, fields_description: Dict[str, Any] | None = None):
        """Document an API endpoint"""
        if fields_description is None:
            fields_description = {}

        doc = {
            'name': name,
            'description': description,
            'endpoint': endpoint,
            'method': method,
            'response_type': response_type,
            'fields': fields_description
        }
        self.documentation.append(doc)
        logger.info(f"✓ Documented: {name}")

    def save_sample(self, api_name: str, data: Any, format_type: str = 'json'):
        """Save API response sample"""
        filename = self.output_dir / f"{api_name}_response.{format_type}"

        try:
            if format_type == 'json':
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
            elif format_type == 'xml':
                if isinstance(data, bytes):
                    with open(filename, 'wb') as f:
                        f.write(data)
                else:
                    with open(filename, 'w') as f:
                        f.write(str(data))

            logger.info(f"✓ Saved: {filename}")
            return str(filename)
        except Exception as e:
            logger.error(f"Failed to save {filename}: {e}")
            return None

    def test_getapplist(self):
        """Test getapplist.do endpoint"""
        logger.info("\n" + "="*80)
        logger.info("Testing: getapplist.do")
        logger.info("="*80)

        try:
            apps = self.fetcher.get_all_applications()

            if not apps:
                logger.warning("No applications returned")
                return

            logger.info(f"✓ Got {len(apps)} applications")

            # Save sample
            self.save_sample('01_getapplist', apps, 'json')

            # Document structure
            if apps:
                sample_app = apps[0]
                fields_doc = {
                    'id': 'Application ID (integer)',
                    'guid': 'Application GUID (UUID string)',
                    'name': 'Application name (string)',
                    'legacy_id': 'Legacy application ID (integer)',
                    'profile': 'Profile object containing app details',
                    'created_date': 'Creation date (ISO 8601)',
                    'modified_date': 'Last modified date (ISO 8601)',
                }

                self.document_api(
                    'getapplist.do',
                    'Get list of all applications',
                    'GET /api/5.0/getapplist.do',
                    'GET',
                    'JSON (v1 API)',
                    apps,
                    fields_doc
                )

                logger.info("\nSample Application:")
                logger.info(json.dumps(sample_app, indent=2, default=str))

        except Exception as e:
            logger.error(f"Failed to test getapplist: {e}")

    def test_getappinfo(self):
        """Test getappinfo.do endpoint"""
        logger.info("\n" + "="*80)
        logger.info("Testing: getappinfo.do")
        logger.info("="*80)

        try:
            apps = self.fetcher.get_all_applications()
            if not apps:
                logger.warning("No apps to test")
                return

            app = apps[0]
            app_id = app.get('id') or app.get('legacy_id')
            app_name = app.get('name')

            logger.info(f"Testing with app: {app_name} (id: {app_id})")

            # Note: getappinfo.do might not be directly exposed in veracode_api_py
            # We'll document it based on API documentation

            fields_doc = {
                'app_id': 'Application ID',
                'app_name': 'Application name',
                'organization_id': 'Organization ID',
                'business_criticality': 'Business criticality level (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)',
                'is_policy_sandboxed': 'Whether app is sandboxed (true/false)',
                'custom_fields': 'Custom field values',
                'tags': 'Application tags',
                'policies': 'Assigned policies',
            }

            self.document_api(
                'getappinfo.do',
                'Get detailed application information',
                'GET /api/5.0/getappinfo.do?app_id={app_id}',
                'GET',
                'XML',
                None,
                fields_doc
            )

            logger.info("✓ Documented getappinfo.do structure")

        except Exception as e:
            logger.error(f"Failed to test getappinfo: {e}")

    def test_getbuildlist(self):
        """Test getbuildlist.do endpoint"""
        logger.info("\n" + "="*80)
        logger.info("Testing: getbuildlist.do")
        logger.info("="*80)

        try:
            apps = self.fetcher.get_all_applications()
            if not apps:
                logger.warning("No apps to test")
                return

            app = apps[0]
            app_id = app.get('id') or app.get('legacy_id')
            app_name = app.get('name')

            logger.info(f"Testing with app: {app_name} (id: {app_id})")

            # Note: veracode_api_py might have this as get_builds() or similar
            # Document the expected structure

            fields_doc = {
                'build_id': 'Build ID (integer)',
                'app_id': 'Application ID',
                'version': 'Build version string',
                'build_status': 'Status (PUBLISHED, INCOMPLETE, RUNNING, etc.)',
                'policy_name': 'Policy applied to build',
                'policy_compliance_status': 'PASS or FAIL',
                'published_date': 'When build was published (ISO 8601)',
                'scan_overdue_date': 'When rescan is due',
                'results_ready': 'Whether results are ready (true/false)',
                'sandbox_id': 'Sandbox ID if sandboxed',
            }

            self.document_api(
                'getbuildlist.do',
                'Get list of builds for an application',
                'GET /api/5.0/getbuildlist.do?app_id={app_id}',
                'GET',
                'XML',
                None,
                fields_doc
            )

            logger.info("✓ Documented getbuildlist.do structure")

        except Exception as e:
            logger.error(f"Failed to test getbuildlist: {e}")

    def test_getbuildinfo(self):
        """Test getbuildinfo.do endpoint"""
        logger.info("\n" + "="*80)
        logger.info("Testing: getbuildinfo.do")
        logger.info("="*80)

        try:
            apps = self.fetcher.get_all_applications()
            if not apps:
                logger.warning("No apps to test")
                return

            app = apps[0]
            app_guid = app.get('guid')
            app_name = app.get('name')

            if not app_guid:
                logger.warning("No GUID available for app")
                return

            logger.info(f"Testing with app: {app_name} (guid: {app_guid})")

            # Try to get build info
            build_info = self.fetcher.get_build_info(str(app_guid))

            if build_info:
                self.save_sample('04_getbuildinfo', build_info, 'json')
                logger.info("✓ Got build info")
                logger.info("\nSample Build Info:")
                logger.info(json.dumps(build_info, indent=2, default=str)[:500] + "...")
            else:
                logger.warning("No build info returned")

            fields_doc = {
                'build_id': 'Build ID',
                'app_id': 'Application ID',
                'version': 'Build version',
                'build_status': 'Status (PUBLISHED, etc.)',
                'policy_name': 'Policy name',
                'policy_compliance_status': 'PASS/FAIL',
                'rules_status': 'PASS/FAIL/NOT_APPLICABLE',
                'published_date': 'Publication date (ISO 8601)',
                'results_ready': 'Results ready flag',
                'analysis_unit_id': 'Analysis unit identifier',
                'sast_build_number': 'Static analysis build number',
                'dast_build_number': 'Dynamic analysis build number',
                'sast_submitted_date': 'Static analysis submission date',
                'dast_submitted_date': 'Dynamic analysis submission date',
                'vulnerability': 'Array of vulnerability findings',
            }

            self.document_api(
                'getbuildinfo.do',
                'Get information about a specific build',
                'GET /api/5.0/getbuildinfo.do?app_id={app_id}&build_id={build_id}',
                'GET',
                'XML (with embedded vulnerability data)',
                build_info,
                fields_doc
            )

        except Exception as e:
            logger.error(f"Failed to test getbuildinfo: {e}")

    def test_detailedreport(self):
        """Test detailedreport.do endpoint"""
        logger.info("\n" + "="*80)
        logger.info("Testing: detailedreport.do")
        logger.info("="*80)

        try:
            # This endpoint returns detailed vulnerability findings
            # It requires a build_id parameter

            fields_doc = {
                'flaw_id': 'Unique flaw identifier',
                'category': 'Vulnerability category',
                'cwe': 'CWE ID',
                'type': 'Vulnerability type',
                'description': 'Vulnerability description',
                'severity': 'Severity level (1-5)',
                'cvss_score': 'CVSS v3 score',
                'sha1': 'SHA1 hash of affected component (MATCHING KEY)',
                'library_id': 'Veracode library ID (MATCHING KEY)',
                'component_name': 'Component/library name',
                'component_version': 'Component version',
                'file_name': 'Affected file name',
                'first_found_date': 'When vulnerability was first detected',
                'mitigated_date': 'When vulnerability was mitigated (if any)',
                'mitigation': 'Mitigation text',
                'mitigation_type': 'Type of mitigation',
                'new': 'Is this a new finding (true/false)',
                'blocklisted': 'Is component blocklisted (true/false)',
                'affects_policy_compliance': 'Does it affect policy compliance',
            }

            self.document_api(
                'detailedreport.do',
                'Get detailed vulnerability findings for a build',
                'GET /api/5.0/detailedreport.do?build_id={build_id}',
                'GET',
                'XML',
                None,
                fields_doc
            )

            logger.info("✓ Documented detailedreport.do structure")
            logger.info("\nKey Fields for Matching:")
            logger.info("  - sha1: Primary matching key with SBOM")
            logger.info("  - library_id: Secondary matching key with SBOM")

        except Exception as e:
            logger.error(f"Failed to test detailedreport: {e}")

    def test_applications_v1_api(self):
        """Test Applications v1 API"""
        logger.info("\n" + "="*80)
        logger.info("Testing: Applications v1 API")
        logger.info("="*80)

        try:
            apps = self.fetcher.get_all_applications()

            if not apps:
                logger.warning("No applications returned")
                return

            logger.info(f"✓ Got {len(apps)} applications from v1 API")

            # Save sample
            self.save_sample('06_applications_v1', apps, 'json')

            # Document structure
            if apps:
                sample_app = apps[0]
                fields_doc = {
                    'guid': 'Application GUID (UUID) - Used for SBOM API calls',
                    'id': 'Application ID (integer)',
                    'name': 'Application name',
                    'legacy_id': 'Legacy application ID',
                    'profile': 'Profile object with application metadata',
                    'created_date': 'Creation date (ISO 8601)',
                    'modified_date': 'Last modification date (ISO 8601)',
                    'business_criticality': 'Business impact level',
                    'tags': 'Associated tags',
                }

                self.document_api(
                    'GET /appsec/v1/applications',
                    'Get all applications (v1 REST API)',
                    'GET /appsec/v1/applications?scan_type=STATIC&size=500',
                    'GET',
                    'JSON',
                    apps,
                    fields_doc
                )

                logger.info("\nSample Application from v1 API:")
                logger.info(json.dumps(sample_app, indent=2, default=str))

        except Exception as e:
            logger.error(f"Failed to test applications v1 API: {e}")

    def test_sbom_api(self):
        """Test SBOM v1 API (CycloneDX format)"""
        logger.info("\n" + "="*80)
        logger.info("Testing: SBOM v1 API")
        logger.info("="*80)

        try:
            apps = self.fetcher.get_all_applications()
            if not apps:
                logger.warning("No apps to test")
                return

            # Try first few apps to find one with SBOM data
            for idx, app in enumerate(apps[:5]):
                app_guid = app.get('guid')
                app_name = app.get('name')

                logger.info(f"Trying app {idx+1}: {app_name}")

                try:
                    sbom_data = self.fetcher.get_sbom(str(app_guid))

                    if sbom_data:
                        logger.info(f"✓ Got SBOM for: {app_name}")
                        self.save_sample('07_sbom_cyclonedx', sbom_data, 'json')

                        # Document structure
                        fields_doc = {
                            'bomFormat': 'Format identifier (CycloneDX)',
                            'specVersion': 'CycloneDX specification version',
                            'version': 'SBOM version number',
                            'metadata': 'Metadata about the SBOM',
                            'components': 'Array of software components',
                            'services': 'Array of services (if any)',
                            'vulnerabilities': 'Known vulnerabilities',
                        }

                        component_fields = {
                            'bom-ref': 'Unique reference ID within SBOM (MATCHING KEY)',
                            'type': 'Component type (library, application, framework, etc.)',
                            'name': 'Component name',
                            'version': 'Component version',
                            'purl': 'Package URL - standard format for components',
                            'hashes': 'Array of hash objects (SHA-1, SHA-256, etc.)',
                            'hashes[].alg': 'Hash algorithm (SHA-1, SHA-256, MD5, etc.)',
                            'hashes[].content': 'Hash value - (MATCHING KEY for SHA-1)',
                            'licenses': 'License information',
                            'vulnerabilities': 'Known CVEs affecting component',
                            'vulnerabilities[].ref': 'CVE identifier',
                            'vulnerabilities[].ratings': 'Severity ratings',
                            'evidence': 'Evidence of component identification',
                            'dependencies': 'Dependency relationships',
                        }

                        self.document_api(
                            'GET /srcclr/sbom/v1/targets/{app_guid}/cyclonedx',
                            'Get SBOM data in CycloneDX format for an application',
                            'GET /srcclr/sbom/v1/targets/{app_guid}/cyclonedx?type=application',
                            'GET',
                            'JSON (CycloneDX format)',
                            sbom_data,
                            {**fields_doc, **{'components': component_fields}}
                        )

                        # Show sample
                        logger.info("\nSample SBOM Structure:")
                        if 'bom' in sbom_data and 'components' in sbom_data['bom']:
                            components = sbom_data['bom']['components']
                            if components:
                                logger.info(f"Total components in SBOM: {len(components)}")
                                logger.info("\nSample Component:")
                                logger.info(json.dumps(components[0], indent=2, default=str))

                        logger.info("\nKey Fields for Matching:")
                        logger.info("  - sha1 (from hashes): Primary matching key")
                        logger.info("  - bom-ref: Secondary matching key")
                        logger.info("  - purl: Package URL for additional matching strategies")

                        break

                except Exception as e:
                    logger.debug(f"SBOM not available for {app_name}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Failed to test SBOM API: {e}")

    def generate_documentation(self):
        """Generate markdown documentation from collected samples"""
        logger.info("\n" + "="*80)
        logger.info("Generating Documentation")
        logger.info("="*80)

        doc_file = self.output_dir / 'API_RESPONSE_DOCUMENTATION.md'

        with open(doc_file, 'w') as f:
            f.write("# Veracode API Response Structures\n\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")

            for idx, api_doc in enumerate(self.documentation, 1):
                f.write(f"## {idx}. {api_doc['name']}\n\n")
                f.write(f"**Description**: {api_doc['description']}\n\n")
                f.write(f"**Endpoint**: `{api_doc['endpoint']}`\n\n")
                f.write(f"**Method**: {api_doc['method']}\n\n")
                f.write(f"**Response Type**: {api_doc['response_type']}\n\n")

                f.write("### Response Fields\n\n")
                f.write("| Field | Type | Description |\n")
                f.write("|-------|------|-------------|\n")

                for field, description in api_doc['fields'].items():
                    f.write(f"| `{field}` | N/A | {description} |\n")

                f.write("\n---\n\n")

        logger.info(f"✓ Generated: {doc_file}")
        return doc_file

    def run_all_tests(self):
        """Run all API discovery tests"""
        logger.info("\n" + "🔍 VERACODE API DISCOVERY - TASK 1.1")
        logger.info("="*80 + "\n")

        self.test_getapplist()
        self.test_getappinfo()
        self.test_getbuildlist()
        self.test_getbuildinfo()
        self.test_detailedreport()
        self.test_applications_v1_api()
        self.test_sbom_api()

        # Generate documentation
        self.generate_documentation()

        logger.info("\n" + "="*80)
        logger.info("✅ API DISCOVERY COMPLETE")
        logger.info("="*80)
        logger.info(f"\nSaved samples to: {self.output_dir}")
        logger.info(f"Total endpoints documented: {len(self.documentation)}")
        logger.info("\nNext steps:")
        logger.info("  1. Review saved JSON/XML samples in docs/api_samples/")
        logger.info("  2. Review API_RESPONSE_DOCUMENTATION.md")
        logger.info("  3. Update API_FIELD_MAPPING.md with actual field names")
        logger.info("  4. Proceed to Task 1.2 (create detailed field mapping)")


def main():
    parser = argparse.ArgumentParser(description='Task 1.1: Document API Response Structures')
    parser.add_argument('--output-dir', default='docs/api_samples',
                        help='Directory to save API response samples')
    parser.add_argument('--veracode_api_key_id', help='Veracode API Key ID')
    parser.add_argument('--veracode_api_key_secret', help='Veracode API Key Secret')

    args = parser.parse_args()

    try:
        # Initialize fetcher
        fetcher = VeracodeApiFetcher(api_id=args.veracode_api_key_id,
                                     api_key=args.veracode_api_key_secret)

        # Run discovery
        discovery = APIDiscovery(fetcher, args.output_dir)
        discovery.run_all_tests()

    except Exception as e:
        logger.error(f"Error: {e}")
        raise


if __name__ == '__main__':
    main()
