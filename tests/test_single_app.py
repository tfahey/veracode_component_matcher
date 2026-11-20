#!/usr/bin/env python3
"""
Single Application Test Script

Tests api_fetcher.py against a specific application by name.
Provides detailed logging and output for debugging.

Run with:
    python tests/test_single_app.py "App Name"
    python tests/test_single_app.py <app_id or app_guid>
    python tests/test_single_app.py "App Name" --verbose
    python tests/test_single_app.py "App Name" --output tests/results
"""

import argparse
import json
import logging
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import UUID

# Add parent directory to path so we can import project modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from veracode_api_py import Applications

from api_fetcher import VeracodeApiFetcher

# Setup logging
logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False, log_file: str = None):
    """Configure logging with optional verbose mode"""
    level = logging.DEBUG if verbose else logging.INFO
    format_str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(format_str)
    console_handler.setFormatter(console_formatter)

    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(format_str)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
        logger.info(f"Logging to file: {log_file}")

    if verbose:
        logger.debug("DEBUG logging enabled")


def _app_display_name(app: dict) -> str:
    return app.get('name') or app.get('profile', {}).get('name') or 'Unknown'


def _app_org_id(app: dict) -> Optional[int]:
    org_id = app.get('organization_id') or app.get('oid')
    return int(org_id) if org_id is not None else None


def _find_by_id_or_guid(lookup: str) -> Optional[dict]:
    """Direct API lookup by legacy app ID or GUID; avoids listing every application."""
    try:
        if lookup.isdigit():
            logger.info(f"Looking up app ID {lookup}...")
            response = Applications().get(legacy_id=int(lookup))
            apps = (response or {}).get('_embedded', {}).get('applications', [])
            return apps[0] if apps else None
        try:
            guid = UUID(lookup)
        except ValueError:
            return None
        logger.info(f"Looking up app GUID {guid}...")
        app = Applications().get(guid=guid)
        return app if isinstance(app, dict) and app.get('guid') else None
    except Exception as e:
        logger.debug(f"ID/GUID lookup failed for '{lookup}': {e}")
        return None


def find_application(app_name: str, org_id: Optional[int] = None) -> Optional[dict]:
    """Find application by app ID, GUID, or name (optionally restricted to an organization ID)"""
    lookup = app_name.strip()
    logger.info(f"Searching for application: '{lookup}'" + (f" in org {org_id}" if org_id else ""))

    app = _find_by_id_or_guid(lookup)
    if app:
        logger.info(f"✓ Found by ID/GUID: {_app_display_name(app)}")
        if org_id and _app_org_id(app) != org_id:
            logger.warning(f"App belongs to org {_app_org_id(app)}, not --org-id {org_id}")
        return app

    # Server-side name filter instead of fetching all applications
    try:
        response = Applications().get_by_name(lookup)
    except Exception as e:
        logger.error(f"Name lookup failed: {e}")
        return None
    apps: list = [a for a in response if isinstance(a, dict)] if isinstance(response, list) else []
    logger.debug(f"Name search returned {len(apps)} applications")

    if org_id:
        apps = [a for a in apps if _app_org_id(a) == org_id]
        logger.debug(f"{len(apps)} applications in org {org_id}")

    # Exact name match
    for app in apps:
        if _app_display_name(app).lower() == lookup.lower():
            logger.info(f"✓ Found exact match: {_app_display_name(app)}")
            return app

    # Partial match
    matches = [a for a in apps if lookup.lower() in _app_display_name(a).lower()]
    if matches:
        logger.warning(f"No exact match found. Found {len(matches)} partial matches:")
        for app in matches[:5]:
            logger.warning(f"  - {_app_display_name(app)} (app ID {app.get('id')}, org {_app_org_id(app)})")
        logger.info(f"Using first match: {_app_display_name(matches[0])}")
        return matches[0]

    logger.error(f"Application '{lookup}' not found")
    return None


def collect_app_data(fetcher: VeracodeApiFetcher, app: dict) -> dict:
    """Collect all data for an application"""
    app_id = app.get('id') or app.get('legacy_id')
    app_name = app.get('name') or app.get('profile', {}).get('name') or 'Unknown'
    app_guid = app.get('guid')

    logger.info(f"\nCollecting data for: {app_name}")
    logger.debug(f"  App ID: {app_id}")
    logger.debug(f"  App GUID: {app_guid}")

    results = {
        'app_name': app_name,
        'app_id': app_id,
        'app_guid': app_guid,
        'sca_components': [],
        'sbom_components': [],
        'sbom_unavailable_reason': None,
        'errors': [],
        'collection_time': datetime.now().isoformat(),
    }

    # Collect SCA data via detailed report
    if app_id:
        try:
            logger.info("  Fetching SCA vulnerability data via detailed report...")

            # Get builds for this app
            builds = fetcher.get_build_list(app_id)
            if builds and len(builds) > 0:
                # Get the most recent build (latest is last in chronologically-ordered list)
                build_dict = builds[-1] if isinstance(builds[-1], dict) else {}
                build_id = build_dict.get('build_id') if isinstance(build_dict, dict) else str(builds[-1])
                build_date = build_dict.get('policy_updated_date')
                logger.debug(f"    Using build ID: {build_id}, date: {build_date}")

                # Get detailed report for this build
                detailed_report = fetcher.get_detailed_report(build_id)
                if detailed_report:
                    # Extract SCA components from detailed report
                    sca_components = fetcher.extract_sca_from_detailed_report(
                        detailed_report, app_id=app_id, app_guid=app_guid,
                        build_id=build_id, build_date=build_date, app_name=app_name)
                    results['sca_components'] = sca_components
                    logger.info(f"  ✓ Collected {len(sca_components)} SCA components")
                    if sca_components:
                        logger.debug(f"    SCA fields: {list(sca_components[0].keys())}")
                else:
                    logger.warning("  ⚠ No detailed report found for SCA data")
            else:
                logger.warning("  ⚠ No builds found for SCA collection")

        except Exception as e:
            error_msg = f"Failed to fetch SCA data: {e}"
            logger.error(f"  ✗ {error_msg}")
            logger.exception("Exception details:")
            results['errors'].append(error_msg)

    # Collect SBOM data
    if app_guid:
        try:
            logger.info("  Fetching SBOM component data...")
            sbom_components, unavailable_reason = fetcher.collect_app_sbom_components(
                app_id, app_guid, app_name=app_name)

            if sbom_components:
                results['sbom_components'] = sbom_components
                sources = sorted({c.get('sbom_source') for c in sbom_components})
                logger.info(f"  ✓ Collected {len(sbom_components)} SBOM components from: {', '.join(sources)}")
                logger.debug(f"    SBOM fields: {list(sbom_components[0].keys())}")
            else:
                results['sbom_unavailable_reason'] = unavailable_reason
                logger.warning(f"  ⚠ No SBOM data found: {unavailable_reason}")

        except Exception as e:
            error_msg = f"Failed to fetch SBOM data: {e}"
            logger.error(f"  ✗ {error_msg}")
            results['errors'].append(error_msg)

    return results


def export_results(results: dict, output_dir: str):
    """Export collected data to files"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    app_name = results['app_name']
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_name = app_name.replace(' ', '_').lower()

    # Export SCA data
    if results['sca_components']:
        sca_json_file = os.path.join(output_dir, f"{base_name}_sca_{timestamp}.json")
        with open(sca_json_file, 'w') as f:
            json.dump(results['sca_components'], f, indent=2)
        logger.info(f"✓ Exported SCA JSON: {sca_json_file}")

        # Export SCA CSV
        fetcher = VeracodeApiFetcher()
        sca_csv_file = os.path.join(output_dir, f"{base_name}_vulnerabilities_{timestamp}.csv")
        fetcher.export_vulnerability_csv(results['sca_components'], sca_csv_file)
        logger.info(f"✓ Exported SCA CSV: {sca_csv_file}")

    # Export SBOM data
    if results['sbom_components']:
        sbom_json_file = os.path.join(output_dir, f"{base_name}_sbom_{timestamp}.json")
        with open(sbom_json_file, 'w') as f:
            json.dump(results['sbom_components'], f, indent=2)
        logger.info(f"✓ Exported SBOM JSON: {sbom_json_file}")

        # Export SBOM CSV
        fetcher = VeracodeApiFetcher()
        sbom_csv_file = os.path.join(output_dir, f"{base_name}_sbom_components_{timestamp}.csv")
        fetcher.export_sbom_csv(results['sbom_components'], sbom_csv_file)
        logger.info(f"✓ Exported SBOM CSV: {sbom_csv_file}")

    # Export summary JSON
    summary_file = os.path.join(output_dir, f"{base_name}_summary_{timestamp}.json")
    with open(summary_file, 'w') as f:
        json.dump(results, f, indent=2)
    logger.info(f"✓ Exported summary: {summary_file}")


def print_summary(results: dict):
    """Print test summary"""
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    print(f"\nApplication: {results['app_name']}")
    print(f"  App ID: {results['app_id']}")
    print(f"  App GUID: {results['app_guid']}")

    print(f"\nData Collected:")
    print(f"  SCA Components: {len(results['sca_components'])}")
    print(f"  SBOM Components: {len(results['sbom_components'])}")
    if results.get('sbom_unavailable_reason'):
        print(f"  SBOM Unavailable: {results['sbom_unavailable_reason']}")

    if results['sca_components']:
        print(f"\n  SCA Sample (first record):")
        sample = results['sca_components'][0]
        for key in list(sample.keys())[:5]:
            value = sample[key]
            if isinstance(value, (list, dict)):
                print(f"    {key}: {type(value).__name__}")
            else:
                print(f"    {key}: {value}")
        if len(sample) > 5:
            print(f"    ... and {len(sample) - 5} more fields")

    if results['sbom_components']:
        print(f"\n  SBOM Sample (first record):")
        sample = results['sbom_components'][0]
        for key in list(sample.keys())[:5]:
            value = sample[key]
            if isinstance(value, (list, dict)):
                print(f"    {key}: {type(value).__name__}")
            else:
                print(f"    {key}: {value}")
        if len(sample) > 5:
            print(f"    ... and {len(sample) - 5} more fields")

    if results['errors']:
        print(f"\nErrors ({len(results['errors'])}):")
        for error in results['errors']:
            print(f"  ✗ {error}")
    else:
        print(f"\n✅ Collection completed successfully")

    print("=" * 80 + "\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Test api_fetcher against a specific application',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with application name
  python tests/test_single_app.py "My Application"

  # Test with application ID or GUID
  python tests/test_single_app.py 1301028
  python tests/test_single_app.py 6a747366-ed0d-490c-a069-39995c4ad7d6

  # Restrict a name search to one organization (useful for proxy accounts)
  python tests/test_single_app.py "Payments" --org-id 12345

  # Test with verbose logging
  python tests/test_single_app.py "My Application" --verbose

  # Test with custom output directory
  python tests/test_single_app.py "My Application" --verbose --output ./test_results

  # Test with log file
  python tests/test_single_app.py "My Application" --verbose --log-file app_test.log
        """
    )

    parser.add_argument('app_name', help='Application name, app ID, or app GUID to test')
    parser.add_argument('--org-id', type=int, help='Only match applications in this organization ID')
    parser.add_argument('--verbose', action='store_true', help='Enable DEBUG logging')
    parser.add_argument('--output', default='tests/results', help='Output directory for exports (default: tests/results)')
    parser.add_argument('--log-file', help='Log output to file')
    parser.add_argument('--veracode_api_key_id', help='Veracode API Key ID')
    parser.add_argument('--veracode_api_key_secret', help='Veracode API Key Secret')

    args = parser.parse_args()

    # Setup logging
    setup_logging(verbose=args.verbose, log_file=args.log_file)

    logger.info("=" * 80)
    logger.info("SINGLE APPLICATION TEST")
    logger.info("=" * 80)

    try:
        # Initialize fetcher
        logger.info("Initializing Veracode API fetcher...")
        fetcher = VeracodeApiFetcher(
            api_id=args.veracode_api_key_id,
            api_key=args.veracode_api_key_secret
        )

        # Find application
        app = find_application(args.app_name, org_id=args.org_id)
        if not app:
            logger.error("Test failed: Application not found")
            return 1

        # Collect data
        results = collect_app_data(fetcher, app)

        # Export results
        logger.info(f"\nExporting results to: {args.output}")
        export_results(results, args.output)

        # Print summary
        print_summary(results)

        # Get failure summary
        failure_summary = fetcher.get_failure_summary()
        if failure_summary['failed_apps'] > 0:
            logger.warning(f"API failures: {failure_summary['failed_apps']} apps, {failure_summary['total_retries']} retries")

        logger.info("✅ Test completed successfully")
        return 0

    except KeyboardInterrupt:
        logger.warning("Test interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Test failed with exception: {e}", exc_info=args.verbose)
        return 1


if __name__ == '__main__':
    sys.exit(main())
