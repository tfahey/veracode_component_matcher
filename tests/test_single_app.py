#!/usr/bin/env python3
"""
Single Application Test Script

Tests api_fetcher.py against a specific application by name.
Provides detailed logging and output for debugging.

Run with:
    python tests/test_single_app.py "App Name"
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


def find_application(fetcher: VeracodeApiFetcher, app_name: str) -> dict:
    """Find application by name"""
    logger.info(f"Searching for application: '{app_name}'")

    apps = fetcher.get_all_applications()
    if not apps:
        logger.error("No applications found in Veracode")
        return None

    logger.debug(f"Found {len(apps)} total applications")

    # Exact match first
    for app in apps:
        app_display_name = app.get('name') or app.get('profile', {}).get('name') or 'Unknown'
        if app_display_name.lower() == app_name.lower():
            logger.info(f"✓ Found exact match: {app_display_name}")
            return app

    # Partial match
    matches = []
    for app in apps:
        app_display_name = app.get('name') or app.get('profile', {}).get('name') or 'Unknown'
        if app_name.lower() in app_display_name.lower():
            matches.append((app_display_name, app))

    if matches:
        logger.warning(f"No exact match found. Found {len(matches)} partial matches:")
        for display_name, app in matches[:5]:
            logger.warning(f"  - {display_name}")
        if matches:
            logger.info(f"Using first match: {matches[0][0]}")
            return matches[0][1]

    logger.error(f"Application '{app_name}' not found")
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
                # Get the most recent build
                build_id = builds[0].get('build_id') if isinstance(builds[0], dict) else str(builds[0])
                logger.debug(f"    Using build ID: {build_id}")

                # Get detailed report for this build
                detailed_report = fetcher.get_detailed_report(build_id)
                if detailed_report:
                    # Extract SCA components from detailed report
                    sca_components = fetcher.extract_sca_from_detailed_report(detailed_report)
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
            sbom_data_raw = fetcher.get_sbom(app_guid)

            if sbom_data_raw:
                sbom_components = fetcher.extract_sbom_components(sbom_data_raw)
                results['sbom_components'] = sbom_components
                logger.info(f"  ✓ Collected {len(sbom_components)} SBOM components")
                logger.debug(f"    SBOM fields: {list(sbom_components[0].keys()) if sbom_components else []}")
            else:
                logger.warning("  ⚠ No SBOM data found")

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
  python test_single_app.py "My Application"

  # Test with verbose logging
  python test_single_app.py "My Application" --verbose

  # Test with custom output directory
  python test_single_app.py "My Application" --verbose --output ./test_results

  # Test with log file
  python test_single_app.py "My Application" --verbose --log-file app_test.log
        """
    )

    parser.add_argument('app_name', help='Application name to test')
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
        app = find_application(fetcher, args.app_name)
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
