#!/usr/bin/env python3
"""
Phase 4 Export Functionality Test

Tests all data export methods in api_fetcher.py using sample data.
Validates JSON and CSV export functionality.

Output files generated:
- test_sca_export.json: Exported vulnerability data
- test_sbom_export.json: Exported SBOM components
- test_vulnerability_export.csv: CSV vulnerability export
- test_sbom_export.csv: CSV SBOM export

Run with:
    python test_phase_4_export.py
"""

import json
import csv
import logging
import os
from pathlib import Path
from api_fetcher import VeracodeApiFetcher

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def load_sample_data():
    """Load sample data files"""
    try:
        with open('all_sca_components.json', 'r') as f:
            vulns = json.load(f)
        logger.info(f"✓ Loaded {len(vulns)} vulnerability records")

        with open('all_sbom_components.json', 'r') as f:
            components = json.load(f)
        logger.info(f"✓ Loaded {len(components)} SBOM components")

        return vulns, components
    except FileNotFoundError as e:
        logger.error(f"Sample data file not found: {e}")
        return None, None


def verify_json_export(filename):
    """Verify JSON export file integrity"""
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        return len(data) > 0
    except Exception as e:
        logger.error(f"Failed to verify {filename}: {e}")
        return False


def verify_csv_export(filename):
    """Verify CSV export file integrity"""
    try:
        with open(filename, 'r') as f:
            reader = csv.reader(f)
            rows = list(reader)
        return len(rows) > 1  # At least header + 1 data row
    except Exception as e:
        logger.error(f"Failed to verify {filename}: {e}")
        return False


def test_phase_4_export():
    """Test Phase 4 export functionality"""

    print("\n" + "="*80)
    print("PHASE 4 TEST - Data Export Functionality")
    print("="*80 + "\n")

    # Load sample data
    print("--- Step 1: Loading Sample Data ---")
    vulns, components = load_sample_data()

    if not vulns or not components:
        print("✗ Failed to load sample data")
        return False

    # Initialize fetcher
    print("\n--- Step 2: Initializing API Fetcher ---")
    fetcher = VeracodeApiFetcher()
    print("✓ API Fetcher initialized")

    # Test JSON exports
    print("\n--- Step 3: Testing JSON Export Methods ---")

    try:
        print("  Testing save_vulnerability_data()...")
        vuln_json = fetcher.save_vulnerability_data(vulns, 'test_sca_export.json')
        assert verify_json_export(vuln_json), "JSON verification failed"
        print(f"    ✓ {vuln_json} ({os.path.getsize(vuln_json)} bytes)")
    except Exception as e:
        logger.error(f"Failed to export vulnerability JSON: {e}")
        return False

    try:
        print("  Testing save_sbom_data()...")
        sbom_json = fetcher.save_sbom_data(components, 'test_sbom_export.json')
        assert verify_json_export(sbom_json), "JSON verification failed"
        print(f"    ✓ {sbom_json} ({os.path.getsize(sbom_json)} bytes)")
    except Exception as e:
        logger.error(f"Failed to export SBOM JSON: {e}")
        return False

    # Test CSV exports
    print("\n--- Step 4: Testing CSV Export Methods ---")

    try:
        print("  Testing export_vulnerability_csv()...")
        vuln_csv = fetcher.export_vulnerability_csv(vulns, 'test_vulnerability_export.csv')
        assert verify_csv_export(vuln_csv), "CSV verification failed"
        print(f"    ✓ {vuln_csv} ({os.path.getsize(vuln_csv)} bytes)")
    except Exception as e:
        logger.error(f"Failed to export vulnerability CSV: {e}")
        return False

    try:
        print("  Testing export_sbom_csv()...")
        sbom_csv = fetcher.export_sbom_csv(components, 'test_sbom_export.csv')
        assert verify_csv_export(sbom_csv), "CSV verification failed"
        print(f"    ✓ {sbom_csv} ({os.path.getsize(sbom_csv)} bytes)")
    except Exception as e:
        logger.error(f"Failed to export SBOM CSV: {e}")
        return False

    # Verify exports
    print("\n--- Step 5: Verifying Exports ---")

    files_to_check = [
        ('test_sca_export.json', 'Vulnerability JSON'),
        ('test_sbom_export.json', 'SBOM JSON'),
        ('test_vulnerability_export.csv', 'Vulnerability CSV'),
        ('test_sbom_export.csv', 'SBOM CSV'),
    ]

    all_files_exist = True
    for filename, desc in files_to_check:
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            print(f"  ✓ {desc:20} {filename:30} {size:>8} bytes")
        else:
            print(f"  ✗ {desc:20} {filename:30} NOT FOUND")
            all_files_exist = False

    if not all_files_exist:
        return False

    # Display sample data
    print("\n--- Step 6: Sample Data Preview ---")

    print("  Sample from test_vulnerability_export.csv:")
    with open('test_vulnerability_export.csv', 'r') as f:
        reader = csv.reader(f)
        header = next(reader)
        row = next(reader)
        print(f"    Columns: {len(header)}")
        print(f"    CVE: {row[0]}, Component: {row[4]}@{row[5]}, SHA1: {row[6]}, App: {row[9]}")

    print("\n  Sample from test_sbom_export.csv:")
    with open('test_sbom_export.csv', 'r') as f:
        reader = csv.reader(f)
        header = next(reader)
        row = next(reader)
        print(f"    Columns: {len(header)}")
        print(f"    Component: {row[2]}@{row[3]}, App: {row[1]}, Vendor: {row[10]}")

    # Summary
    print("\n" + "="*80)
    print("PHASE 4 EXPORT TEST SUMMARY")
    print("="*80)

    print(f"\n✓ Data Loaded:")
    print(f"  Vulnerability Records: {len(vulns)}")
    print(f"  SBOM Components: {len(components)}")

    print(f"\n✓ Exports Completed:")
    print(f"  JSON Exports: 2 (vulnerability + SBOM)")
    print(f"  CSV Exports: 2 (vulnerability + SBOM)")
    print(f"  Total Files: 4")

    print(f"\n✓ File Sizes:")
    total_size = sum(os.path.getsize(f) for f, _ in files_to_check if os.path.exists(f))
    print(f"  Total: {total_size:,} bytes")

    print(f"\n✅ PHASE 4 EXPORT TEST PASSED - All export methods working correctly!")
    return True


if __name__ == '__main__':
    success = test_phase_4_export()
    exit(0 if success else 1)
