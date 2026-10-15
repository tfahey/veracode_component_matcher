#!/usr/bin/env python3
"""
Test script for CSV export + vulnerability matching

Uses sample JSON data (all_sca_components.json, all_sbom_components.json),
runs vulnerability matching, and exports results to both CSV and JSON files.

Output files (in tests/results/):
- matched_components.csv: Successfully matched SBOM + SCA components
- unmatched_components.csv: Components that could not be matched
- test_csv_matcher_results.json: Detailed matching results with statistics

Run with:
    python tests/test_csv_export.py
"""

import json
import logging
from pathlib import Path
from vulnerability_matcher import VulnerabilityMatcher

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def load_sample_data(sbom_file: str, sca_file: str):
    """Load sample data from JSON files"""
    sbom_data = []
    sca_data = []

    if Path(sbom_file).exists():
        with open(sbom_file, 'r') as f:
            sbom_data = json.load(f)
        logger.info(f"✓ Loaded {len(sbom_data)} SBOM components from {sbom_file}")
    else:
        logger.warning(f"⚠ SBOM file not found: {sbom_file}")

    if Path(sca_file).exists():
        with open(sca_file, 'r') as f:
            sca_data = json.load(f)
        logger.info(f"✓ Loaded {len(sca_data)} SCA records from {sca_file}")
    else:
        logger.warning(f"⚠ SCA file not found: {sca_file}")

    return sbom_data, sca_data


def map_sbom_data(sbom_data):
    """Map sample SBOM data to matcher format"""
    mapped = []
    for component in sbom_data:
        mapped_component = {
            'name': component.get('component_name'),
            'version': component.get('component_version'),
            'bom-ref': component.get('bom_ref'),
            'purl': component.get('purl'),
            'hashes': {'SHA-1': component.get('sha1')} if component.get('sha1') else {},
            'library_id': component.get('library_id'),
        }
        mapped.append(mapped_component)
    return mapped


def map_sca_data(sca_data):
    """Map sample SCA data to matcher format"""
    mapped = []
    for record in sca_data:
        mapped_record = {
            'library_name': record.get('component_name'),
            'library_version': record.get('component_version'),
            'library_id': record.get('library_id'),
            'sha1': record.get('sha1'),
            'purl': None,
            'vulnerabilities': [{
                'cve_id': record.get('cve_id'),
                'severity': record.get('severity'),
                'cvss_score': record.get('cvss_score'),
                'description': record.get('description'),
                'first_found_date': record.get('first_found_date'),
                'cwe_id': record.get('cwe_id'),
            }] if record.get('cve_id') else [],
        }
        mapped.append(mapped_record)
    return mapped


def save_matcher_results(matcher, filename: str = 'test_csv_matcher_results.json'):
    """Save detailed matcher results to JSON"""
    results = {
        'statistics': matcher.get_statistics(),
        'matched_details': [
            {
                'sbom_name': m.sbom_component.name,
                'sbom_version': m.sbom_component.version,
                'sbom_sha1': m.sbom_component.sha1,
                'sbom_purl': m.sbom_component.purl,
                'sbom_bom_ref': m.sbom_component.bom_ref,
                'sca_name': m.sca_component.name if m.sca_component else None,
                'sca_version': m.sca_component.version if m.sca_component else None,
                'sca_sha1': m.sca_component.sha1 if m.sca_component else None,
                'sca_library_id': m.sca_component.library_id if m.sca_component else None,
                'match_strategy': m.match_strategy,
                'confidence': m.confidence,
                'cve_ids': [v.get('cve_id') for v in m.sca_component.vulnerabilities] if m.sca_component else [],
            }
            for m in matcher.matched
        ],
        'unmatched_details': [
            {
                'name': c.name,
                'version': c.version,
                'source': c.source,
                'sha1': c.sha1,
                'library_id': c.library_id,
                'purl': c.purl,
                'bom_ref': c.bom_ref,
                'reason': 'No matching SHA1/PURL/name+version found' if c.source == 'sbom' else 'Orphaned SCA component',
            }
            for c in matcher.unmatched
        ],
    }

    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)

    logger.info(f"✓ Saved detailed results to {filename}")
    return filename


def test_csv_export():
    """Test CSV export workflow with sample data"""

    print("\n" + "="*80)
    print("CSV EXPORT TEST - Vulnerability Matching & Export")
    print("="*80 + "\n")

    # Load sample data
    print("--- Step 1: Loading Sample Data ---")
    sbom_data, sca_data = load_sample_data('all_sbom_components.json', 'all_sca_components.json')

    if not sbom_data and not sca_data:
        print("✗ No data to process - both sample files are empty or missing")
        return False

    # Initialize and run matcher
    print("\n--- Step 2: Running Vulnerability Matcher ---")
    matcher = VulnerabilityMatcher()

    # Load data
    if sbom_data:
        print(f"Loading {len(sbom_data)} SBOM components...")
        matcher.load_sbom_data(map_sbom_data(sbom_data))

    if sca_data:
        print(f"Loading {len(sca_data)} SCA records...")
        matcher.load_sca_data(map_sca_data(sca_data))

    # Run matching
    print("\nExecuting matching process...")
    matched, unmatched = matcher.match_all()

    print(f"\n✓ Matching complete:")
    print(f"  Matched: {len(matched)} components")
    print(f"  Unmatched: {len(unmatched)} components")

    # Export results
    print("\n--- Step 3: Exporting Results ---")

    # Create output directory
    Path('tests/results').mkdir(parents=True, exist_ok=True)

    # CSV exports
    print("Exporting to CSV...")
    csv_matched = 'tests/results/matched_components.csv'
    csv_unmatched = 'tests/results/unmatched_components.csv'
    matcher.export_matched_csv(csv_matched)
    matcher.export_unmatched_csv(csv_unmatched)

    # JSON export
    print("Exporting detailed results to JSON...")
    json_results = save_matcher_results(matcher, 'tests/results/test_csv_matcher_results.json')

    # Display summary
    print("\n--- Step 4: Generating Summary ---")
    matcher.print_summary()

    # Statistics
    print("="*80)
    print("EXPORT SUMMARY")
    print("="*80)

    stats = matcher.get_statistics()
    print(f"\n✓ SBOM Components Processed:  {stats['total_sbom_components']}")
    print(f"✓ SCA Records Processed:      {stats['total_sca_components']}")
    print(f"✓ Successfully Matched:       {stats['matched_components']}")
    print(f"✓ Unmatched Components:       {stats['unmatched_components']}")
    print(f"✓ Overall Match Rate:         {100 - stats['match_gap_percentage']:.1f}%")

    print(f"\n📊 Output Files Generated:")
    print(f"   ✓ {csv_matched}")
    print(f"   ✓ {csv_unmatched}")
    print(f"   ✓ {json_results}")

    # Verify files were created
    all_files_exist = all(Path(f).exists() for f in [csv_matched, csv_unmatched, json_results])
    if all_files_exist:
        print(f"\n✅ CSV EXPORT TEST PASSED - All files generated successfully")
        return True
    else:
        print(f"\n❌ CSV EXPORT TEST FAILED - Some files were not created")
        return False


if __name__ == '__main__':
    success = test_csv_export()
    exit(0 if success else 1)
