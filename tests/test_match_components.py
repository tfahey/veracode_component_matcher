#!/usr/bin/env python3
"""
Test script for component matching with sample data

Tests the vulnerability_matcher.py matching engine using hardcoded sample data
to verify matching strategies work correctly.

Run with:
    python tests/test_match_components.py
"""

import json
import logging
from pathlib import Path
from vulnerability_matcher import VulnerabilityMatcher

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def test_match_components():
    """Test component matching with hardcoded sample data"""

    print("\n" + "="*80)
    print("COMPONENT MATCHING TEST - Sample Data Validation")
    print("="*80 + "\n")

    # Sample SBOM data (from SBOM API)
    sbom_data = [
        {
            'name': 'log4j',
            'version': '2.14.1',
            'purl': 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
            'bom_ref': 'sbom-12345',
            'sha1': 'abc123def456'
        },
        {
            'name': 'spring-core',
            'version': '5.3.8',
            'purl': 'pkg:maven/org/springframework/spring-core@5.3.8',
            'bom_ref': 'sbom-67890',
            'sha1': 'xyz789abc123'
        },
        {
            'name': 'jackson-databind',
            'version': '2.12.3',
            'purl': 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.3',
            'bom_ref': 'sbom-11111',
            'sha1': 'qqq111www222'
        },
        {
            'name': 'junit',
            'version': '4.13.2',
            'purl': 'pkg:maven/junit/junit@4.13.2',
            'bom_ref': 'sbom-22222',
            'sha1': 'eee555rrr666'
        },
        {
            'name': 'requests-http',
            'version': '2.26.0',
            'purl': 'pkg:pypi/requests@2.26.0',
            'bom_ref': 'sbom-33333',
            'sha1': 'ttt777yyy888'
        }
    ]

    # Sample SCA data (from detailedreport.do)
    sca_data = [
        {
            'library_name': 'log4j',
            'library_version': '2.14.1',
            'library_id': 'lib-001',
            'sha1': 'ABC123DEF456',
            'vendor': 'Apache',
            'vulnerabilities': [
                {'cve_id': 'CVE-2021-44228', 'severity': 'Critical'}
            ]
        },
        {
            'library_name': 'spring-framework',
            'library_version': '5.3.8',
            'library_id': 'lib-002',
            'sha1': 'xyz789abc123',
            'vendor': 'Spring',
            'vulnerabilities': []
        },
        {
            'library_name': 'jackson-databind',
            'library_version': '2.12.3',
            'library_id': 'lib-003',
            'sha1': 'qqq111www222',
            'vendor': 'FasterXML',
            'vulnerabilities': [
                {'cve_id': 'CVE-2020-36518', 'severity': 'High'}
            ]
        },
        {
            'library_name': 'junit4',
            'library_version': '4.13.2',
            'library_id': 'lib-004',
            'sha1': 'eee555rrr666',
            'vendor': 'JUnit',
            'vulnerabilities': []
        },
        {
            'library_name': 'requests',
            'library_version': '2.26.0',
            'library_id': 'lib-005',
            'sha1': 'ttt777yyy888',
            'vendor': 'Python Requests',
            'vulnerabilities': []
        }
    ]

    # Initialize matcher
    print("--- Initializing Vulnerability Matcher ---")
    matcher = VulnerabilityMatcher()

    # Load data
    print("\n--- Loading Sample Data ---")
    print(f"Loading {len(sbom_data)} SBOM components...")
    matcher.load_sbom_data(sbom_data)

    print(f"Loading {len(sca_data)} SCA components...")
    matcher.load_sca_data(sca_data)

    # Run matching
    print("\n--- Running Component Matching ---")
    matched, unmatched = matcher.match_all()

    # Display results
    print("\n--- Matching Results ---")
    print(f"✓ Matched components: {len(matched)}")
    print(f"✓ Unmatched components: {len(unmatched)}")

    if matched:
        print("\nMatched Components:")
        strategy_counts = {}
        for result in matched:
            strategy = result.match_strategy or 'unknown'
            strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1
            print(f"  - {result.sbom_component.name}@{result.sbom_component.version}")
            print(f"    Strategy: {result.match_strategy}, Confidence: {result.confidence:.2%}")
            if result.sca_component:
                print(f"    Matched with SCA: {result.sca_component.name}@{result.sca_component.version}")

        print("\nMatching Strategies Used:")
        for strategy, count in sorted(strategy_counts.items()):
            print(f"  {strategy}: {count} component(s)")

    if unmatched:
        print("\nUnmatched Components:")
        for component in unmatched[:5]:
            print(f"  - {component.name}@{component.version} (from {component.source})")
        if len(unmatched) > 5:
            print(f"  ... and {len(unmatched) - 5} more")

    # Save results
    print("\n--- Saving Results ---")
    strategy_breakdown = {}
    for m in matched:
        strategy = m.match_strategy or 'unknown'
        if strategy not in strategy_breakdown:
            strategy_breakdown[strategy] = 0
        strategy_breakdown[strategy] += 1

    results = {
        'total_matched': len(matched),
        'total_unmatched': len(unmatched),
        'match_rate': len(matched) / (len(matched) + len(unmatched)) * 100 if (len(matched) + len(unmatched)) > 0 else 0,
        'strategy_breakdown': strategy_breakdown,
        'strategies_tested': sorted(list(set(r.match_strategy for r in matched if r.match_strategy))),
        'test_data_type': 'sample'
    }

    results_file = 'tests/results/test_match_components_results.json'
    Path('tests/results').mkdir(parents=True, exist_ok=True)
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"✓ Results saved to {results_file}")

    # Summary
    print("\n" + "="*80)
    print("SAMPLE DATA MATCHING TEST SUMMARY")
    print("="*80)
    print(f"✓ SBOM components: {len(sbom_data)}")
    print(f"✓ SCA records: {len(sca_data)}")
    print(f"✓ Matched: {len(matched)}")
    print(f"✓ Unmatched: {len(unmatched)}")
    if (len(matched) + len(unmatched)) > 0:
        print(f"✓ Match rate: {len(matched) / (len(matched) + len(unmatched)) * 100:.1f}%")

    return True


if __name__ == '__main__':
    success = test_match_components()
    exit(0 if success else 1)
