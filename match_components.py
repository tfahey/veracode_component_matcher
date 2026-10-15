#!/usr/bin/env python3
"""
Component matching script for vulnerability_matcher.py

Matches SCA components with SBOM data using data exported from api_fetcher.py
(all_sca_components.json, all_sbom_components.json).

Run with:
    python match_components.py
"""

import json
import logging
import glob
from pathlib import Path
from vulnerability_matcher import VulnerabilityMatcher

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def load_sample_data(sbom_file: str, sca_file: str):
    """Load sample data from JSON files"""
    sbom_data = []
    sca_data = []

    # Load SBOM data
    if Path(sbom_file).exists():
        with open(sbom_file, 'r') as f:
            sbom_data = json.load(f)
        logger.info(f"✓ Loaded {len(sbom_data)} SBOM components from {sbom_file}")
    else:
        logger.warning(f"⚠ SBOM file not found: {sbom_file}")

    # Load SCA data
    if Path(sca_file).exists():
        with open(sca_file, 'r') as f:
            sca_data = json.load(f)
        logger.info(f"✓ Loaded {len(sca_data)} SCA components from {sca_file}")
    else:
        logger.warning(f"⚠ SCA file not found: {sca_file}")

    return sbom_data, sca_data


def match_components():
    """Match SCA and SBOM components from exported data"""

    print("\n" + "="*80)
    print("COMPONENT MATCHING - Using api_fetcher Export Data")
    print("="*80 + "\n")

    # Load sample data from api_fetcher exports (direct from export/ folder)
    print("--- Loading Sample Data ---")
    # Try recent exports first, fall back to older ones
    sbom_file = None
    sca_file = None

    # Find most recent SBOM and SCA export files
    import glob
    sbom_files = glob.glob('export/*sbom_20*.json') + glob.glob('*sbom_20*.json')
    sca_files = glob.glob('export/*sca_20*.json') + glob.glob('*sca_20*.json')

    # Also check legacy files
    sbom_files.extend(['all_sbom_components.json'])
    sca_files.extend(['all_sca_components.json'])

    for f in sorted(sbom_files, reverse=True):
        if Path(f).exists():
            sbom_file = f
            break

    for f in sorted(sca_files, reverse=True):
        if Path(f).exists():
            sca_file = f
            break

    sbom_data, sca_data = load_sample_data(sbom_file or 'all_sbom_components.json',
                                           sca_file or 'all_sca_components.json')

    if not sbom_data and not sca_data:
        print("✗ No data to test - export files are empty or missing")
        print("\nTo generate export files, run:")
        print("  python test_single_app.py 'GitHub-Verademo'")
        return False

    # Initialize matcher
    print("\n--- Initializing Vulnerability Matcher ---")
    matcher = VulnerabilityMatcher()

    # Load data (no field mapping needed - vulnerability_matcher handles it)
    print("\n--- Loading Data into Matcher ---")
    if sbom_data:
        print(f"Loading {len(sbom_data)} SBOM components...")
        # Load data directly - vulnerability_matcher.py handles field name mapping
        matcher.load_sbom_data(sbom_data)

    if sca_data:
        print(f"Loading {len(sca_data)} SCA components...")
        # Load data directly - vulnerability_matcher.py handles field name mapping
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
        for component in unmatched[:5]:  # Show first 5
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
        'matched_details': [
            {
                'sbom_name': m.sbom_component.name,
                'sbom_version': m.sbom_component.version,
                'sca_name': m.sca_component.name if m.sca_component else None,
                'sca_version': m.sca_component.version if m.sca_component else None,
                'strategy': m.match_strategy,
                'confidence': m.confidence,
            }
            for m in matched
        ],
        'unmatched_count': len(unmatched),
    }

    with open('match_components_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    print(f"✓ Results saved to match_components_results.json")

    # Summary
    print("\n" + "="*80)
    print("MATCHER TEST SUMMARY")
    print("="*80)
    print(f"✓ SBOM components processed: {len(sbom_data)}")
    print(f"✓ SCA records processed: {len(sca_data)}")
    print(f"✓ Matched: {len(matched)}")
    print(f"✓ Unmatched: {len(unmatched)}")
    print(f"✓ Match rate: {len(matched) / (len(matched) + len(unmatched)) * 100:.1f}%" if (len(matched) + len(unmatched)) > 0 else "")

    return True


if __name__ == '__main__':
    success = match_components()
    exit(0 if success else 1)
