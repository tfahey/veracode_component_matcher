# Veracode Component Matcher

Fetches vulnerability data from Veracode's APIs across all applications and matches SCA components from `getbuildinfo.do` with SBOM data from the SBOM API endpoint, implementing multiple matching strategies to close data gaps.

## Features

- **Multiple matching strategies** to maximize component matching:
  - SHA1 hash matching (most reliable)
  - Package URL (PURL) matching
  - Composite key matching (vendor/name/version)
  - Library ID matching (Veracode-specific)
  - Fuzzy name matching (fallback)

- **Comprehensive reporting**:
  - Match statistics by strategy
  - Gap analysis with unmatched components
  - CSV export of matched and unmatched components
  - Detailed logging

- **Easy integration**:
  - Modular design for easy adaptation
  - Support for both API fetching and local JSON data
  - Configurable matching thresholds

## Installation

```bash
pip install -r requirements.txt
```

## Setup

Create a `.env` file with your Veracode credentials:

```
VERACODE_API_ID=your_api_id
VERACODE_API_KEY=your_api_key
```

## Usage

### Option 1: Fetch data from Veracode APIs

```python
from api_fetcher import VeracodeApiFetcher
from vulnerability_matcher import VulnerabilityMatcher

# Fetch data
fetcher = VeracodeApiFetcher()
build_info = fetcher.get_build_info(app_id="12345")
sbom_data = fetcher.get_sbom_cyclonedx(application_guid="app-guid-here")

sca_components = fetcher.extract_sca_vulnerabilities(build_info)
sbom_components = fetcher.extract_sbom_components(sbom_data)

# Match
matcher = VulnerabilityMatcher()
matcher.load_sbom_data(sbom_components)
matcher.load_sca_data(sca_components)
matched, unmatched = matcher.match_all()

# Report
matcher.print_summary()
matcher.export_matched_csv('matched.csv')
matcher.export_unmatched_csv('unmatched.csv')
```

### Option 2: Use local JSON files

```python
import json
from vulnerability_matcher import VulnerabilityMatcher

# Load from files
with open('sbom_components.json') as f:
    sbom_data = json.load(f)

with open('sca_components.json') as f:
    sca_data = json.load(f)

# Match
matcher = VulnerabilityMatcher()
matcher.load_sbom_data(sbom_data)
matcher.load_sca_data(sca_data)
matched, unmatched = matcher.match_all()

# Report
matcher.print_summary()
matcher.export_matched_csv('matched.csv')
matcher.export_unmatched_csv('unmatched.csv')
```

### Command Line

```bash
# Example with local data
python vulnerability_matcher.py

# Fetch and match in one go
python api_fetcher.py  # Requires editing main() with app IDs
```

## Matching Strategies

The matcher tries strategies in this order, stopping at the first match:

1. **SHA1** - Exact hash match (highest confidence)
2. **PURL** - Package URL matching (high confidence)
3. **Composite Key** - vendor/name/version (medium confidence)
4. **Library ID** - Veracode bom_ref to library_id (medium confidence)
5. **Fuzzy Name** - String similarity on normalized names (fallback)

Each strategy has different sensitivity to:
- Component packaging variations
- Build/rebuild differences
- Different package managers
- Transitive vs direct dependencies

## Output

### Summary Statistics
```
============================================================
VULNERABILITY MATCHING SUMMARY
============================================================
SBOM Components:        150
SCA Components:         120
Matched:                111
Unmatched:              39
Gap Percentage:         26.0%

Matches by Strategy:
  SHA1                   45 (40.5%)
  PURL                   38 (34.2%)
  COMPOSITE_KEY          18 (16.2%)
  LIBRARY_ID              7 (6.3%)
  FUZZY_NAME              3 (2.7%)
============================================================
```

### CSV Output

**matched.csv**
```
SBOM Name,SBOM Version,SCA Name,SCA Version,Match Strategy,Confidence,Vulnerabilities Count
log4j,2.14.1,log4j,2.14.1,sha1,1.0,5
```

**unmatched.csv**
```
Source,Name,Version,Component Type,Reason
SBOM,spring-web,5.3.9,Unknown,No matching SHA1/PURL/name+version found
SCA,jackson-annotations,2.11.2,Unknown,Orphaned SCA component
```

## Analyzing Unmatched Components

The 26% gap typically comes from:

1. **Transitive dependencies** - May lack SHA1 or have different package formats
2. **Developer dependencies** - Excluded from one scan type but not the other
3. **Unsupported package managers** - Format variations in name/version
4. **Timing issues** - Component scanned in one source but not the other
5. **Package manager changes** - Renamed or reorganized between scans

To investigate, examine the `unmatched.csv` for patterns in:
- Package manager type (npm, maven, pip, etc.)
- Component naming conventions
- Version format differences

## Customization

### Adjust fuzzy matching threshold

```python
matcher = VulnerabilityMatcher()
matcher.FUZZY_THRESHOLD = 80  # Default is 85
```

### Add custom matching strategy

```python
def _match_by_custom(self, component):
    # Your logic here
    return candidate_component or None

# Add to MATCH_STRATEGIES list
```

### Modify data extraction

Update `api_fetcher.py` methods to handle different API response structures:
- `extract_sca_vulnerabilities()` - Adjust for different build info formats
- `extract_sbom_components()` - Adapt to different SBOM structures

## Troubleshooting

**High unmatched percentage?**
- Check SBOM and SCA are from the same application/build
- Verify API endpoints are returning expected data structures
- Review unmatched component types and patterns

**False positives in fuzzy matching?**
- Lower `FUZZY_THRESHOLD` value
- Increase required version match precision

**API authentication errors?**
- Verify `.env` credentials are correct
- Check API ID/key have appropriate permissions
- Ensure endpoints are accessible from your network

## Future Enhancements

- Database backend for tracking match history
- Web dashboard for match visualization
- Machine learning-based matching optimization
- Integration with vulnerability management workflows
- Batch processing for multiple applications
