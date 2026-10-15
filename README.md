# Veracode Component Matcher

Fetches vulnerability data from Veracode's APIs across all applications and matches SCA components from `detailedreport.do` (software_composition_analysis section) with SBOM data from the CycloneDX SBOM API endpoint, implementing multiple matching strategies to close data gaps.

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

## Installation & Setup

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Credentials

Choose one of these methods (in order of precedence):

**Option A: Environment Variables (recommended for CI/CD)**
```bash
export VERACODE_API_KEY_ID=your_api_id
export VERACODE_API_KEY_SECRET=your_api_secret
python api_fetcher.py
```

**Option B: .env File (recommended for local development)**
```bash
# Create .env in project directory
echo "VERACODE_API_KEY_ID=your_api_id" > .env
echo "VERACODE_API_KEY_SECRET=your_api_secret" >> .env
python api_fetcher.py
```

**Option C: Credentials File (system default)**
```bash
# Create ~/.veracode/credentials file
mkdir -p ~/.veracode
cat > ~/.veracode/credentials << EOF
[default]
veracode_api_key_id = your_api_id
veracode_api_key_secret = your_api_secret
EOF
python api_fetcher.py
```

**Option D: Command-Line Arguments (least preferred)**
```bash
python api_fetcher.py --veracode_api_key_id YOUR_ID --veracode_api_key_secret YOUR_SECRET
```

⚠️ **Security note**: Never commit `.env` file to git (it's in `.gitignore`)

## Quick Start (Command Line)

The simplest way to run the component matcher:

```bash
# Fetch SCA/SBOM data from all applications and match components
python api_fetcher.py --output ./data

# Test single application
python test_single_app.py "GitHub-Verademo"

# Run vulnerability matching on exported data
python match_components.py
```

**What happens:**
- `api_fetcher.py` fetches SCA components and SBOM data from all Veracode applications
- Exports JSON files with component data to `./data/` directory
- `test_single_app.py` tests a single application and exports results to `./export/`
- `match_components.py` runs the matching engine and shows results

**Output files created:**
- `all_sca_components.json` - Raw SCA vulnerability data
- `all_sbom_components.json` - Raw SBOM component data
- `matched_components.csv` - Components matched across SCA/SBOM
- `unmatched_components.csv` - Components in only one source

## Usage

### Option 1: Fetch data from Veracode APIs

```python
from api_fetcher import VeracodeApiFetcher
from vulnerability_matcher import VulnerabilityMatcher

# Fetch data
fetcher = VeracodeApiFetcher()

# Get application and build list
builds = fetcher.get_build_list(app_id="1301028")
build_id = builds[0]['build_id']

# Get SCA data from detailed report
detailed_report = fetcher.get_detailed_report(build_id)
sca_components = fetcher.extract_sca_from_detailed_report(detailed_report)

# Get SBOM data
sbom_data = fetcher.get_sbom(app_guid="6a747366-ed0d-490c-a069-39995c4ad7d6")
sbom_components = fetcher.extract_sbom_components(sbom_data)

# Match
matcher = VulnerabilityMatcher()
matcher.load_sbom_data(sbom_components)
matcher.load_sca_data(sca_components)
matched, unmatched = matcher.match_all()

# Report
print(f"Matched: {len(matched)}, Unmatched: {len(unmatched)}")
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

### Command Line - Detailed

**Fetch data from all applications:**
```bash
# Fetch all applications (uses credentials from .env or ~/.veracode/credentials)
python api_fetcher.py

# Fetch and save to custom directory
python api_fetcher.py --output ./my_data

# Fetch only first N applications (useful for testing)
python api_fetcher.py --limit 5

# Use specific API credentials
python api_fetcher.py --veracode_api_key_id YOUR_ID --veracode_api_key_secret YOUR_SECRET
```

**Test single application:**
```bash
# Export SCA and SBOM data for one app
python test_single_app.py "GitHub-Verademo"

# Results saved to export/ directory with timestamps
```

**Run component matching:**
```bash
# Match exported SCA and SBOM data
python match_components.py

# Displays match statistics and saves results to CSV
```

**Run all integration tests:**
```bash
python test_phase_6_integration.py
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
- `extract_sca_from_detailed_report()` - Adjust SCA extraction from detailedreport.do
- `extract_sbom_components()` - Adapt to different SBOM structures
- `extract_sca_vulnerabilities()` - Legacy method for getbuildinfo.do (deprecated)

## Troubleshooting

### Command-Line Issues

**"ModuleNotFoundError: No module named 'veracode_api_py'"**
```bash
# Install dependencies
pip install -r requirements.txt
```

**"API credentials are invalid or expired"**
```bash
# Check your credentials are correct
# Option 1: Verify .env file
cat .env

# Option 2: Verify environment variables
echo $VERACODE_API_KEY_ID
echo $VERACODE_API_KEY_SECRET

# Option 3: Verify credentials file
cat ~/.veracode/credentials
```

**"No module named 'api_fetcher'"**
```bash
# Run from project root directory
cd /path/to/veracode_component_matcher
python api_fetcher.py
```

**"Permission denied" when running script**
```bash
# Make script executable
chmod +x api_fetcher.py
python api_fetcher.py  # or use python explicitly
```

### Data Issues

**High unmatched percentage?**
- Check SBOM and SCA are from the same application/build
- Verify API endpoints are returning expected data structures
- Review unmatched component types and patterns

**False positives in fuzzy matching?**
- Lower `FUZZY_THRESHOLD` value
- Increase required version match precision

**API authentication errors?**
- Verify credentials are correct for your Veracode account
- Check API ID/key have appropriate permissions
- Ensure endpoints are accessible from your network

## Future Enhancements

- Database backend for tracking match history
- Web dashboard for match visualization
- Machine learning-based matching optimization
- Integration with vulnerability management workflows
- Batch processing for multiple applications
