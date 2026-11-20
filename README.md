# Veracode Component Matcher

Fetches vulnerability data from Veracode's APIs across all applications and matches SCA components from `detailedreport.do` (software_composition_analysis section) with SBOM data from the CycloneDX SBOM API endpoint, implementing multiple matching strategies to close data gaps.

## Features

- **Per-application matching** - each application's SCA components are compared only with that same application's SBOM
- **Multiple matching strategies**, exact identifiers first:
  - SHA1 hash matching (most reliable)
  - Package URL (PURL) matching
  - Library ID matching (Veracode-specific)
  - Composite key matching (vendor/name/version)
  - Fuzzy name matching (fallback)
- **Linked SCA agent projects** - agent-based SBOMs of projects linked to an application are merged into that application's SBOM data
- **Explained gaps** - every unmatched component gets a reason, including the Veracode API's reason when an application has no SBOM

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
python tests/test_single_app.py "GitHub-Verademo"

# Run vulnerability matching on exported data
python match_components.py
```

**What happens:**
- `api_fetcher.py` fetches SCA components and SBOM data from all Veracode applications
- Exports JSON files with component data to `./data/` directory
- `tests/test_single_app.py` tests a single application and exports results to `tests/results/`
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

app_id, app_guid, app_name = "1301028", "6a747366-ed0d-490c-a069-39995c4ad7d6", "GitHub-Verademo"

# Get the latest build (getbuildlist.do returns builds oldest -> newest)
builds = fetcher.get_build_list(app_id)
build = builds[-1]

# Get SCA data from detailed report, tagged with app and build
detailed_report = fetcher.get_detailed_report(build['build_id'])
sca_components = fetcher.extract_sca_from_detailed_report(
    detailed_report, app_id=app_id, app_guid=app_guid, app_name=app_name,
    build_id=build['build_id'], build_date=build.get('policy_updated_date'))

# Get SBOM data: application SBOM plus agent SBOMs of linked SCA projects
sbom_components, unavailable_reason = fetcher.collect_app_sbom_components(app_id, app_guid, app_name=app_name)
if unavailable_reason:
    print(f"No SBOM data: {unavailable_reason}")

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

**Select applications (`api_fetcher.py`):**

| Option | Description |
|---|---|
| `--app-name TEXT` | Only process applications whose name contains `TEXT` (server-side partial name match) |
| `--org-id ID` | Only process applications in organization `ID`. Useful for accounts that can see many organizations; combine with `--app-name` to avoid listing every application |
| `--list-apps` | Print the matching applications (App ID, Org ID, GUID, Name) and exit without fetching SCA or SBOM data |

```bash
# Only applications whose name contains "Payments"
python api_fetcher.py --app-name "Payments" --output ./out/payments

# Only applications in organization 12345 whose name contains "Payments"
python api_fetcher.py --app-name "Payments" --org-id 12345 --output ./out/org_12345

# Preview which applications would be processed
python api_fetcher.py --app-name "Payments" --org-id 12345 --list-apps
```

**Test single application (`tests/test_single_app.py`):**

The application can be given as a name, app ID, or app GUID. An app ID or GUID is looked up directly, which is much faster than a name search.

| Option | Description |
|---|---|
| `--org-id ID` | When searching by name, only match applications in organization `ID` |

```bash
# By name
python tests/test_single_app.py "GitHub-Verademo"

# By app ID or app GUID
python tests/test_single_app.py 1301028
python tests/test_single_app.py 6a747366-ed0d-490c-a069-39995c4ad7d6

# Name search restricted to one organization
python tests/test_single_app.py "Payments" --org-id 12345

# Results saved to tests/results/ directory with timestamps
```

**Run component matching:**
```bash
# Match exported SCA and SBOM data
python match_components.py

# Displays match statistics and saves results to CSV
```

**Run integration tests:**
```bash
# Test component matching with sample data
python tests/test_match_components.py

# Run all phase 6 integration tests
python tests/test_phase_6_integration.py
```

## How Matching Works and Reading the Results

### Where the data comes from

| Data | Source | Notes |
|---|---|---|
| SCA components | `detailedreport.do` (software_composition_analysis section) for the application's **latest build** in `getbuildlist.do` | The build list is ordered oldest to newest; the last entry is used. Each record carries `app_id`, `app_guid`, `app_name`, `build_id` and `build_published_date`. |
| Application SBOM | `GET /srcclr/sbom/v1/targets/{appGuid}/cyclonedx?type=application` | Only available if the application has had a **policy scan (or agent scan) within the last 13 months**. Running a new policy scan makes the SBOM available. |
| Linked project SBOMs | `GET /srcclr/v3/applications/{appGuid}/projects` to list linked SCA agent projects, then `GET /srcclr/sbom/v1/targets/{projectGuid}/cyclonedx?type=agent` for each | Always fetched and merged into the application's SBOM data. Tagged `sbom_source = agent:<project name>`. |

Every SBOM component records where it came from in `sbom_source`: `application` or `agent:<linked project name>`.

### How components are matched

1. **Matching is per application.** Components are grouped by application GUID (falling back to app ID), and each application's SBOM components are compared only with that application's SCA components. The same library in two applications is matched separately.
2. **Matching is driven from the SBOM side.** For each SBOM component, the strategies below are tried in order and the first one that finds an SCA component wins. Each SBOM component is paired with at most one SCA component.
3. **Strategy order** - exact identifiers first, fuzzy matching last:

| # | Strategy | Compares | Confidence |
|---|---|---|---|
| 1 | `sha1` | SBOM SHA-1 hash with SCA SHA-1 | 1.0 |
| 2 | `purl` | Package URL type, namespace, name and version | 1.0 |
| 3 | `library_id` | SBOM `bom_ref` with SCA `library_id` (Veracode format `type:group:artifact:version:`, e.g. `maven:org.yaml:snakeyaml:1.26:`) | 1.0 |
| 4 | `composite_key` | vendor/name/version | 1.0 |
| 5 | `fuzzy_name` | Normalized-name similarity of at least `FUZZY_THRESHOLD` (85), +10 when versions are equal | 0.85 |

`library_id` runs before `fuzzy_name` on purpose. Agent SBOMs have no SHA-1 hashes and SCA records have no purls, so when fuzzy matching ran earlier it could pair an SBOM component with the wrong SCA record (for example `commons-collections4@4.0` with SCA `Commons Collections@3.1`, leaving `Apache Commons Collections@4.0` unmatched). With exact identifiers first, most matches are made by `library_id` or `sha1`, and fuzzy matching is a rare fallback.

### Output files

| File | Contents |
|---|---|
| `all_sca_components_<ts>.json`, `vulnerabilities_<ts>.csv` | SCA records with app and build columns |
| `all_sbom_components_<ts>.json`, `sbom_components_<ts>.csv` | SBOM components with app columns and `sbom_source` |
| `application_metadata_<ts>.csv/.json` | One row per application: `app_id`, `app_guid`, `sbom_component_count`, `sbom_unavailable_reason` |
| `matched_components_<ts>.csv` | `App ID, App Name, SBOM Name, SBOM Version, SCA Name, SCA Version, Match Strategy, Confidence, Vulnerabilities Count, Build ID, Build Published Date` |
| `unmatched_components_<ts>.csv` | `App ID, App Name, Source, Name, Version, Component Type, Reason, Reason Detail, Build ID, Build Published Date, SBOM Source` |

Example summary:
```
============================================================
VULNERABILITY MATCHING SUMMARY
============================================================
SBOM Components:        1170
SCA Components:         5396
Matched:                1163
Unmatched:              4240
Gap Percentage:         362.39%

Unmatched by Reason:
  No SBOM data for application              4207
  No matching SHA1/PURL/name+version found     7
  Orphaned SCA component                      26

Orphaned SCA by Classification:
  Likely version mismatch                      1
  Not in SBOM                                 25

Matches by Strategy:
  LIBRARY_ID            965 (83.0%)
  SHA1                  198 (17.0%)
============================================================
```

`Gap Percentage` is unmatched components divided by SBOM components, so it can exceed 100% when many applications have SCA data but no SBOM. Use **Unmatched by Reason** to see what the gap actually consists of.

### Unmatched reasons

| Reason | Source | Meaning | What to do |
|---|---|---|---|
| `No SBOM data for application` | SCA | The application has SCA data but no SBOM components at all (neither application nor linked-project SBOM). `Reason Detail` holds the API's explanation. | Not a matching failure. See the SBOM availability messages below. |
| `No SCA data for application` | SBOM | The application has SBOM components but no SCA records. | Check that the application's latest build has SCA results in `detailedreport.do`. |
| `No matching SHA1/PURL/name+version found` | SBOM | An SBOM component that no SCA component matched. | Usually the application's own packaging (e.g. `verademo.war`, `spring-boot-*.jar`), which SCA does not report as a library. |
| `Orphaned SCA component` | SCA | The application **has** SBOM data, but no SBOM component was paired with this SCA record. | Read `Reason Detail` (below). |

`Orphaned SCA component` does **not** always mean the library is missing from the SBOM. A second pass looks for the same library in the application's SBOM - by package coordinates (`library_id` vs. SBOM `bom_ref`/purl, ignoring version), then by normalized name - and classifies the orphan in `Reason Detail`:

| Reason Detail | Meaning |
|---|---|
| `Not in SBOM` | No SBOM component with the same package or name. The library is genuinely absent from the SBOM. |
| `Likely version mismatch` | The SBOM has the same library at a different version (e.g. SCA `Apache Log4j@1.2.8`, SBOM `log4j@1.2.17`). Usually the two sides come from different scans. |
| `Likely mis-match` | The SBOM has the same library and version, but that SBOM component was paired with a different SCA record. Indicates a matching-strategy problem worth reporting. |
| `Likely missed match` | The SBOM has the same library and version and it is also unmatched. Indicates a matching gap worth reporting. |

### SBOM availability messages

When an application has no SBOM data, `Reason Detail` (unmatched CSV) and `sbom_unavailable_reason` (application metadata) contain the reason:

| Message | Meaning | Fix |
|---|---|---|
| `HTTP 404: No Policy or Agent Scan Performed in last 13 Months. Please initiate new scan.` | No policy or agent scan in the last 13 months. Sandbox scans do not count. | Run a policy scan, or link an SCA agent project that has been scanned recently. |
| `HTTP 404: The requested resource could not be found` | The SBOM service has no SBOM for this target. The underlying cause has not been confirmed. | Check the application's scan history and SCA results in the Veracode platform. |
| `SBOM returned but contained no components` | The SBOM call succeeded but listed no components, so Veracode SCA found no open-source libraries to report. A common cause is a language or build system that SCA does not support (see below). | Check the application's language against the supported languages and its SCA results in the platform. |

**Language support.** Veracode SCA does not support every language, so some applications legitimately produce an SBOM with no components:

- **C and C++ are not supported by SCA upload and scan.** See [SCA upload and scan - supported languages](https://docs.veracode.com/r/SCA_Upload_and_Scan#supported-languages).
- **C and C++ are supported by SCA agent-based scans only for projects built with Make.** See [Agent-based scans - supported languages](https://docs.veracode.com/r/Agent_Based_Scans#supported-languages). Scanning a Make-based C/C++ project with the SCA agent and linking it to the application adds its components through the linked-project SBOM.
- **Python with Poetry is supported** by both scan types (`pyproject.toml` and `poetry.lock`), so an empty SBOM for a Poetry application is not explained by language support. Check that those files were included in the upload.

### Common scenarios

| Scenario | What to expect |
|---|---|
| Application with a recent policy scan | Application SBOM is returned; most SCA components match by `library_id` or `sha1`. A few SBOM-only entries for the application's own artifacts. |
| No policy scan in 13 months, no linked project | No SBOM. All SCA records are `No SBOM data for application` with the 13-month message. |
| No recent policy scan, but a linked agent project | SBOM comes only from the linked project (`sbom_source = agent:...`). If the linked project is different code from what was uploaded, many SCA records are `Orphaned SCA component` / `Not in SBOM`. |
| Recent policy scan and a linked project | Both SBOMs are merged. The SBOM export lists a component once per source; the matcher treats entries with the same name and version as one component. |
| Libraries changed between the SCA build and the SBOM scan | Orphans classified `Likely version mismatch` or `Not in SBOM`. |
| Same library in several applications | Matched independently per application. |

### Interpreting results - checklist

1. Start with **Unmatched by Reason**. `No SBOM data for application` is an SBOM availability issue, not a matching issue; check `sbom_unavailable_reason` in the application metadata.
2. For `Orphaned SCA component`, filter on `Reason Detail`: `Not in SBOM` and `Likely version mismatch` usually mean the two sides describe different scans; `Likely mis-match` and `Likely missed match` point at the matcher.
3. Check `SBOM Source`: orphans in applications whose SBOM is only `agent:...` often reflect what the linked project contains rather than a matching problem.
4. Compare `Build Published Date` with the SBOM's scan time when versions differ.

### Known limitations

- `Build Published Date` is the build's `policy_updated_date` from `getbuildlist.do`. It changes when policy is re-evaluated, so it is not necessarily the scan date.
- Agent SBOMs carry no SHA-1 hashes, so their components match by `library_id` or name.
- Records without application information (for example hand-built sample data) are all matched as a single group.

## Customization

### Adjust fuzzy matching threshold

```python
matcher = VulnerabilityMatcher()
matcher.FUZZY_THRESHOLD = 80  # Default is 85
```

### Add custom matching strategy

```python
def _match_by_custom(self, sbom_component, candidates):
    # candidates: SCA components of the same application
    # Your logic here
    return matching_sca_component or None

# Add the strategy name to MATCH_STRATEGIES and dispatch it in _match_component()
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
- Look at **Unmatched by Reason** first - most of the gap is usually applications with no SBOM data
- See [How Matching Works and Reading the Results](#how-matching-works-and-reading-the-results)

**False positives in fuzzy matching?**
- Raise `FUZZY_THRESHOLD` (default 85) so fewer names qualify as matches

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
