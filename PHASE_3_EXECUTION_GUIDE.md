# Phase 3: API Implementation - Execution Guide

## Overview

**Phase 3** implements the complete data collection workflows in `api_fetcher.py`, using the data models from Phase 2 to store and process API responses.

**Time Estimate**: 6 hours  
**Status**: ✅ COMPLETE - API methods implemented  
**Deliverable**: Updated `api_fetcher.py` with Phase 3 methods

---

## What Phase 3 Includes

### Task 3.1: Vulnerability Data Collection ✅ COMPLETE

Four new methods added to `VeracodeApiFetcher`:

#### 1. **get_build_list(app_id)** (Line 338)
Fetches list of builds for an application

```python
def get_build_list(self, app_id: str) -> Optional[List[Dict]]:
    """Fetch list of builds for an application"""
```

**Returns**: List of build dictionaries with:
- `build_id`: Build identifier
- `version`: Build version
- `build_status`: Status (PUBLISHED, etc.)
- `published_date`: Publication date

**Used By**: `fetch_all_vulnerability_data()` to get available builds

#### 2. **get_latest_build(builds)** (Line 359)
Selects the most recent build from a list

```python
def get_latest_build(self, builds: List[Dict]) -> Optional[Dict]:
    """Select the latest build from a list"""
```

**Logic**: Sorts by `published_date` (descending) and returns the first (newest)

**Used By**: `fetch_all_vulnerability_data()` to select which build to analyze

#### 3. **get_detailed_report(build_id)** (Line 380)
Fetches vulnerability findings for a specific build

```python
def get_detailed_report(self, build_id: str) -> Optional[List[Dict]]:
    """Fetch detailed vulnerability findings for a build"""
```

**Returns**: List of vulnerability findings with:
- `cve_id`: CVE identifier
- `sha1`: **Matching key** (Column AA)
- `library_id`: **Matching key** (Column AE)
- `component_name`, `component_version`: Component info
- `severity`, `cvss_score`: Severity data
- And 30+ other fields

**Used By**: `fetch_all_vulnerability_data()` to get actual vulnerability data

#### 4. **fetch_all_vulnerability_data(app_limit)** (Line 405) ⭐
**MAIN WORKFLOW** - Orchestrates complete vulnerability data collection

```python
def fetch_all_vulnerability_data(self, app_limit: Optional[int] = None) -> List[Dict]:
    """Complete workflow for collecting vulnerability data"""
```

**Workflow**:
```
1. Get all applications
2. For each app:
   a. Get build list (get_build_list)
   b. Select latest build (get_latest_build)
   c. Get vulnerability findings (get_detailed_report)
   d. Extract and map all fields
   e. Create record dict with all 30+ fields
3. Return List[Dict] of vulnerability records
```

**Output Format**:
```python
[
    {
        # Matching keys
        'sha1': 'abc123...',
        'library_id': 'lib-001',
        
        # Vulnerability
        'cve_id': 'CVE-2021-44228',
        'severity': 5,
        'cvss_score': 9.8,
        
        # Component
        'component_name': 'log4j-core',
        'component_version': '2.14.1',
        
        # Build/App metadata
        'build_id': 'build-123',
        'app_id': 'app-001',
        'app_name': 'MyApp',
        
        # ... and 20+ more fields
    },
    # ... more vulnerability records
]
```

### Task 3.2: SBOM Data Collection ✅ COMPLETE

Three new methods added to `VeracodeApiFetcher`:

#### 1. **_extract_hash(component, hash_type)** (Line 537)
Helper to extract specific hash from CycloneDX component

```python
def _extract_hash(self, component: Dict, hash_type: str) -> Optional[str]:
    """Extract a specific hash type from a CycloneDX component"""
```

**Usage**:
```python
sha1 = self._extract_hash(component, 'SHA-1')
sha256 = self._extract_hash(component, 'SHA-256')
md5 = self._extract_hash(component, 'MD5')
```

**Why**: SBOM stores hashes in array format: `hashes[{alg: 'SHA-1', content: '...'}]`

#### 2. **fetch_all_sbom_data(app_limit)** (Line 554) ⭐
**MAIN WORKFLOW** - Orchestrates complete SBOM data collection

```python
def fetch_all_sbom_data(self, app_limit: Optional[int] = None) -> List[Dict]:
    """Complete workflow for collecting SBOM data"""
```

**Workflow**:
```
1. Get all applications (v1 API)
2. For each app with GUID:
   a. Get SBOM data (CycloneDX format)
   b. Extract components array
   c. For each component:
      - Extract hashes (SHA-1, SHA-256, etc.)
      - Extract CVE/CWE info
      - Enrich with app metadata
   d. Create component record with all fields
3. Return List[Dict] of SBOM components
```

**Output Format**:
```python
[
    {
        # App identification
        'application_id': '550e8400-e29b-41d4-a716-446655440000',
        'app_name': 'MyApp',
        
        # Component identification
        'component_name': 'lodash',
        'component_version': '4.17.21',
        'component_type': 'library',
        
        # Matching keys
        'bom_ref': 'pkg:npm/lodash@4.17.21',
        'sha1': '88d36f5051fb029ad5ef1119a73953f7add33fd9',
        
        # Additional hashes
        'sha256': 'be3e3338...',
        
        # Package info
        'purl': 'pkg:npm/lodash@4.17.21',
        'vendor': 'lodash',
        
        # Vulnerability info
        'cve_ids': 'CVE-2021-23337',
        'cwe_ids': 'CWE-1104',
        
        # ... more fields
    },
    # ... more components
]
```

---

## File Changes

### api_fetcher.py (Updated)

**New Methods Added** (Lines 328-650):

```python
# Phase 3: API Implementation
# Task 3.1: Vulnerability Data Collection
├── get_build_list(app_id) → Optional[List[Dict]]
├── get_latest_build(builds) → Optional[Dict]
├── get_detailed_report(build_id) → Optional[List[Dict]]
└── fetch_all_vulnerability_data(app_limit) → List[Dict]

# Task 3.2: SBOM Data Collection
├── _extract_hash(component, hash_type) → Optional[str]
└── fetch_all_sbom_data(app_limit) → List[Dict]
```

**Total Lines Added**: ~320 lines of implementation

---

## Usage Examples

### Example 1: Collect Vulnerability Data

```python
from api_fetcher import VeracodeApiFetcher

fetcher = VeracodeApiFetcher()

# Collect vulnerability data from all applications
vulns = fetcher.fetch_all_vulnerability_data()

print(f"Collected {len(vulns)} vulnerability records")

# Example output:
# Collected 1234 vulnerability records

# Access individual record
first_vuln = vulns[0]
print(f"CVE: {first_vuln['cve_id']}")  # CVE-2021-44228
print(f"Component: {first_vuln['component_name']}")  # log4j-core
print(f"SHA1: {first_vuln['sha1']}")  # abc123...
```

### Example 2: Collect SBOM Data

```python
from api_fetcher import VeracodeApiFetcher

fetcher = VeracodeApiFetcher()

# Collect SBOM data from all applications
components = fetcher.fetch_all_sbom_data()

print(f"Collected {len(components)} SBOM components")

# Example output:
# Collected 5678 SBOM components

# Access individual component
first_comp = components[0]
print(f"Component: {first_comp['component_name']}")  # lodash
print(f"Version: {first_comp['component_version']}")  # 4.17.21
print(f"SHA1: {first_comp['sha1']}")  # 88d36f5051...
```

### Example 3: Collect with Limit (Testing)

```python
from api_fetcher import VeracodeApiFetcher

fetcher = VeracodeApiFetcher()

# Test with only 3 applications
vulns = fetcher.fetch_all_vulnerability_data(app_limit=3)
components = fetcher.fetch_all_sbom_data(app_limit=3)

print(f"Test: {len(vulns)} vulnerabilities, {len(components)} components")
```

### Example 4: Save to Files

```python
from api_fetcher import VeracodeApiFetcher
import json

fetcher = VeracodeApiFetcher()

# Collect data
vulns = fetcher.fetch_all_vulnerability_data()
components = fetcher.fetch_all_sbom_data()

# Save to JSON files
with open('all_sca_components.json', 'w') as f:
    json.dump(vulns, f, indent=2)

with open('all_sbom_components.json', 'w') as f:
    json.dump(components, f, indent=2)

print("Data saved to JSON files")
```

---

## Integration with Data Models

Phase 3 data can be used with Phase 2 data models:

```python
from api_fetcher import VeracodeApiFetcher
from data_models import SCAVulnerabilityRecord, SBOMComponent

fetcher = VeracodeApiFetcher()

# Collect raw data
raw_vulns = fetcher.fetch_all_vulnerability_data()

# Convert to typed dataclass instances
vuln_records = [
    SCAVulnerabilityRecord(**vuln_dict)
    for vuln_dict in raw_vulns
]

print(f"Created {len(vuln_records)} typed vulnerability records")

# Can now use dataclass methods
for record in vuln_records[:5]:
    print(f"Valid: {record.is_valid()}")
    print(f"Key: {record.get_component_key()}")
```

---

## Data Flow

```
Phase 3 Implementation
═════════════════════════════════════════════════════════════

API Responses (XML/JSON)
         ↓
   get_build_list()
        ↓
   get_latest_build()
        ↓
   get_detailed_report()
        ↓
   Field Mapping & Extraction
        ↓
   fetch_all_vulnerability_data() → List[Dict]
        ↓
   Return to caller (Phase 4: Export)


SBOM Responses (CycloneDX JSON)
         ↓
    get_sbom()
        ↓
    _extract_hash()
        ↓
    Component Extraction
        ↓
    CVE/CWE Extraction
        ↓
    fetch_all_sbom_data() → List[Dict]
        ↓
    Return to caller (Phase 4: Export)
```

---

## Error Handling (Currently)

Phase 3 includes basic error handling:

- Try/except blocks catch API failures
- Logs errors but continues processing
- Missing builds/SBOM gracefully skipped
- Returns empty list if all apps fail

**Full Error Handling** will be added in **Phase 5**.

---

## Next Steps: Phase 4

**Phase 4: Data Export (2 hours)**

Phase 4 will:
1. Export vulnerability data to JSON/CSV
2. Export SBOM data to JSON/CSV
3. Create `save_vulnerability_data()` method
4. Create `save_sbom_data()` method
5. Create CSV export methods

**Usage in Phase 4:**
```python
fetcher = VeracodeApiFetcher()
vulns = fetcher.fetch_all_vulnerability_data()
components = fetcher.fetch_all_sbom_data()

fetcher.save_vulnerability_data(vulns, 'sca_data.json')
fetcher.save_sbom_data(components, 'sbom_data.json')
```

---

## Testing Phase 3

All Phase 3 methods are documented and ready for testing:

```bash
# Test by running api_fetcher.py (when Phase 7 docs complete)
python api_fetcher.py --limit 3

# Or test individual methods
python -c "
from api_fetcher import VeracodeApiFetcher
fetcher = VeracodeApiFetcher()
vulns = fetcher.fetch_all_vulnerability_data(app_limit=1)
print(f'Vulnerabilities: {len(vulns)}')
"
```

---

## Checklist: Phase 3 Complete

- ✅ get_build_list() method implemented
- ✅ get_latest_build() method implemented
- ✅ get_detailed_report() method implemented
- ✅ fetch_all_vulnerability_data() main workflow
- ✅ _extract_hash() helper implemented
- ✅ fetch_all_sbom_data() main workflow
- ✅ Field mapping for 30+ vulnerability fields
- ✅ Field mapping for 13 SBOM fields
- ✅ Logging at all key steps
- ✅ Error handling and graceful degradation
- ✅ Returns typed List[Dict] for both workflows
- ✅ Documentation complete

---

## Key Implementation Details

### Matching Keys Preserved
✓ `sha1` extracted and included in all records  
✓ `library_id` extracted from vulnerability data  
✓ `bom_ref` extracted from SBOM data

### Field Mapping Complete
✓ All 38 vulnerability fields mapped  
✓ All 13 SBOM fields mapped  
✓ Null/None values handled gracefully

### Performance Considerations
- Processes apps sequentially (not parallel)
- Continues on individual app failures
- Logs progress at key steps
- App limit option for testing

---

**Phase 3 Status**: ✅ COMPLETE  
**Next Phase**: Phase 4 - Data Export (2 hours)  
**Total Plan Progress**: 3/7 phases complete (8 hours done, 12 hours remaining)
