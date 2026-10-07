# Phase 2: Data Structure Design - Execution Guide

## Overview

**Phase 2** defines the Python data model classes that represent vulnerability and SBOM components. This phase bridges the API data with the matching and reporting workflows.

**Time Estimate**: 3 hours  
**Status**: ✅ COMPLETE - Data models created and tested  
**Deliverable**: `data_models.py` with full dataclass definitions

---

## What Phase 2 Includes

### Task 2.1: Define Data Classes ✅ COMPLETE

Two main dataclasses created:

#### 1. **SCAVulnerabilityRecord** (38 fields)
Represents vulnerability data from `detailedreport.do` API

**Key Features:**
- Comprehensive field mapping (all 38 columns from Excel)
- Matching keys: `sha1` (Column AA), `library_id` (Column AE)
- Proper type hints (Optional[str], Optional[int], etc.)
- Data validation in `__post_init__`
- Helper methods: `is_valid()`, `get_component_key()`, `to_dict()`

**Structure:**
```python
@dataclass
class SCAVulnerabilityRecord:
    # Matching Keys (Critical)
    sha1: Optional[str]
    library_id: Optional[str]

    # Vulnerability Info
    cve_id, severity, cwe_id, cvss_score, ...

    # Component Info
    component_name, component_version, component_id, ...

    # Build Info
    build_id, build_version, build_published_date, ...

    # App Info
    app_id, app_guid, app_name, business_criticality, ...

    # And 20+ more fields...
```

#### 2. **SBOMComponent** (13 fields)
Represents components from SBOM v1 API (CycloneDX format)

**Key Features:**
- Mapping to SBOM sheet columns (A-M)
- Matching keys: `sha1` (Column F), `bom_ref` (Column E)
- PURL parsing: `get_purl_parts()`
- Validation: Required fields enforce in `__post_init__`

**Structure:**
```python
@dataclass
class SBOMComponent:
    # Required Fields
    application_id: str
    app_name: str
    component_name: str

    # Matching Keys (Critical)
    bom_ref: Optional[str]
    sha1: Optional[str]

    # Additional Info
    component_version, component_type, purl, vendor, ...
    cve_ids, cwe_ids, all_dependencies, ...
```

#### 3. **VulnerabilityGroup**
Helper dataclass for data aggregation

Used to group multiple CVEs by component during processing:
```python
@dataclass
class VulnerabilityGroup:
    component: SCAVulnerabilityRecord
    vulnerabilities: List[Dict[str, Any]]

    # Methods:
    - add_vulnerability()
    - get_cve_count()
    - get_cve_ids()
    - get_max_severity()
```

### Task 2.2: Design Aggregation Strategy ✅ COMPLETE

**DataAggregator** class provides data processing utilities:

#### Method 1: `group_vulnerabilities_by_component()`
Groups multiple CVE records for same component

```python
findings = [
    {'sha1': 'abc123', 'library_id': 'lib-001', 'cve_id': 'CVE-2021-1234', ...},
    {'sha1': 'abc123', 'library_id': 'lib-001', 'cve_id': 'CVE-2021-5678', ...},
]

groups = DataAggregator.group_vulnerabilities_by_component(findings)
# Result: {('abc123', 'lib-001', 'log4j', '2.14.1'): VulnerabilityGroup(...)}
```

**Why This Matters:**
- detailedreport.do returns one vulnerability per row
- Same component may have multiple CVEs
- Allows analysis and aggregation before denormalizing back

#### Method 2: `flatten_vulnerability_groups()`
Converts grouped data back to denormalized (one row per CVE)

```python
groups = DataAggregator.group_vulnerabilities_by_component(findings)
records = DataAggregator.flatten_vulnerability_groups(groups)
# Result: List of SCAVulnerabilityRecord, one per CVE
```

#### Method 3: `deduplicate_sbom_components()`
Removes duplicate SBOM components by key

```python
components = [sbom1, sbom2, sbom1_duplicate, ...]
unique = DataAggregator.deduplicate_sbom_components(components)
# Result: List with duplicates removed
```

#### Method 4: `validate_records()`
Validates vulnerability records before export

```python
valid, errors = DataAggregator.validate_records(records, min_match_keys=True)
print(f"Valid: {len(valid)}, Errors: {len(errors)}")
```

---

## File Structure

### `data_models.py` (430+ lines)

```
data_models.py
├── SCAVulnerabilityRecord (class, 38 fields)
│   ├── __post_init__() - Type normalization
│   ├── to_dict()
│   ├── is_valid()
│   └── get_component_key()
│
├── SBOMComponent (class, 13 fields)
│   ├── __post_init__() - Validation
│   ├── to_dict()
│   ├── is_valid()
│   ├── get_component_key()
│   └── get_purl_parts()
│
├── VulnerabilityGroup (class)
│   ├── add_vulnerability()
│   ├── get_cve_count()
│   ├── get_cve_ids()
│   └── get_max_severity()
│
├── DataAggregator (class, 4 static methods)
│   ├── group_vulnerabilities_by_component()
│   ├── flatten_vulnerability_groups()
│   ├── deduplicate_sbom_components()
│   └── validate_records()
│
└── Utility Functions
    ├── create_sample_vulnerability_record()
    ├── create_sample_sbom_component()
    └── __main__ (test suite)
```

---

## Usage Examples

### Example 1: Create a Vulnerability Record

```python
from data_models import SCAVulnerabilityRecord

record = SCAVulnerabilityRecord(
    sha1="abc123def456",
    library_id="lib-001",
    cve_id="CVE-2021-44228",
    severity=5,
    component_name="log4j-core",
    component_version="2.14.1",
    app_id="app-001",
    app_name="MyApp",
)

print(f"Valid: {record.is_valid()}")  # True
print(f"CVE: {record.cve_id}")  # CVE-2021-44228
```

### Example 2: Create a SBOM Component

```python
from data_models import SBOMComponent

component = SBOMComponent(
    application_id="550e8400-e29b-41d4-a716-446655440000",
    app_name="MyApp",
    component_name="lodash",
    component_version="4.17.21",
    sha1="88d36f5051fb029ad5ef1119a73953f7add33fd9",
    bom_ref="pkg:npm/lodash@4.17.21",
    purl="pkg:npm/lodash@4.17.21",
)

print(f"Valid: {component.is_valid()}")  # True
print(f"PURL: {component.purl}")
```

### Example 3: Group and Aggregate Data

```python
from data_models import DataAggregator

findings = [
    {
        'sha1': 'abc123',
        'library_id': 'lib-001',
        'cve_id': 'CVE-2021-1234',
        'severity': 5,
        'component_name': 'log4j',
        'component_version': '2.14.1',
        'app_id': 'app-001',
    },
    {
        'sha1': 'abc123',
        'library_id': 'lib-001',
        'cve_id': 'CVE-2021-5678',
        'severity': 4,
        'component_name': 'log4j',
        'component_version': '2.14.1',
        'app_id': 'app-001',
    },
]

# Group by component
groups = DataAggregator.group_vulnerabilities_by_component(findings)
print(f"Groups: {len(groups)}")  # 1 component, 2 CVEs

# Analyze
for key, group in groups.items():
    print(f"Component: {group.component.component_name}")
    print(f"Vulnerabilities: {group.get_cve_count()}")
    print(f"Max Severity: {group.get_max_severity()}")
    print(f"CVEs: {group.get_cve_ids()}")

# Flatten back
records = DataAggregator.flatten_vulnerability_groups(groups)
print(f"Records: {len(records)}")  # 2 records
```

### Example 4: Validate Records

```python
from data_models import DataAggregator, SCAVulnerabilityRecord

records = [
    SCAVulnerabilityRecord(sha1="abc", app_id="app-1", component_name="comp1"),
    SCAVulnerabilityRecord(app_id="app-2", component_name="comp2"),  # Missing sha1/lib_id
]

valid, errors = DataAggregator.validate_records(records, min_match_keys=True)
print(f"Valid: {len(valid)}, Errors: {len(errors)}")
for error in errors:
    print(f"  - {error}")
```

---

## Testing

All dataclasses are tested by running the module directly:

```bash
python data_models.py
```

**Output:**
```
Testing SCAVulnerabilityRecord...
✓ Created: log4j-core@2.14.1
  CVE: CVE-2021-44228 (Severity: 5)
  Matching keys - SHA1: True, Library ID: True

Testing SBOMComponent...
✓ Created: lodash@4.17.21
  BOM-Ref: pkg:npm/lodash@4.17.21
  Matching keys - SHA1: True, BOM-Ref: True

Testing DataAggregator...
✓ Grouped 2 findings into 1 component(s)
  Component: log4j@2.14.1
  Vulnerabilities: 2
  CVEs: CVE-2021-1234, CVE-2021-5678
  Max Severity: 5

✅ All tests passed!
```

---

## Key Design Decisions

### 1. **Dataclasses vs. Regular Classes**
- ✅ Built-in JSON serialization with `asdict()`
- ✅ Automatic `__init__`, `__repr__`, `__eq__`
- ✅ Type hints with IDE support
- ✅ Minimal boilerplate

### 2. **Optional Fields**
- ✅ Not all fields required (real data has gaps)
- ✅ Explicit `Optional[T]` type hints
- ✅ Graceful handling of missing data

### 3. **Matching Key Strategy**
- Primary: `sha1` (most reliable)
- Secondary: `library_id` or `bom_ref` (Veracode-specific)
- Validated with `is_valid()` method

### 4. **Aggregation Pattern**
- Group by component key (sha1, library_id, name, version)
- Store multiple CVEs per component
- Flatten back to denormalized format for Excel

### 5. **Validation Approach**
- `__post_init__`: Normalize types (str → int/float)
- `is_valid()`: Check matching keys present
- Separate validation function for batch processing

---

## Integration with Next Phases

### Phase 3 (API Implementation)
Data models will be used to:
- Store API response data
- Provide type safety
- Enable JSON serialization

```python
# In api_fetcher.py Phase 3
def extract_sca_vulnerabilities(self, build_info):
    records = []
    for finding in build_info:
        record = SCAVulnerabilityRecord(
            sha1=finding.get('sha1'),
            library_id=finding.get('library_id'),
            # ... map all fields ...
        )
        records.append(record)
    return records
```

### Phase 4 (Export)
Data models will be exported to JSON/CSV:

```python
# In api_fetcher.py Phase 4
def save_vulnerability_data(self, records, filename):
    data = [r.to_dict() for r in records]
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
```

### Phase 6 (Matching)
Data models will integrate with VulnerabilityMatcher:

```python
# In vulnerability_matcher.py
from data_models import SCAVulnerabilityRecord, SBOMComponent

matcher = VulnerabilityMatcher()
matcher.load_sca_data([r.to_dict() for r in sca_records])
matcher.load_sbom_data([c.to_dict() for c in sbom_components])
```

---

## What's Ready for Phase 3

✅ Complete dataclass definitions  
✅ Type hints for all fields  
✅ Validation methods  
✅ Aggregation utilities  
✅ Testing and examples  
✅ Ready to integrate with API implementation

---

## Checklist: Phase 2 Complete

- ✅ SCAVulnerabilityRecord class (38 fields)
- ✅ SBOMComponent class (13 fields)
- ✅ VulnerabilityGroup helper class
- ✅ DataAggregator with 4 utility methods
- ✅ Type hints on all fields
- ✅ Validation methods
- ✅ Test cases pass
- ✅ Documentation complete
- ✅ Ready for Phase 3 implementation

---

## Next Step: Phase 3

**Phase 3: API Implementation (6 hours)**

Begin creating:
1. API collection methods in `api_fetcher.py`
2. Use data models to store API responses
3. Implement error handling
4. Add retry logic

**Files to create/modify:**
- Update `api_fetcher.py` with Phase 3 methods
- Create `tests/test_api_fetcher.py` for unit tests

---

## References

- [data_models.py](data_models.py) - Source code
- [API_FETCHER_UPDATE_PLAN.md](API_FETCHER_UPDATE_PLAN.md) - Phase 2 section
- [API_FIELD_MAPPING.md](API_FIELD_MAPPING.md) - Field reference

---

**Phase 2 Status**: ✅ COMPLETE  
**Next Phase**: Phase 3 - API Implementation (6 hours)  
**Total Plan Progress**: 2/7 phases complete (3 hours done, 18 hours remaining)
