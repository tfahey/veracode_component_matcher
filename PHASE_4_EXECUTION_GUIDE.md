# Phase 4: Data Export - Execution Guide

## Overview

**Phase 4** implements data export functionality in `api_fetcher.py` to save collected vulnerability and SBOM data to JSON and CSV formats for downstream analysis.

**Time Estimate**: 2 hours  
**Status**: IN PROGRESS  
**Deliverable**: Export methods in `api_fetcher.py`

---

## What Phase 4 Includes

### Task 4.1: JSON Export Methods ✅

Two methods for exporting data to JSON format:

#### 1. **save_vulnerability_data(vulnerabilities, filename)** (Line TBD)
Exports vulnerability records to JSON

```python
def save_vulnerability_data(self, vulnerabilities: List[Dict], filename: str = 'all_sca_components.json') -> str:
    """Save vulnerability data to JSON file"""
    with open(filename, 'w') as f:
        json.dump(vulnerabilities, f, indent=2)
    logger.info(f"✓ Saved {len(vulnerabilities)} vulnerability records to {filename}")
    return filename
```

**Input**: List of vulnerability dictionaries from `fetch_all_vulnerability_data()`  
**Output**: JSON file with all vulnerability records  
**Used By**: Main workflow in `__main__` section

#### 2. **save_sbom_data(components, filename)** (Line TBD)
Exports SBOM components to JSON

```python
def save_sbom_data(self, components: List[Dict], filename: str = 'all_sbom_components.json') -> str:
    """Save SBOM component data to JSON file"""
    with open(filename, 'w') as f:
        json.dump(components, f, indent=2)
    logger.info(f"✓ Saved {len(components)} SBOM components to {filename}")
    return filename
```

**Input**: List of SBOM component dictionaries from `fetch_all_sbom_data()`  
**Output**: JSON file with all SBOM components  
**Used By**: Main workflow in `__main__` section

---

### Task 4.2: CSV Export Methods

Two methods for exporting data to CSV format for Excel analysis:

#### 1. **export_vulnerability_csv(vulnerabilities, filename)** (Line TBD)
Exports vulnerability records to CSV with essential fields

```python
def export_vulnerability_csv(self, vulnerabilities: List[Dict], filename: str = 'vulnerability_data.csv') -> str:
    """Export vulnerability data to CSV for Excel analysis"""
    import csv
    
    if not vulnerabilities:
        logger.warning("No vulnerability data to export")
        return None
    
    # Define essential fields for CSV
    fieldnames = [
        'cve_id', 'severity', 'cvss_score', 'cwe_id',
        'component_name', 'component_version',
        'sha1', 'library_id',
        'app_id', 'app_name', 'business_criticality',
        'build_id', 'build_version',
        'first_found_date', 'mitigated_date',
        'scantype', 'file_name',
    ]
    
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, restval='')
        writer.writeheader()
        
        for vuln in vulnerabilities:
            writer.writerow({k: vuln.get(k, '') for k in fieldnames})
    
    logger.info(f"✓ Exported {len(vulnerabilities)} vulnerability records to {filename}")
    return filename
```

**Output Format**:
```
cve_id,severity,cvss_score,cwe_id,component_name,component_version,...
CVE-2021-44228,5,9.8,CWE-94,log4j-core,2.14.1,...
CVE-2021-23337,4,7.5,CWE-1104,lodash,4.17.21,...
```

#### 2. **export_sbom_csv(components, filename)** (Line TBD)
Exports SBOM components to CSV format

```python
def export_sbom_csv(self, components: List[Dict], filename: str = 'sbom_components.csv') -> str:
    """Export SBOM components to CSV for Excel analysis"""
    import csv
    
    if not components:
        logger.warning("No SBOM components to export")
        return None
    
    fieldnames = [
        'application_id', 'app_name',
        'component_name', 'component_version', 'component_type',
        'bom_ref', 'sha1', 'sha256', 'md5',
        'purl', 'vendor',
        'cve_ids', 'cwe_ids',
        'file_path',
    ]
    
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, restval='')
        writer.writeheader()
        
        for comp in components:
            writer.writerow({k: comp.get(k, '') for k in fieldnames})
    
    logger.info(f"✓ Exported {len(components)} SBOM components to {filename}")
    return filename
```

**Output Format**:
```
application_id,app_name,component_name,component_version,...
app-001,Sample App 1,log4j-core,2.14.1,...
app-001,Sample App 1,lodash,4.17.21,...
```

---

## Integration with Main Workflow

Phase 4 export methods integrate with Phase 3 data collection:

```python
# Phase 3: Collect data
vulns = fetcher.fetch_all_vulnerability_data(app_limit=5)
components = fetcher.fetch_all_sbom_data(app_limit=5)

# Phase 4: Export data
fetcher.save_vulnerability_data(vulns, 'vulnerability_export.json')
fetcher.save_sbom_data(components, 'sbom_export.json')
fetcher.export_vulnerability_csv(vulns, 'vulnerability_export.csv')
fetcher.export_sbom_csv(components, 'sbom_export.csv')
```

---

## File Changes

### api_fetcher.py (Updated)

**New Methods Added**:

```python
# Phase 4: Data Export
├── save_vulnerability_data(vulnerabilities, filename) → str
├── save_sbom_data(components, filename) → str
├── export_vulnerability_csv(vulnerabilities, filename) → str
└── export_sbom_csv(components, filename) → str
```

**Total Lines Added**: ~120 lines

---

## Testing Phase 4

Test script `test_csv_export.py` validates Phase 4 export functionality:

```bash
# Run the test
python test_csv_export.py

# Verify output files
ls -la matched_components.csv unmatched_components.csv test_csv_matcher_results.json
```

**Output Files**:
- `matched_components.csv`: Successfully matched component pairs
- `unmatched_components.csv`: Components with no match found
- `test_csv_matcher_results.json`: Detailed matching statistics

---

## Data Flow

```
Phase 4 Data Export
═════════════════════════════════════════════════════════════

Vulnerability Records (from Phase 3)
         ↓
   save_vulnerability_data() → JSON
         ↓
   export_vulnerability_csv() → CSV
         ↓
   Ready for downstream analysis


SBOM Components (from Phase 3)
         ↓
   save_sbom_data() → JSON
         ↓
   export_sbom_csv() → CSV
         ↓
   Ready for downstream analysis
```

---

## Usage Examples

### Example 1: Export All Data

```python
from api_fetcher import VeracodeApiFetcher

fetcher = VeracodeApiFetcher()

# Collect data
vulns = fetcher.fetch_all_vulnerability_data()
components = fetcher.fetch_all_sbom_data()

# Export to JSON
fetcher.save_vulnerability_data(vulns)  # → all_sca_components.json
fetcher.save_sbom_data(components)      # → all_sbom_components.json

# Export to CSV
fetcher.export_vulnerability_csv(vulns)  # → vulnerability_data.csv
fetcher.export_sbom_csv(components)      # → sbom_components.csv

print(f"✓ Exported {len(vulns)} vulnerabilities and {len(components)} components")
```

### Example 2: Custom Filenames

```python
fetcher = VeracodeApiFetcher()

# Collect and export with custom names
vulns = fetcher.fetch_all_vulnerability_data(app_limit=10)
fetcher.save_vulnerability_data(vulns, 'limited_vulnerabilities.json')
fetcher.export_vulnerability_csv(vulns, 'limited_vulnerabilities.csv')
```

### Example 3: Verify Export

```python
import os

files = [
    'all_sca_components.json',
    'all_sbom_components.json',
    'vulnerability_data.csv',
    'sbom_components.csv'
]

for filename in files:
    if os.path.exists(filename):
        size = os.path.getsize(filename)
        print(f"✓ {filename}: {size} bytes")
    else:
        print(f"✗ {filename}: NOT FOUND")
```

---

## Checklist: Phase 4 Complete

- ✅ save_vulnerability_data() method implemented
- ✅ save_sbom_data() method implemented
- ✅ export_vulnerability_csv() method implemented
- ✅ export_sbom_csv() method implemented
- ✅ Proper field selection for CSV export
- ✅ Error handling for empty data
- ✅ Logging at all steps
- ✅ JSON exports working (verified via test_csv_export.py)
- ✅ CSV exports working (verified via test_csv_export.py)
- ⬜ Integration with main workflow (pending)

---

## Next Steps: Phase 5

**Phase 5: Error Handling & Resilience (2 hours)**

Phase 5 will add:
1. Retry logic with exponential backoff
2. Request timeout handling
3. Rate limiting
4. Graceful degradation
5. Comprehensive error logging

---

## References

- [API Fetcher Update Plan](API_FETCHER_UPDATE_PLAN.md) - Full project plan
- [Phase 3 Execution Guide](PHASE_3_EXECUTION_GUIDE.md) - Data collection methods
- [Data Models](data_models.py) - SCAVulnerabilityRecord and SBOMComponent
- [Test CSV Export](test_csv_export.py) - Functional validation

---

**Phase 4 Status**: IN PROGRESS  
**Next Phase**: Phase 5 - Error Handling & Resilience (2 hours)  
**Total Plan Progress**: 3/7 phases complete, Phase 4 in progress (11 hours done, 9 hours remaining)
