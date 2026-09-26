# Project Plan: Update api_fetcher.py to Automate Complete Data Collection

## Executive Summary

Currently, the Excel file is manually populated with data from Veracode APIs. This plan details how to update `api_fetcher.py` to **automate the complete collection** of both vulnerability data and SBOM data, extracting all necessary columns for the matching workflow.

**Scope**: Update `api_fetcher.py` with complete implementation for both data sources  
**Effort**: 12-16 hours development + testing  
**Value**: Fully automated daily report generation pipeline  

---

## Current State

### What api_fetcher.py Currently Does
✓ Fetches applications  
✓ Attempts to fetch build info  
✓ Attempts to fetch SBOM  
✓ Some extraction logic present  

### What's Missing
✗ Complete vulnerability data extraction (detailedreport.do not used)  
✗ Proper build traversal (getting latest build)  
✗ Full column extraction for both data sources  
✗ Proper aggregation and formatting  
✗ Error handling and retry logic  
✗ Data validation  

---

## API Collection Flow

### Part 1: Vulnerability Data Flow

```
1. Get App List
   ↓
2. For Each App:
   a. Get App Info (app_id from list)
   b. Get Build List (app_id)
   c. Get Latest Build
   d. Get Build Info (app_id + build_id)
   e. Get Detailed Report (build_id)
   ↓
3. Extract Columns:
   - sha1 (Column AA in manual analysis)
   - library_id (Column AE in manual analysis)
   - cve_id, severity, cwe_id, cvss_score
   - component_name, version
   - build_id, build_version, app_id, app_name
   - And 30+ other columns for SCA Vuln Data sheet
```

### Part 2: SBOM Data Flow

```
1. Get Applications (v1 API)
   ↓
2. For Each App (app_guid):
   a. Get SBOM Data (CycloneDX format)
   ↓
3. Extract Columns:
   - sha1 (Column F in manual analysis)
   - bom_ref (Column E in manual analysis)
   - name, version, purl
   - component_type, file_path
   - cve_ids, cwe_ids
   - And other metadata
```

---

## Implementation Plan

### Phase 1: Research & Planning (2 hours)

#### Task 1.1: Document API Response Structures
- [ ] Test getapplist.do and document response format
- [ ] Test getappinfo.do response
- [ ] Test getbuildlist.do response
- [ ] Test getbuildinfo.do response
- [ ] Test detailedreport.do response
- [ ] Test Applications v1 API response
- [ ] Test SBOM v1 API response (CycloneDX)
- [ ] Save sample responses to `docs/api_samples/` for reference

**Deliverables**: 
- `docs/api_samples/getapplist_response.json`
- `docs/api_samples/detailedreport_response.json`
- `docs/api_samples/sbom_cyclonedx_response.json`

#### Task 1.2: Map API Fields to Excel Columns
Create mapping document showing:
- API field → Excel column name → Column letter → Data type

**Example:**
```
SCA Vuln Data (from detailedreport.do):
  api_field: cve_id → Excel: cve_id → AA → string
  api_field: severity → Excel: severity → B → integer
  api_field: sha1 → Excel: sha1 → AA → string (matching key)
  ...

SBOM Components (from SBOM API):
  api_field: name → Excel: component_name → D → string
  api_field: sha1 → Excel: sha1 → F → string (matching key)
  api_field: bom-ref → Excel: bom_ref → E → string (matching key)
  ...
```

**Deliverable**: `docs/API_FIELD_MAPPING.md`

---

### Phase 2: Data Structure Design (3 hours)

#### Task 2.1: Define Data Classes
Create Python dataclasses to match the Excel structure:

```python
@dataclass
class SCAVulnerabilityRecord:
    """Represents a vulnerability from detailedreport.do"""
    # Identifying columns
    sha1: str  # Column AA - Primary matching key
    library_id: str  # Column AE - Secondary matching key
    
    # Vulnerability info
    cve_id: str
    severity: int
    cwe_id: Optional[str]
    cvss_score: float
    vulnerability_affects_policy_compliance: bool
    
    # Component info
    component_name: str
    component_version: str
    component_id: str
    
    # Build info
    build_id: str
    build_version: str
    build_published_date: str
    
    # App info
    app_id: str
    app_guid: str
    app_name: str
    business_criticality: str
    
    # Scan info
    scantype: str  # SCA, Static, Dynamic, etc.
    first_found_date: str
    mitigated_date: Optional[str]
    
    # Additional metadata
    file_name: Optional[str]
    mitigation: Optional[str]
    description: Optional[str]
    cve_summary: Optional[str]
    blocklisted: bool
    new: bool

@dataclass
class SBOMComponent:
    """Represents a component from SBOM API"""
    # Identifying columns
    sha1: Optional[str]  # Column F - Primary matching key
    bom_ref: str  # Column E - Secondary matching key
    
    # Component info
    component_name: str
    component_type: str  # "library", "application", etc.
    component_version: str
    
    # Package info
    purl: Optional[str]
    vendor: Optional[str]
    
    # Hash info
    sha256: Optional[str]
    bytecode_hash: Optional[str]
    
    # Metadata
    file_path: Optional[str]
    cve_ids: Optional[str]  # Comma-separated
    cwe_ids: Optional[str]  # Comma-separated
    all_dependencies: Optional[str]
    
    # App info
    application_id: str
    app_name: str
    match_type: Optional[str]
```

**Deliverable**: `data_models.py` with complete class definitions

#### Task 2.2: Design Aggregation Strategy
Since detailedreport.do returns one vulnerability per row, multiple rows may represent the same component:

```python
# Strategy: Group vulnerabilities by component (sha1 + library_id)
def aggregate_vulnerabilities(findings: List[Dict]) -> List[SCAVulnerabilityRecord]:
    """
    Group vulnerabilities by component and aggregate.
    
    One component may have multiple vulnerabilities.
    Grouping key: (sha1, library_id, component_name, component_version)
    """
    
    grouped = {}
    for finding in findings:
        key = (finding.get('sha1'), finding.get('library_id'))
        if key not in grouped:
            grouped[key] = {
                'record': SCAVulnerabilityRecord(...),
                'vulnerabilities': []
            }
        grouped[key]['vulnerabilities'].append({
            'cve_id': finding.get('cve_id'),
            'severity': finding.get('severity'),
            'cwe_id': finding.get('cwe_id'),
            ...
        })
    
    return grouped
```

**Deliverable**: `data_aggregation.py` with aggregation logic

---

### Phase 3: API Implementation (6 hours)

#### Task 3.1: Implement Vulnerability Data Collection

**New Methods in VeracodeApiFetcher:**

```python
def get_build_list(self, app_id: str) -> List[Dict]:
    """Fetch build list for an application"""
    # GET /api/5.0/getbuildlist.do?app_id={app_id}
    pass

def get_latest_build(self, app_id: str) -> Optional[Dict]:
    """Get latest build from build list"""
    pass

def get_detailed_report(self, build_id: str) -> List[Dict]:
    """Fetch detailed vulnerability report from detailedreport.do"""
    # GET /api/5.0/detailedreport.do?build_id={build_id}
    # Returns: List of vulnerability findings
    pass

def fetch_all_vulnerability_data(self, app_limit: Optional[int] = None) -> List[SCAVulnerabilityRecord]:
    """
    Complete vulnerability data collection workflow:
    1. Get all applications
    2. For each app:
       a. Get build list
       b. Get latest build
       c. Get detailed report
       d. Extract findings
       e. Aggregate by component
    3. Return complete list
    """
    
    # Pseudo-code
    apps = self.get_all_applications()
    if app_limit:
        apps = apps[:app_limit]
    
    all_vulnerabilities = []
    
    for idx, app in enumerate(apps):
        app_id = app.get('id')
        app_guid = app.get('guid')
        app_name = app.get('name')
        
        logger.info(f"[{idx+1}/{len(apps)}] Processing app: {app_name}")
        
        try:
            # Get builds
            builds = self.get_build_list(app_id)
            latest_build = self.get_latest_build(builds)
            
            if not latest_build:
                logger.debug(f"  No builds found for {app_name}")
                continue
            
            build_id = latest_build.get('build_id')
            
            # Get detailed report
            findings = self.get_detailed_report(build_id)
            
            # Process findings
            for finding in findings:
                vuln_record = SCAVulnerabilityRecord(
                    sha1=finding.get('sha1'),
                    library_id=finding.get('library_id'),
                    cve_id=finding.get('cve_id'),
                    # ... map all fields
                    app_id=app_id,
                    app_guid=app_guid,
                    app_name=app_name,
                    build_id=build_id,
                )
                all_vulnerabilities.append(vuln_record)
            
            logger.info(f"  Extracted {len(findings)} findings")
        
        except Exception as e:
            logger.warning(f"  Failed to process {app_name}: {e}")
            continue
    
    return all_vulnerabilities
```

**Deliverable**: Updated `api_fetcher.py` with vulnerability methods

#### Task 3.2: Enhance SBOM Data Collection

```python
def fetch_all_sbom_data(self, app_limit: Optional[int] = None) -> List[SBOMComponent]:
    """
    Complete SBOM data collection workflow:
    1. Get all applications
    2. For each app:
       a. Get SBOM (CycloneDX format)
       b. Extract components
       c. Enrich with app metadata
    3. Return complete list
    """
    
    # Pseudo-code
    apps = self.get_all_applications()
    if app_limit:
        apps = apps[:app_limit]
    
    all_components = []
    
    for idx, app in enumerate(apps):
        app_guid = app.get('guid')
        app_id = app.get('id')
        app_name = app.get('name')
        
        logger.info(f"[{idx+1}/{len(apps)}] Processing SBOM for: {app_name}")
        
        try:
            sbom_data = self.get_sbom(app_guid)
            
            if not sbom_data:
                logger.debug(f"  No SBOM found for {app_name}")
                continue
            
            # Extract components from CycloneDX format
            components = sbom_data.get('bom', {}).get('components', [])
            
            for comp in components:
                sbom_component = SBOMComponent(
                    sha1=self._extract_hash(comp, 'SHA-1'),
                    sha256=self._extract_hash(comp, 'SHA-256'),
                    bom_ref=comp.get('bom-ref'),
                    component_name=comp.get('name'),
                    component_type=comp.get('type', 'library'),
                    component_version=comp.get('version'),
                    purl=comp.get('purl'),
                    # ... map all fields
                    application_id=app_id,
                    app_name=app_name,
                )
                all_components.append(sbom_component)
            
            logger.info(f"  Extracted {len(components)} components")
        
        except Exception as e:
            logger.warning(f"  Failed to process SBOM for {app_name}: {e}")
            continue
    
    return all_components

def _extract_hash(self, component: Dict, hash_type: str) -> Optional[str]:
    """Extract specific hash type from CycloneDX component"""
    for hash_item in component.get('hashes', []):
        if hash_item.get('alg') == hash_type:
            return hash_item.get('content')
    return None
```

**Deliverable**: Enhanced SBOM methods in `api_fetcher.py`

---

### Phase 4: Data Export (2 hours)

#### Task 4.1: Export to JSON

```python
def save_vulnerability_data(self, vulnerabilities: List[SCAVulnerabilityRecord], filename: str):
    """Save vulnerability data to JSON"""
    data = [asdict(v) for v in vulnerabilities]
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    logger.info(f"Saved {len(vulnerabilities)} vulnerability records to {filename}")

def save_sbom_data(self, components: List[SBOMComponent], filename: str):
    """Save SBOM data to JSON"""
    data = [asdict(c) for c in components]
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    logger.info(f"Saved {len(components)} SBOM components to {filename}")
```

#### Task 4.2: Export to CSV

```python
def export_vulnerability_csv(self, vulnerabilities: List[SCAVulnerabilityRecord], filename: str):
    """Export vulnerability data to CSV for Excel import"""
    import csv
    
    if not vulnerabilities:
        logger.warning("No vulnerabilities to export")
        return
    
    with open(filename, 'w', newline='') as f:
        fieldnames = [
            'cve_id', 'severity', 'cwe_id', 'cvss_score',
            'component_name', 'component_version',
            'sha1', 'library_id',
            'app_name', 'app_id',
            'build_version', 'first_found_date',
            'scantype', 'file_name',
            # ... include all fields
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for vuln in vulnerabilities:
            writer.writerow(asdict(vuln))
    
    logger.info(f"Exported {len(vulnerabilities)} records to {filename}")

def export_sbom_csv(self, components: List[SBOMComponent], filename: str):
    """Export SBOM data to CSV for Excel import"""
    # Similar structure
    pass
```

**Deliverable**: Export methods in `api_fetcher.py`

---

### Phase 5: Error Handling & Resilience (2 hours)

#### Task 5.1: Implement Retry Logic

```python
def _retry_api_call(self, func, max_retries: int = 3, backoff_factor: float = 1.0):
    """Retry API calls with exponential backoff"""
    import time
    
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            
            wait_time = backoff_factor ** attempt
            logger.warning(f"API call failed, retrying in {wait_time}s: {e}")
            time.sleep(wait_time)
```

#### Task 5.2: Add Validation

```python
def validate_vulnerability_record(self, record: SCAVulnerabilityRecord) -> bool:
    """Validate required fields"""
    required = ['sha1', 'library_id', 'app_id', 'build_id']
    
    for field in required:
        if not getattr(record, field, None):
            logger.debug(f"Invalid record missing {field}")
            return False
    
    return True

def validate_sbom_component(self, component: SBOMComponent) -> bool:
    """Validate SBOM component"""
    required = ['component_name', 'application_id', 'bom_ref']
    
    for field in required:
        if not getattr(component, field, None):
            logger.debug(f"Invalid SBOM missing {field}")
            return False
    
    return True
```

**Deliverable**: Error handling and validation logic

---

### Phase 6: Integration & Testing (3 hours)

#### Task 6.1: Update main() Function

```python
def main():
    """Main entry point - complete automated workflow"""
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['vuln', 'sbom', 'all'], default='all',
                        help='What data to fetch')
    parser.add_argument('--limit', type=int, help='Limit number of apps')
    parser.add_argument('--output-dir', default='.', help='Output directory')
    parser.add_argument('--export-format', choices=['json', 'csv', 'both'], default='json')
    
    args = parser.parse_args()
    
    fetcher = VeracodeApiFetcher()
    
    # Fetch data
    vulnerabilities = []
    sbom_components = []
    
    if args.mode in ['vuln', 'all']:
        logger.info("Fetching vulnerability data...")
        vulnerabilities = fetcher.fetch_all_vulnerability_data(app_limit=args.limit)
        logger.info(f"✓ Fetched {len(vulnerabilities)} vulnerability records")
    
    if args.mode in ['sbom', 'all']:
        logger.info("Fetching SBOM data...")
        sbom_components = fetcher.fetch_all_sbom_data(app_limit=args.limit)
        logger.info(f"✓ Fetched {len(sbom_components)} SBOM components")
    
    # Export data
    if vulnerabilities:
        if args.export_format in ['json', 'both']:
            fetcher.save_vulnerability_data(
                vulnerabilities,
                f"{args.output_dir}/all_sca_components.json"
            )
        if args.export_format in ['csv', 'both']:
            fetcher.export_vulnerability_csv(
                vulnerabilities,
                f"{args.output_dir}/sca_vulnerabilities.csv"
            )
    
    if sbom_components:
        if args.export_format in ['json', 'both']:
            fetcher.save_sbom_data(
                sbom_components,
                f"{args.output_dir}/all_sbom_components.json"
            )
        if args.export_format in ['csv', 'both']:
            fetcher.export_sbom_csv(
                sbom_components,
                f"{args.output_dir}/sbom_components.csv"
            )
    
    # Generate matching report
    from vulnerability_matcher import VulnerabilityMatcher
    from generate_xlsx_report import ExcelReportGenerator
    
    logger.info("Generating matching report...")
    matcher = VulnerabilityMatcher()
    
    # Convert to matcher format
    matcher.load_sbom_data([asdict(c) for c in sbom_components])
    matcher.load_sca_data([asdict(v) for v in vulnerabilities])
    matcher.match_all()
    matcher.print_summary()
    
    # Generate Excel
    generator = ExcelReportGenerator(matcher=matcher)
    output_file = generator.generate(f"{args.output_dir}/SBOM_Vuln_Analysis_Automated.xlsx")
    logger.info(f"✓ Report generated: {output_file}")
```

#### Task 6.2: Unit Tests

Create `tests/test_api_fetcher.py`:

```python
import pytest
from api_fetcher import VeracodeApiFetcher
from data_models import SCAVulnerabilityRecord, SBOMComponent

def test_vulnerability_record_validation():
    """Test validation of vulnerability records"""
    # Test valid record
    valid = SCAVulnerabilityRecord(
        sha1="abc123",
        library_id="lib-001",
        cve_id="CVE-2021-1234",
        severity=5,
        # ...
    )
    assert fetcher.validate_vulnerability_record(valid)
    
    # Test invalid record (missing required field)
    invalid = SCAVulnerabilityRecord(sha1=None, ...)
    assert not fetcher.validate_vulnerability_record(invalid)

def test_sbom_component_extraction():
    """Test SBOM component extraction from CycloneDX"""
    # Test with sample CycloneDX response
    pass

def test_hash_extraction():
    """Test hash extraction from multiple formats"""
    pass
```

**Deliverable**: Test suite with >80% coverage

---

### Phase 7: Documentation (2 hours)

#### Task 7.1: Update README with new API fetcher features

```markdown
### Complete Data Collection

The enhanced API fetcher now provides complete automated collection:

**Collect vulnerability data:**
```bash
python api_fetcher.py --mode vuln
```

**Collect SBOM data:**
```bash
python api_fetcher.py --mode sbom
```

**Collect both and generate report:**
```bash
python api_fetcher.py --mode all --export-format both
```

**Output:**
- `all_sca_components.json` - All vulnerabilities
- `all_sbom_components.json` - All components
- `SBOM_Vuln_Analysis_Automated.xlsx` - Matching report
```

#### Task 7.2: Create API Reference Doc

Document all new methods with examples.

**Deliverable**: Updated `README.md` and `docs/API_REFERENCE.md`

---

## Detailed Implementation Steps

### Step 1: Set Up Data Models

```bash
# Create new file
touch data_models.py

# Add dataclasses for:
# - SCAVulnerabilityRecord
# - SBOMComponent
```

### Step 2: Update api_fetcher.py

Add methods in this order:
1. `get_build_list(app_id)` - Fetch build list
2. `get_latest_build(builds)` - Select latest
3. `get_detailed_report(build_id)` - Fetch findings
4. `fetch_all_vulnerability_data()` - Main workflow
5. `fetch_all_sbom_data()` - Enhanced SBOM
6. Export methods (JSON, CSV)
7. Validation methods
8. Retry logic

### Step 3: Test Each Method

```bash
# Test individual fetcher
python -c "
from api_fetcher import VeracodeApiFetcher
fetcher = VeracodeApiFetcher()

# Test build list
builds = fetcher.get_build_list('app_id')
print(f'Got {len(builds)} builds')
"
```

### Step 4: Test Complete Workflow

```bash
python api_fetcher.py --mode vuln --limit 3
python api_fetcher.py --mode sbom --limit 3
python api_fetcher.py --mode all --limit 3
```

### Step 5: Verify Output

```bash
# Check generated files
ls -lh all_*.json
wc -l all_*.json

# Check data quality
python -c "
import json
with open('all_sca_components.json') as f:
    data = json.load(f)
    print(f'Vulnerabilities: {len(data)}')
    if data:
        print(f'Sample: {data[0]}')
"
```

---

## Testing Strategy

### Unit Tests (Phase 6)
- [ ] Test data model validation
- [ ] Test hash extraction
- [ ] Test API response parsing
- [ ] Test aggregation logic

### Integration Tests
- [ ] Test with real Veracode APIs (limit to 1-2 apps)
- [ ] Verify JSON structure matches expectations
- [ ] Verify CSV export format
- [ ] Test error handling with invalid credentials

### Data Quality Tests
- [ ] Verify no null values in required fields
- [ ] Verify sha1/library_id are populated
- [ ] Verify component names and versions
- [ ] Compare with manual Excel for sample apps

---

## Success Criteria

After implementation, verify:

- ✅ `python api_fetcher.py --mode all` completes without errors
- ✅ `all_sca_components.json` contains 10K+ vulnerability records
- ✅ `all_sbom_components.json` contains 50K+ components
- ✅ Both files have proper structure with all required columns
- ✅ `generate_xlsx_report.py` successfully reads the JSON files
- ✅ Generated Excel shows >20% match rate (vs. current 4.7%)
- ✅ All 5 sheets present in Excel with proper formatting
- ✅ Statistics sheet shows breakdown by matching strategy

---

## Rollout Plan

### Week 1: Development
- [ ] Complete all tasks in Phases 1-5
- [ ] Write unit tests
- [ ] Test with 3-5 sample apps

### Week 2: Validation
- [ ] Full integration testing with production data
- [ ] Verify match rate improvement
- [ ] Performance optimization if needed
- [ ] Final review and documentation

### Week 3: Deployment
- [ ] Merge to main branch
- [ ] Deploy to production environment
- [ ] Set up scheduled runs (daily at 2 AM)
- [ ] Monitor for issues

---

## Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|-----------|
| API rate limiting | High | Implement backoff logic, limit concurrent requests |
| Incomplete data | Medium | Add validation, handle missing fields gracefully |
| Large response sizes | Medium | Stream processing, incremental saves |
| Breaking API changes | Low | Monitor API docs, maintain version flexibility |

---

## Deliverables Summary

| Phase | Deliverable | File |
|-------|-------------|------|
| 1 | API documentation | `docs/API_FIELD_MAPPING.md` |
| 2 | Data models | `data_models.py` |
| 3 | API methods | Updated `api_fetcher.py` |
| 4 | Export methods | Updated `api_fetcher.py` |
| 5 | Error handling | Updated `api_fetcher.py` |
| 6 | Tests & integration | `tests/test_api_fetcher.py` |
| 7 | Documentation | Updated `README.md` |

---

## Time Estimate

| Phase | Tasks | Hours |
|-------|-------|-------|
| 1 | Research & Planning | 2 |
| 2 | Data Structures | 3 |
| 3 | API Implementation | 6 |
| 4 | Data Export | 2 |
| 5 | Error Handling | 2 |
| 6 | Testing | 3 |
| 7 | Documentation | 2 |
| **Total** | | **20** |

---

## Next Steps

1. Review this plan with stakeholders
2. Confirm API endpoints and field mappings
3. Start Phase 1 (Research & Planning)
4. Set up weekly progress reviews
5. Deploy to production after Phase 2 validation

---

## References

- [Excel Analysis Document](XLSX_GENERATION_ANALYSIS.md)
- [Current api_fetcher.py](api_fetcher.py)
- [Vulnerability Matcher](vulnerability_matcher.py)
- [Generate Excel Report](generate_xlsx_report.py)
