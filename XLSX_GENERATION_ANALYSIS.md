# SBOM Vuln Analysis Excel Generation Analysis

## Current Excel File Structure

### File: `SBOM Vuln Analysis _2.xlsx`

The Excel workbook contains **4 sheets** with **131,503 total data rows**:

| Sheet Name | Rows | Purpose | Current Status |
|------------|------|---------|-----------------|
| **SBOM Components** | 95,661 | SBOM data with component details and CVE mappings | Populated manually |
| **SCA Vuln Data** | 14,794 | Vulnerability data from Veracode SCA scans | Populated manually |
| **Using Hash** | 9,245 | SHA1-based component matching with VLOOKUP formulas | 448 mappings (4.8%) |
| **Using Library ID** | 11,301 | Library ID-based matching with VLOOKUP formulas | 508 mappings (4.5%) |

---

## Sheet Details

### 1. **SBOM Components** (95,661 rows)
**Columns (13):**
- `application_id` - Application GUID
- `app_name` - Application name  
- `component_type` - "library" or other type
- `component_name` - Component name (often JAR filename)
- `bom_ref` - Unique SBOM reference ID
- `sha1` - SHA1 hash
- `sha256` - SHA256 hash
- `match_type` - Matching method used
- `bytecode_hash` - Bytecode hash value
- `file_path` - File path in application
- `cve_ids` - Associated CVE IDs
- `cwe_ids` - Associated CWE IDs
- `all_dependencies` - Dependency information

**Current Data Source:** Manual population from Veracode SBOM API

---

### 2. **SCA Vuln Data** (14,794 rows)
**Columns (38):**
- `cve_id`, `severity`, `cwe_id` - Vulnerability identifiers
- `component_id`, `library_id`, `sha1`, `library` - Component identifiers
- `version`, `vendor` - Component version and vendor
- `cvss_score`, `max_cvss_score` - CVSS scoring
- `vulnerability_affects_policy_compliance` - Compliance flag
- `build_id`, `build_version`, `app_id`, `app_name` - Build and app identifiers
- `scantype`, `static_version`, `dynamic_version` - Scan details
- And many more vulnerability metadata columns...

**Current Data Source:** Manual population from Veracode Build Info API

---

### 3. **Using Hash** (9,245 rows)
**Columns (8):**
- `sbom_sha1` - SHA1 from SBOM
- `SCA_sha1` - SHA1 from SCA data
- `Mapping` - Excel VLOOKUP formula: `=VLOOKUP(B2,A:A,1,0)`
- `Component Name` - VLOOKUP to retrieve component name

**Current Status:** 
- **Manual hash matching** - Someone manually created rows matching SBOM SHA1s with SCA SHA1s
- **Only 448 rows (4.8%) have successful mappings** out of 9,245 potential matches
- **Formula-based approach** - Uses Excel VLOOKUP instead of programmatic matching

**Issues:**
- ❌ Very low match rate suggests most SHA1s don't align
- ❌ Labor-intensive manual matching process
- ❌ Error-prone: requires human identification of matches
- ❌ Not reproducible/automatable

---

### 4. **Using Library ID** (11,301 rows)  
**Columns (8):**
- `bom_ref` - SBOM reference ID
- `SCA_library_id` - Veracode library ID from SCA
- `Mapping` - Excel VLOOKUP formula
- `Component Name` - VLOOKUP lookup

**Current Status:**
- **Manual library ID matching** - Same manual approach as hash sheet
- **Only 508 rows (4.5%) have successful mappings** out of 11,301 potential matches
- **Formula-based approach** - Relies on Excel VLOOKUP

**Issues:**
- ❌ Similar low match rate as hash sheet
- ❌ Dependent on availability of library IDs in both sources
- ❌ Not scalable or reproducible

---

## Comparison: Current Scripts vs. Excel Output

### What the Scripts Do:
```python
# api_fetcher.py
- Fetches ALL applications from Veracode
- Extracts SCA components from getbuildinfo.do
- Extracts SBOM components from /srcclr/sbom/v1/
- Exports to JSON files (all_sca_components.json, all_sbom_components.json)

# vulnerability_matcher.py
- Loads JSON data
- Applies 5 matching strategies:
  1. SHA1 matching
  2. PURL matching
  3. Composite key (vendor/name/version)
  4. Library ID matching
  5. Fuzzy name matching
- Exports to CSV (matched_components.csv, unmatched_components.csv)
```

### What the Excel File Contains:
```
✓ Raw SBOM and SCA data (95K + 14K rows)
✓ Manual SHA1 matching attempts (448 mappings)
✓ Manual Library ID matching attempts (508 mappings)
✗ No PURL-based matching
✗ No composite key matching
✗ No fuzzy name matching
✗ No version-aware matching
```

---

## Key Findings

### 1. **Massive Gap Between Potential and Actual Matches**
- SBOM Components: 95,661
- SCA Components: 14,794
- Hash-based matches: 448 (only 3% of SCA components matched)
- Library ID matches: 508 (only 3.4% of SCA components matched)

**Root Cause:** The Excel file only attempts 2 matching strategies (SHA1 and Library ID), whereas the scripts support 5 strategies including more reliable methods like PURL and composite key matching.

### 2. **Manual vs. Automated Approach**
- Excel: Manual identification of matching pairs + VLOOKUP
- Scripts: Programmatic matching with multiple fallback strategies

**Result:** Scripts would produce substantially higher match rates

### 3. **Missing Matching Strategies**
Excel file lacks:
- ✗ PURL (Package URL) matching - High confidence, widely used
- ✗ Composite key (vendor/name/version) - Medium confidence, catches version variations
- ✗ Fuzzy name matching - Fallback for edge cases

---

## Recommendations

### **Option 1: Generate Excel from Python Scripts (Recommended)**

Create a new Python script `generate_xlsx_report.py` that:

```python
# Pseudo-code structure
from api_fetcher import VeracodeApiFetcher
from vulnerability_matcher import VulnerabilityMatcher
import openpyxl

# Step 1: Fetch data
fetcher = VeracodeApiFetcher()
all_sca = fetcher.fetch_all_sca_components()
all_sbom = fetcher.fetch_all_sbom_components()

# Step 2: Match components
matcher = VulnerabilityMatcher()
matcher.load_sbom_data(all_sbom)
matcher.load_sca_data(all_sca)
matched, unmatched = matcher.match_all()

# Step 3: Generate Excel workbook
wb = openpyxl.Workbook()

# Sheet 1: SBOM Components
ws_sbom = wb.active
ws_sbom.title = "SBOM Components"
# Export all SBOM data with match results

# Sheet 2: SCA Vuln Data
ws_sca = wb.create_sheet("SCA Vuln Data")
# Export all SCA data

# Sheet 3: Matched Results
ws_matched = wb.create_sheet("Matched Components")
# Show successful matches with strategy used and confidence

# Sheet 4: Unmatched Analysis
ws_unmatched = wb.create_sheet("Unmatched Components")
# Show gaps and analysis

wb.save('SBOM_Vuln_Analysis_AUTOMATED.xlsx')
```

**Advantages:**
- ✅ Automated/reproducible
- ✅ Uses all 5 matching strategies (vs. 2 in current Excel)
- ✅ Higher match rates expected
- ✅ Eliminates manual work
- ✅ Can be scheduled/versioned
- ✅ Comprehensive reporting

---

### **Option 2: Enhance Current Excel-Based Approach**

If continuing with Excel manual approach:

1. **Add PURL Matching Column**
   - Extract PURL from SBOM components
   - Use VLOOKUP to find matching PURLs in SCA data

2. **Add Version-Aware Composite Key**
   - Create composite key: `vendor/name/version`
   - Add column for matching on this key

3. **Add Fuzzy Matching**
   - Use `FUZZY()` function or plugin
   - Fall back when exact matches fail

4. **Improve Documentation**
   - Add "Matching Strategy" column showing which method worked
   - Add "Confidence Score" (1.0 for exact, 0.85+ for fuzzy)

**Limitations:**
- ❌ Still manual/labor-intensive
- ❌ Excel has limitations on fuzzy matching
- ❌ Not reproducible or version-controlled
- ❌ Difficult to update when data changes

---

### **Option 3: Hybrid Approach**

1. Use Python scripts to generate core data (Options 1 + 2)
2. Export to Excel with all matches pre-calculated
3. Add Excel-based analysis/formatting layer
4. Maintain matching logic in Python, visualization in Excel

**Best of Both Worlds:**
- ✅ Python for reliable matching logic
- ✅ Excel for reporting/visualization
- ✅ Reproducible and version-controlled

---

## Implementation Steps (Recommended: Option 1 + 3)

### Step 1: Create `generate_xlsx_report.py`
```python
#!/usr/bin/env python3
"""Generate comprehensive SBOM/SCA analysis Excel report"""

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from api_fetcher import VeracodeApiFetcher
from vulnerability_matcher import VulnerabilityMatcher

def generate_report(output_file='SBOM_Vuln_Analysis_Generated.xlsx'):
    """Generate Excel report with all matching strategies applied"""
    
    # Fetch and match data
    fetcher = VeracodeApiFetcher()
    matcher = VulnerabilityMatcher()
    
    # ... implementation ...
    
    # Create workbook with 4-5 sheets
    # Sheet 1: Raw SBOM Data
    # Sheet 2: Raw SCA Data  
    # Sheet 3: Matched Components (with strategy, confidence, statistics)
    # Sheet 4: Unmatched Components (with gap analysis)
    # Sheet 5: Summary Statistics
    
    wb.save(output_file)

if __name__ == '__main__':
    generate_report()
```

### Step 2: Enhance VulnerabilityMatcher
- Add method `export_to_xlsx()` for direct Excel export
- Include formatting and conditional highlighting

### Step 3: Add Matching Metrics
- Track which strategy matched each component
- Calculate confidence scores
- Generate gap analysis report

### Step 4: Create Automated Pipeline
```bash
# Run monthly/weekly
python3 generate_xlsx_report.py --output "SBOM_Vuln_Analysis_$(date +%Y%m%d).xlsx"
```

---

## Expected Outcomes

### Current Excel File:
- Total Matches: ~950 (across both methods)
- Match Rate: ~3-4% of components
- Coverage: Very incomplete

### With Recommended Approach:
- Total Matches: Expected **30-50%+** (using 5 strategies)
- Coverage: Significantly improved gap closure
- Traceability: Full audit trail of which strategy matched each component
- Reproducibility: Same results every run
- Maintainability: Version-controlled logic

---

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `generate_xlsx_report.py` | **Create** | Main script to generate Excel report |
| `vulnerability_matcher.py` | **Enhance** | Add `export_to_xlsx()` method |
| `api_fetcher.py` | **Enhance** | Add data caching for offline use |
| `requirements.txt` | **Update** | Add `openpyxl` dependency |
| `.gitignore` | **Update** | Exclude generated XLSX files |

---

## Summary

**Current State:** Manual Excel-based matching with ~3-4% success rate using only SHA1 and Library ID strategies.

**Recommendation:** Automate Excel generation using Python scripts that leverage all 5 matching strategies, expected to achieve 30-50%+ match rates with full traceability and reproducibility.

**Effort:** 4-6 hours development, with ongoing maintenance minimal (automated runs).

**Value:** Significant improvement in component visibility, automated gap analysis, reproducible reporting pipeline.
