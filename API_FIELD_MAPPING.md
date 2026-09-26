# API Field Mapping: Veracode APIs ↔ Excel Columns

## Overview

This document maps fields from Veracode API responses to the Excel column structure in `SBOM Vuln Analysis _2.xlsx`.

---

## Part 1: Vulnerability Data Mapping

### API Endpoints Used

1. **getapplist.do** - Get all applications
2. **getappinfo.do** - Get detailed app information
3. **getbuildlist.do** - Get list of builds for an app
4. **getbuildinfo.do** - Get information about a specific build
5. **detailedreport.do** - Get detailed vulnerability findings

### SCA Vuln Data Sheet: API Field → Excel Column

| Excel Column | Column # | API Endpoint | API Field | Data Type | Required? | Notes |
|---|---|---|---|---|---|---|
| cve_id | A | detailedreport.do | cwe.id or cve_id | string | ✓ | Primary vulnerability ID |
| severity | B | detailedreport.do | severity | integer (1-5) | ✓ | Vulnerability severity level |
| cwe_id | C | detailedreport.do | cwe.id | string | | CWE identifier |
| first_found_date | D | detailedreport.do | first_found_date | datetime | | ISO 8601 format |
| mitigated_date | E | detailedreport.do | mitigated_date | datetime | | When vulnerability was closed |
| mitigation | F | detailedreport.do | mitigation | string | | Mitigation action text |
| mitigation_type | G | detailedreport.do | mitigation_type | string | | Type of mitigation |
| severity_desc | H | detailedreport.do | severity_desc | string | | Human-readable severity |
| file_name | I | detailedreport.do | file_name | string | | Affected file name |
| scantype | J | getbuildinfo.do | scan_type | string | | "SCA", "Static", "Dynamic", etc. |
| cvss_score | K | detailedreport.do | cvss_score | float | | CVSS v3 score |
| vulnerability_affects_policy_compliance | L | detailedreport.do | affects_policy_compliance | boolean | | Policy compliance impact |
| build_id | M | detailedreport.do | build_id | string | ✓ | Build identifier |
| build_published_date | N | getbuildinfo.do | published_date | datetime | | When build was published |
| build_version | O | getbuildinfo.do | version | string | | Build version number |
| app_id | P | getapplist.do | id or legacy_id | string | ✓ | Application ID |
| app_name | Q | getapplist.do | name | string | ✓ | Application name |
| business_criticality | R | getappinfo.do | business_criticality | string | | "Critical", "High", etc. |
| mitigation_date | S | detailedreport.do | mitigation_date | datetime | | Alternative date field |
| mitigation_action | T | detailedreport.do | mitigation_action | string | | Action taken |
| static_version | U | getbuildinfo.do | sast_build_number | string | | Static analysis version |
| dynamic_version | V | getbuildinfo.do | dast_build_number | string | | Dynamic analysis version |
| static_submitted_date | W | getbuildinfo.do | sast_submitted_date | datetime | | Static analysis scan date |
| dynamic_submitted_date | X | getbuildinfo.do | dast_submitted_date | datetime | | Dynamic analysis scan date |
| cve_summary | Y | detailedreport.do | description | string | | CVE description text |
| component_id | Z | detailedreport.do | component_id | string | | Internal component ID |
| **sha1** | **AA** | detailedreport.do | **sha1** | **string** | **✓✓** | **Primary matching key** |
| vulnerabilities | AB | detailedreport.do | (count) | integer | | Number of vulnerabilities |
| max_cvss_score | AC | detailedreport.do | max_cvss_score | float | | Highest CVSS score |
| library | AD | detailedreport.do | component_name | string | ✓ | Library/component name |
| **library_id** | **AE** | **detailedreport.do** | **library_id** | **string** | **✓✓** | **Secondary matching key** |
| version | AF | detailedreport.do | component_version | string | | Component version |
| vendor | AG | detailedreport.do | vendor | string | | Component vendor |
| description | AH | detailedreport.do | description or summary | string | | Vulnerability description |
| blocklisted | AI | detailedreport.do | blocklisted | boolean | | Is component blocklisted |
| new | AJ | detailedreport.do | new | boolean | | Is vulnerability newly found |
| added_date | AK | detailedreport.do | added_date | datetime | | When added to system |
| component_affects_policy_compliance | AL | detailedreport.do | component_affects_policy_compliance | boolean | | Policy impact flag |

### Key Observations

**Matching Keys (Critical for linking with SBOM):**
- **sha1** (Column AA) - Primary identifier, most reliable
- **library_id** (Column AE) - Secondary identifier, Veracode-specific

**Data Aggregation Note:**
Each row from `detailedreport.do` represents ONE vulnerability. Multiple vulnerabilities may exist for the same component:

```
Example:
component_name: log4j-core
component_version: 2.14.1
sha1: abc123

Findings for log4j-core 2.14.1:
  CVE-2021-44228, severity: 5, cwe: 94
  CVE-2021-45046, severity: 4, cwe: 502
  CVE-2021-45047, severity: 4, cwe: 835

Expected Excel rows: 3 (one per finding)
OR aggregated: 1 row with vulnerabilities count and details

Recommendation: Store as separate rows (denormalized) to match manual Excel structure
```

---

## Part 2: SBOM Components Mapping

### API Endpoints Used

1. **Applications v1 API** - Get all applications
   - Endpoint: `GET /appsec/v1/applications?scan_type=STATIC&size=500`
2. **SBOM v1 API** - Get SBOM data (CycloneDX format)
   - Endpoint: `GET /srcclr/sbom/v1/targets/{app_guid}/cyclonedx?type=application`

### SBOM Components Sheet: API Field → Excel Column

| Excel Column | Column # | API Response | Field Path | Data Type | Required? | Notes |
|---|---|---|---|---|---|---|
| application_id | A | Applications API | guid | string | ✓ | Unique app identifier (GUID format) |
| app_name | B | Applications API | name | string | ✓ | Application name |
| component_type | C | SBOM (CycloneDX) | components[].type | string | | "library", "application", "framework", etc. |
| component_name | D | SBOM (CycloneDX) | components[].name | string | ✓ | Component/library name |
| bom_ref | E | SBOM (CycloneDX) | components[].bom-ref | string | ✓ | SBOM reference identifier |
| **sha1** | **F** | **SBOM (CycloneDX)** | **components[].hashes[].content (where alg=SHA-1)** | **string** | **✓✓** | **Primary matching key** |
| sha256 | G | SBOM (CycloneDX) | components[].hashes[].content (where alg=SHA-256) | string | | SHA256 hash if available |
| match_type | H | (Generated) | (N/A) | string | | How component was matched |
| bytecode_hash | I | SBOM (CycloneDX) | components[].hashes[].content (where alg=bytecode) | string | | Bytecode hash if applicable |
| file_path | J | SBOM (CycloneDX) | components[].evidence.compositions[].components[].purl | string | | File path or PURL |
| cve_ids | K | SBOM (CycloneDX) | components[].vulnerabilities[].ref | string | | Comma-separated CVE list |
| cwe_ids | L | SBOM (CycloneDX) | components[].vulnerabilities[].ratings[].cwe | string | | Comma-separated CWE list |
| all_dependencies | M | SBOM (CycloneDX) | components[].dependencies | string | | Serialized dependency list |

### Additional SBOM Fields to Extract

From CycloneDX component object:

```json
{
  "bom-ref": "pkg:npm/lodash@4.17.21",
  "type": "library",
  "name": "lodash",
  "version": "4.17.21",
  "purl": "pkg:npm/lodash@4.17.21",
  "scope": "required",
  "hashes": [
    {
      "alg": "SHA-1",
      "content": "88d36f5051fb029ad5ef1119a73953f7add33fd9"
    },
    {
      "alg": "SHA-256",
      "content": "..."
    }
  ],
  "licenses": [...],
  "evidence": {
    "identity": {
      "field": "purl",
      "confidence": 0.99,
      "methods": [...]
    }
  },
  "vulnerabilities": [
    {
      "ref": "CVE-2021-23337",
      "ratings": [...]
    }
  ],
  "dependencies": [...]
}
```

---

## Part 3: API Response Structure Examples

### getapplist.do Response

```xml
<?xml version="1.0" encoding="UTF-8"?>
<applist xmlns="https://analysiscenter.veracode.com/api" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <app app_id="123456" app_name="MyApp" account_id="12345" organization_id="54321" 
       custom_fields="" tags="" business_criticality="HIGH" is_policy_sandboxed="false" />
</applist>
```

### getbuildinfo.do Response

```xml
<?xml version="1.0" encoding="UTF-8"?>
<buildinfo xmlns="https://analysiscenter.veracode.com/api">
  <build build_id="789456" app_id="123456" version="1.0.0" 
         build_status="PUBLISHED" policy_name="Policy 1"
         policy_compliance_status="PASS" rules_status="FAILED"
         plan_prescan_submitted_date="..." 
         scan_overdue_date="..."
         published_date="2024-01-15T10:30:00Z"
         results_ready="true" />
</buildinfo>
```

### detailedreport.do Response (XML)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<detailedreport xmlns="https://analysiscenter.veracode.com/api">
  <flaw flaw_id="123" category="..." cwe="123" type="..." description="..."
        severity="5" cvss_score="9.8" 
        sha1="abc123def456..." library_id="lib-001" component_name="log4j" 
        component_version="2.14.1" file_name="log4j-core-2.14.1.jar"
        first_found_date="2024-01-10" mitigated_date="" mitigation=""
        new="false" />
</detailedreport>
```

### SBOM API Response (CycloneDX JSON)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "bom": {
    "version": 1,
    "components": [
      {
        "bom-ref": "pkg:npm/lodash@4.17.21",
        "type": "library",
        "name": "lodash",
        "version": "4.17.21",
        "purl": "pkg:npm/lodash@4.17.21",
        "hashes": [
          {
            "alg": "SHA-1",
            "content": "88d36f5051fb029ad5ef1119a73953f7add33fd9"
          },
          {
            "alg": "SHA-256",
            "content": "be3e3338..."
          }
        ],
        "vulnerabilities": [
          {
            "ref": "CVE-2021-23337",
            "ratings": [
              {
                "score": 8.7,
                "severity": "high",
                "method": "CVSSv3"
              }
            ]
          }
        ]
      }
    ]
  }
}
```

### Applications v1 API Response

```json
{
  "page": 1,
  "page_size": 20,
  "total_size": 150,
  "applications": [
    {
      "guid": "550e8400-e29b-41d4-a716-446655440000",
      "id": "123456",
      "name": "MyApp",
      "business_criticality": "HIGH",
      "legacy_id": "12345",
      "profile": {
        "name": "MyApp"
      }
    }
  ]
}
```

---

## Part 4: Data Extraction Logic

### Algorithm: Extract Vulnerability Data from detailedreport.do

```python
def extract_vulnerabilities(detailed_report_xml: str, app_id: str, app_name: str, build_id: str) -> List[Dict]:
    """
    Extract vulnerability records from detailedreport.do XML response
    
    Input: detailedreport.do XML response
    Output: List of SCAVulnerabilityRecord dicts
    """
    
    findings = []
    root = ET.fromstring(detailed_report_xml)
    
    # Navigate to flaws in XML
    for flaw in root.findall('.//flaw'):
        # Extract all relevant fields
        finding = {
            'cve_id': flaw.get('category'),  # or extract from cwe element
            'severity': int(flaw.get('severity', 0)),
            'cwe_id': flaw.get('cwe'),
            'cvss_score': float(flaw.get('cvss_score', 0)),
            'component_name': flaw.get('component_name'),
            'component_version': flaw.get('component_version'),
            'library_id': flaw.get('library_id'),  # **MATCHING KEY**
            'sha1': flaw.get('sha1'),  # **MATCHING KEY**
            'file_name': flaw.get('file_name'),
            'first_found_date': flaw.get('first_found_date'),
            'mitigated_date': flaw.get('mitigated_date'),
            'new': flaw.get('new') == 'true',
            
            # Add app/build metadata
            'app_id': app_id,
            'app_name': app_name,
            'build_id': build_id,
        }
        findings.append(finding)
    
    return findings
```

### Algorithm: Extract SBOM Components from CycloneDX

```python
def extract_sbom_components(sbom_json: Dict, app_id: str, app_name: str) -> List[Dict]:
    """
    Extract component records from SBOM API CycloneDX response
    
    Input: SBOM API JSON response
    Output: List of SBOMComponent dicts
    """
    
    components = []
    bom = sbom_json.get('bom', {})
    
    for comp in bom.get('components', []):
        # Extract hashes
        sha1 = None
        sha256 = None
        for hash_item in comp.get('hashes', []):
            if hash_item.get('alg') == 'SHA-1':
                sha1 = hash_item.get('content')
            elif hash_item.get('alg') == 'SHA-256':
                sha256 = hash_item.get('content')
        
        # Extract CVE/CWE info
        cve_ids = []
        cwe_ids = []
        for vuln in comp.get('vulnerabilities', []):
            if 'ref' in vuln:
                cve_ids.append(vuln['ref'])
            for rating in vuln.get('ratings', []):
                if 'cwe' in rating:
                    cwe_ids.append(rating['cwe'])
        
        component = {
            'application_id': app_id,
            'app_name': app_name,
            'component_name': comp.get('name'),
            'component_type': comp.get('type', 'library'),
            'component_version': comp.get('version'),
            'bom_ref': comp.get('bom-ref'),  # **MATCHING KEY**
            'sha1': sha1,  # **MATCHING KEY**
            'sha256': sha256,
            'purl': comp.get('purl'),
            'cve_ids': ','.join(cve_ids) if cve_ids else '',
            'cwe_ids': ','.join(cwe_ids) if cwe_ids else '',
        }
        components.append(component)
    
    return components
```

---

## Part 5: Matching Keys Summary

### Primary Matching Strategy: SHA1 Hash

**Used in:** Both vulnerability data (Column AA) and SBOM (Column F)

- **Most Reliable**: Exact binary match
- **Availability**: ~60-80% of components
- **Confidence**: 100%

```python
# In vulnerability_matcher.py
def _match_by_sha1(self, sbom_component):
    if not sbom_component.sha1:
        return None
    
    for sca_component in self.sca_components.values():
        if sca_component.sha1 and \
           sca_component.sha1.upper() == sbom_component.sha1.upper():
            return sca_component
    return None
```

### Secondary Matching Strategy: Library/BOM Reference ID

**Used in:** Vulnerability library_id (Column AE) and SBOM bom_ref (Column E)

- **Reliability**: Medium (Veracode-specific)
- **Availability**: ~40-60% of components
- **Confidence**: 80-85%

```python
# In vulnerability_matcher.py
def _match_by_library_id(self, sbom_component):
    if not sbom_component.bom_ref:
        return None
    
    for sca_component in self.sca_components.values():
        if sca_component.library_id and \
           self._normalize_id(sbom_component.bom_ref) == \
           self._normalize_id(sca_component.library_id):
            return sca_component
    return None
```

### Tertiary Strategies: PURL, Composite Key, Fuzzy Name

See [vulnerability_matcher.py](vulnerability_matcher.py#L176) for implementation.

---

## Part 6: Data Quality Checks

Before exporting data, verify:

```python
# Required fields validation
REQUIRED_VULNERABILITY_FIELDS = [
    'sha1',  # Matching key
    'library_id',  # Matching key
    'app_id',  # Foreign key
    'build_id',  # Foreign key
    'component_name',  # Component identification
    'component_version',  # Component identification
]

REQUIRED_SBOM_FIELDS = [
    'bom_ref',  # Matching key
    'application_id',  # Foreign key
    'component_name',  # Component identification
    'sha1',  # Matching key (may be None, OK)
]

# Quality checks
def validate_vulnerability(record: Dict) -> bool:
    # Check required fields
    for field in REQUIRED_VULNERABILITY_FIELDS:
        if field not in record or not record[field]:
            logger.warning(f"Missing required field: {field}")
            return False
    
    # Check data types
    if not isinstance(record['severity'], (int, float)):
        logger.warning(f"Invalid severity type: {type(record['severity'])}")
        return False
    
    # Check value ranges
    if record['severity'] < 1 or record['severity'] > 5:
        logger.warning(f"Invalid severity value: {record['severity']}")
        return False
    
    return True

def validate_sbom(record: Dict) -> bool:
    for field in REQUIRED_SBOM_FIELDS:
        if field not in record or not record[field]:
            logger.warning(f"Missing required field: {field}")
            return False
    
    return True
```

---

## References

- [Veracode API Documentation](https://docs.veracode.com/r/c_api_overview)
- [CycloneDX Specification](https://cyclonedx.org/specification/)
- [Project Plan: API Fetcher Update](API_FETCHER_UPDATE_PLAN.md)
