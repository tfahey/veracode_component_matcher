# Task 1.1 Execution Guide: Document API Response Structures

## Overview

Task 1.1 involves testing all Veracode API endpoints and documenting their response structures. This guide walks through executing this task using the provided `task_1_1_api_discovery.py` script.

**Objectives:**
- [ ] Test all 7 API endpoints
- [ ] Document response structures
- [ ] Save sample responses (JSON/XML)
- [ ] Create API reference documentation
- [ ] Validate field availability for matching

**Time Estimate:** 1-2 hours  
**Output:** `docs/api_samples/` directory with samples and documentation

---

## Prerequisites

1. ✅ Veracode API credentials (from ~/.veracode/credentials or env vars)
2. ✅ Access to at least one Veracode application
3. ✅ Access to applications with SBOM data (recommended)

### Verify Credentials
```bash
# Check if credentials file exists
ls -la ~/.veracode/credentials

# Or verify environment variables
echo $VERACODE_API_KEY_ID
echo $VERACODE_API_KEY_SECRET
```

---

## Step 1: Prepare Environment

### Create output directory
```bash
mkdir -p docs/api_samples
```

### Verify api_fetcher.py is working
```bash
python -c "
from api_fetcher import VeracodeApiFetcher
fetcher = VeracodeApiFetcher()
print('✓ API client initialized')
apps = fetcher.get_all_applications()
print(f'✓ Found {len(apps)} applications')
"
```

---

## Step 2: Run the Discovery Script

### Basic Execution
```bash
python task_1_1_api_discovery.py
```

This will:
1. Test all 7 API endpoints
2. Save response samples to `docs/api_samples/`
3. Generate documentation
4. Print results to console

### With Custom Output Directory
```bash
python task_1_1_api_discovery.py --output-dir ./api_samples_backup
```

### With Explicit Credentials
```bash
python task_1_1_api_discovery.py \
  --veracode_api_key_id YOUR_ID \
  --veracode_api_key_secret YOUR_KEY
```

---

## Step 3: Monitor Execution

The script will output:

```
================================================================================
🔍 VERACODE API DISCOVERY - TASK 1.1
================================================================================

================================================================================
Testing: getapplist.do
================================================================================
✓ Got 42 applications
✓ Saved: docs/api_samples/01_getapplist_response.json
✓ Documented: getapplist.do

Sample Application:
{
  "guid": "550e8400-e29b-41d4-a716-446655440000",
  "id": 123456,
  "name": "MyApp",
  ...
}

================================================================================
Testing: getbuildinfo.do
================================================================================
...

[More endpoint tests...]

✅ API DISCOVERY COMPLETE
================================================================================

Saved samples to: docs/api_samples
Total endpoints documented: 7

Next steps:
  1. Review saved JSON/XML samples in docs/api_samples/
  2. Review API_RESPONSE_DOCUMENTATION.md
  3. Update API_FIELD_MAPPING.md with actual field names
  4. Proceed to Task 1.2 (create detailed field mapping)
```

---

## Step 4: Review Generated Files

### Check saved samples
```bash
ls -lh docs/api_samples/
```

Expected files:
- `01_getapplist_response.json` - All applications
- `04_getbuildinfo_response.json` - Build information
- `06_applications_v1_response.json` - v1 API apps
- `07_sbom_cyclonedx_response.json` - SBOM data (CycloneDX)
- `API_RESPONSE_DOCUMENTATION.md` - Formatted documentation

### View documentation
```bash
cat docs/api_samples/API_RESPONSE_DOCUMENTATION.md
```

### Examine specific responses
```bash
# Pretty print the applications
python -c "
import json
with open('docs/api_samples/01_getapplist_response.json') as f:
    apps = json.load(f)
    print(f'Total apps: {len(apps)}')
    print('First app fields:')
    for key in apps[0].keys():
        print(f'  - {key}')
"

# Check SBOM structure
python -c "
import json
with open('docs/api_samples/07_sbom_cyclonedx_response.json') as f:
    sbom = json.load(f)
    bom = sbom.get('bom', {})
    components = bom.get('components', [])
    print(f'Total components: {len(components)}')
    if components:
        print('First component:')
        print(json.dumps(components[0], indent=2))
"
```

---

## Step 5: Validate Against Expected Structures

### API 1: getapplist.do
Expected fields:
```python
expected_fields = ['guid', 'id', 'name', 'legacy_id', 'profile']

# Verify
import json
with open('docs/api_samples/01_getapplist_response.json') as f:
    apps = json.load(f)
    if apps:
        app = apps[0]
        for field in expected_fields:
            if field in app:
                print(f'✓ {field} present')
            else:
                print(f'✗ {field} MISSING')
```

### API 2: SBOM (CycloneDX)
Expected structure:
```python
# Verify SBOM structure
import json
with open('docs/api_samples/07_sbom_cyclonedx_response.json') as f:
    sbom = json.load(f)
    
    # Check top-level fields
    required = ['bomFormat', 'specVersion', 'bom']
    for field in required:
        status = '✓' if field in sbom else '✗'
        print(f'{status} {field}')
    
    # Check component fields
    bom = sbom.get('bom', {})
    components = bom.get('components', [])
    if components:
        comp = components[0]
        comp_fields = ['bom-ref', 'type', 'name', 'version', 'purl', 'hashes']
        print('\nComponent fields:')
        for field in comp_fields:
            status = '✓' if field in comp else '✗'
            print(f'  {status} {field}')
        
        # Check hashes
        if 'hashes' in comp:
            print('\n  Hash types:')
            for hash_item in comp['hashes']:
                alg = hash_item.get('alg')
                print(f'    - {alg}')
```

---

## Step 6: Identify Critical Matching Fields

After reviewing the samples, identify:

```python
# Create verification script
import json

print("=" * 60)
print("CRITICAL MATCHING FIELDS VERIFICATION")
print("=" * 60)

# Check vulnerability data
try:
    with open('docs/api_samples/04_getbuildinfo_response.json') as f:
        build_info = json.load(f)
        if 'build' in build_info:
            vulns = build_info.get('build', {}).get('vulnerability', [])
            if vulns:
                v = vulns[0]
                print("\nVulnerability Data:")
                print(f"  sha1: {v.get('sha1', 'MISSING')}")
                print(f"  library_id: {v.get('library_id', 'MISSING')}")
                print(f"  component_name: {v.get('component_name', 'MISSING')}")
                print(f"  component_version: {v.get('component_version', 'MISSING')}")
except Exception as e:
    print(f"Could not check vulnerability data: {e}")

# Check SBOM data
try:
    with open('docs/api_samples/07_sbom_cyclonedx_response.json') as f:
        sbom = json.load(f)
        components = sbom.get('bom', {}).get('components', [])
        if components:
            c = components[0]
            sha1 = None
            for h in c.get('hashes', []):
                if h.get('alg') == 'SHA-1':
                    sha1 = h.get('content')
            print("\nSBOM Component:")
            print(f"  bom-ref: {c.get('bom-ref', 'MISSING')}")
            print(f"  sha1: {sha1 or 'MISSING'}")
            print(f"  name: {c.get('name', 'MISSING')}")
            print(f"  version: {c.get('version', 'MISSING')}")
            print(f"  purl: {c.get('purl', 'MISSING')}")
except Exception as e:
    print(f"Could not check SBOM data: {e}")

print("\n" + "=" * 60)
```

---

## Step 7: Document Findings

Create a findings document:

```bash
cat > docs/api_samples/TASK_1_1_FINDINGS.md << 'EOF'
# Task 1.1 Findings: API Response Structures

## Date
$(date)

## Summary
[Brief summary of findings]

## API Endpoints Tested

### 1. getapplist.do ✓
- **Status**: Working
- **Apps Found**: [Number]
- **Critical Fields Present**: guid, id, name
- **Issues**: None

### 2. getappinfo.do ✓
- **Status**: [Working/Not tested]
- **Issues**: [If any]

### 3. getbuildlist.do ✓
- **Status**: [Working/Not tested]
- **Issues**: [If any]

### 4. getbuildinfo.do ✓
- **Status**: Working
- **Vulnerability Records**: [Number]
- **Matching Keys Present**: sha1, library_id
- **Issues**: None

### 5. detailedreport.do ✓
- **Status**: Documented
- **Expected Fields**: [Listed]
- **Issues**: [If any]

### 6. Applications v1 API ✓
- **Status**: Working
- **Apps Found**: [Number]
- **GUID Format**: Confirmed as UUID
- **Issues**: None

### 7. SBOM v1 API (CycloneDX) ✓
- **Status**: Working
- **Components Found**: [Number]
- **Matching Keys Present**: bom-ref, sha1 (in hashes)
- **SBOM Format**: CycloneDX 1.4
- **Issues**: [If any]

## Matching Key Availability

### SHA1 Hash
- **Vulnerability Data**: ✓ Present in detailedreport.do
- **SBOM Data**: ✓ Present in hashes array (alg=SHA-1)
- **Reliability**: 100% for exact matches

### Library ID / BOM-Ref
- **Vulnerability Data**: ✓ Present as library_id
- **SBOM Data**: ✓ Present as bom-ref
- **Reliability**: 80-85% (Veracode-specific)

## Data Volume
- **Applications**: [Number]
- **Build Info Records**: [Number]
- **SBOM Components**: [Number]
- **Estimated Vulnerabilities**: [Number]

## Next Steps
1. ✓ Complete API field mapping document
2. → Proceed to Task 1.2 (detailed field mapping)
3. → Continue with Phase 2 (Data Structure Design)

## Issues Encountered
[List any issues and resolutions]

## Recommendations
[Any observations for implementation]
EOF
```

---

## Troubleshooting

### Issue: "No applications found"
**Cause**: Either no apps exist or API credentials lack permission  
**Solution**: 
```bash
# Verify credentials work
python -c "
from api_fetcher import VeracodeApiFetcher
fetcher = VeracodeApiFetcher()
print('Credentials valid')
"

# Check with API directly
http --auth-type=veracode_hmac https://analysiscenter.veracode.com/api/5.0/getapplist.do
```

### Issue: "No SBOM data found"
**Cause**: SBOM API requires UUID (guid), not integer ID  
**Solution**: The script automatically converts to string, but verify:
```python
# Check app structure
import json
with open('docs/api_samples/01_getapplist_response.json') as f:
    apps = json.load(f)
    app = apps[0]
    print(f"guid type: {type(app.get('guid'))}")
    print(f"guid value: {app.get('guid')}")
```

### Issue: "Script times out"
**Cause**: Fetching all apps may take time  
**Solution**: Add a limit parameter:
```bash
# Only test first 5 apps (modify script or use as reference)
# Edit task_1_1_api_discovery.py to add:
app_limit = 5
for app in apps[:app_limit]:
    ...
```

### Issue: Responses are empty or incomplete
**Cause**: Recent scans may not be available  
**Solution**: 
```bash
# Check build status
python -c "
from api_fetcher import VeracodeApiFetcher
fetcher = VeracodeApiFetcher()
apps = fetcher.get_all_applications()
for app in apps[:5]:
    print(f\"App: {app.get('name')}\")
    # Try to get build info
    guid = app.get('guid')
    if guid:
        info = fetcher.get_build_info(str(guid))
        print(f\"  Build info available: {bool(info)}\")
"
```

---

## Validation Checklist

After running Task 1.1, verify:

- [ ] `docs/api_samples/` directory created
- [ ] All 7 response files saved (or documented)
- [ ] `API_RESPONSE_DOCUMENTATION.md` generated
- [ ] At least 1 application found
- [ ] At least 1 build info with vulnerabilities
- [ ] At least 1 SBOM with components
- [ ] Both matching keys (sha1/bom-ref) identified
- [ ] Field structures documented
- [ ] Ready to proceed to Task 1.2

---

## Next Steps

After completing Task 1.1:

1. **Review findings** - Examine generated documentation
2. **Validate structures** - Confirm all expected fields present
3. **Document issues** - Note any gaps or anomalies
4. **Create mapping** - Use findings to create detailed field mapping (Task 1.2)

---

## Success Criteria

✅ Task 1.1 is complete when:
- All 7 API endpoints tested and documented
- Sample responses saved to `docs/api_samples/`
- API documentation generated (`API_RESPONSE_DOCUMENTATION.md`)
- Matching keys identified and validated
- Ready to create detailed field mapping (Task 1.2)

---

## Quick Reference: Files Generated

```
docs/api_samples/
├── 01_getapplist_response.json          # All applications
├── 04_getbuildinfo_response.json        # Build with vulnerabilities
├── 06_applications_v1_response.json     # v1 API response
├── 07_sbom_cyclonedx_response.json      # SBOM data
├── API_RESPONSE_DOCUMENTATION.md         # Full documentation
└── TASK_1_1_FINDINGS.md                 # Findings summary
```

---

**Estimated Time**: 30-60 minutes  
**Prerequisites**: Veracode credentials  
**Deliverables**: API response documentation and samples  
**Success Criteria**: All endpoints tested, documentation created, ready for Task 1.2
