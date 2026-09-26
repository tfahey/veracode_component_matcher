# Veracode API Response Structures

Generated: 2026-09-25T12:18:35.605222

## 1. getapplist.do

**Description**: Get list of all applications

**Endpoint**: `GET /api/5.0/getapplist.do`

**Method**: GET

**Response Type**: JSON (v1 API)

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | N/A | Application ID (integer) |
| `guid` | N/A | Application GUID (UUID string) |
| `name` | N/A | Application name (string) |
| `legacy_id` | N/A | Legacy application ID (integer) |
| `profile` | N/A | Profile object containing app details |
| `created_date` | N/A | Creation date (ISO 8601) |
| `modified_date` | N/A | Last modified date (ISO 8601) |

---

## 2. getappinfo.do

**Description**: Get detailed application information

**Endpoint**: `GET /api/5.0/getappinfo.do?app_id={app_id}`

**Method**: GET

**Response Type**: XML

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `app_id` | N/A | Application ID |
| `app_name` | N/A | Application name |
| `organization_id` | N/A | Organization ID |
| `business_criticality` | N/A | Business criticality level (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN) |
| `is_policy_sandboxed` | N/A | Whether app is sandboxed (true/false) |
| `custom_fields` | N/A | Custom field values |
| `tags` | N/A | Application tags |
| `policies` | N/A | Assigned policies |

---

## 3. getbuildlist.do

**Description**: Get list of builds for an application

**Endpoint**: `GET /api/5.0/getbuildlist.do?app_id={app_id}`

**Method**: GET

**Response Type**: XML

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `build_id` | N/A | Build ID (integer) |
| `app_id` | N/A | Application ID |
| `version` | N/A | Build version string |
| `build_status` | N/A | Status (PUBLISHED, INCOMPLETE, RUNNING, etc.) |
| `policy_name` | N/A | Policy applied to build |
| `policy_compliance_status` | N/A | PASS or FAIL |
| `published_date` | N/A | When build was published (ISO 8601) |
| `scan_overdue_date` | N/A | When rescan is due |
| `results_ready` | N/A | Whether results are ready (true/false) |
| `sandbox_id` | N/A | Sandbox ID if sandboxed |

---

## 4. getbuildinfo.do

**Description**: Get information about a specific build

**Endpoint**: `GET /api/5.0/getbuildinfo.do?app_id={app_id}&build_id={build_id}`

**Method**: GET

**Response Type**: XML (with embedded vulnerability data)

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `build_id` | N/A | Build ID |
| `app_id` | N/A | Application ID |
| `version` | N/A | Build version |
| `build_status` | N/A | Status (PUBLISHED, etc.) |
| `policy_name` | N/A | Policy name |
| `policy_compliance_status` | N/A | PASS/FAIL |
| `rules_status` | N/A | PASS/FAIL/NOT_APPLICABLE |
| `published_date` | N/A | Publication date (ISO 8601) |
| `results_ready` | N/A | Results ready flag |
| `analysis_unit_id` | N/A | Analysis unit identifier |
| `sast_build_number` | N/A | Static analysis build number |
| `dast_build_number` | N/A | Dynamic analysis build number |
| `sast_submitted_date` | N/A | Static analysis submission date |
| `dast_submitted_date` | N/A | Dynamic analysis submission date |
| `vulnerability` | N/A | Array of vulnerability findings |

---

## 5. detailedreport.do

**Description**: Get detailed vulnerability findings for a build

**Endpoint**: `GET /api/5.0/detailedreport.do?build_id={build_id}`

**Method**: GET

**Response Type**: XML

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `flaw_id` | N/A | Unique flaw identifier |
| `category` | N/A | Vulnerability category |
| `cwe` | N/A | CWE ID |
| `type` | N/A | Vulnerability type |
| `description` | N/A | Vulnerability description |
| `severity` | N/A | Severity level (1-5) |
| `cvss_score` | N/A | CVSS v3 score |
| `sha1` | N/A | SHA1 hash of affected component (MATCHING KEY) |
| `library_id` | N/A | Veracode library ID (MATCHING KEY) |
| `component_name` | N/A | Component/library name |
| `component_version` | N/A | Component version |
| `file_name` | N/A | Affected file name |
| `first_found_date` | N/A | When vulnerability was first detected |
| `mitigated_date` | N/A | When vulnerability was mitigated (if any) |
| `mitigation` | N/A | Mitigation text |
| `mitigation_type` | N/A | Type of mitigation |
| `new` | N/A | Is this a new finding (true/false) |
| `blocklisted` | N/A | Is component blocklisted (true/false) |
| `affects_policy_compliance` | N/A | Does it affect policy compliance |

---

## 6. GET /appsec/v1/applications

**Description**: Get all applications (v1 REST API)

**Endpoint**: `GET /appsec/v1/applications?scan_type=STATIC&size=500`

**Method**: GET

**Response Type**: JSON

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `guid` | N/A | Application GUID (UUID) - Used for SBOM API calls |
| `id` | N/A | Application ID (integer) |
| `name` | N/A | Application name |
| `legacy_id` | N/A | Legacy application ID |
| `profile` | N/A | Profile object with application metadata |
| `created_date` | N/A | Creation date (ISO 8601) |
| `modified_date` | N/A | Last modification date (ISO 8601) |
| `business_criticality` | N/A | Business impact level |
| `tags` | N/A | Associated tags |

---

