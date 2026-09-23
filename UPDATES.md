# Veracode Component Matcher - Updates

This document describes major updates and improvements made to the Veracode Component Matcher application, including the `api_fetcher.py` module, since the initial implementation.

## Library Migration

### From Raw Requests to veracode_api_py
- **Changed**: Replaced manual HTTP requests with the official `veracode_api_py` library
- **Benefits**: 
  - Built-in credential handling and validation
  - Automatic authentication and error handling
  - Better alignment with Veracode SDK conventions
  - Access to helper methods like `get_apps()`, `get_creds()`
- **Files affected**: `api_fetcher.py`, `requirements.txt`

## Credential Handling

### New Credential Precedence System
Credentials are now resolved in this order (first match wins):
1. Command-line arguments (`--veracode_api_key_id`, `--veracode_api_key_secret`)
2. Environment variables (`VERACODE_API_KEY_ID`, `VERACODE_API_KEY_SECRET`)
3. Credentials file (`~/.veracode/credentials` - default section only)

**Command-line usage:**
```bash
# Use credentials from file (default)
python3 api_fetcher.py --limit 5

# Override with command-line arguments
python3 api_fetcher.py --veracode_api_key_id ID --veracode_api_key_secret SECRET --limit 5

# Override with environment variables
export VERACODE_API_KEY_ID=id
export VERACODE_API_KEY_SECRET=secret
python3 api_fetcher.py --limit 5
```

### Credential Status Reporting
Added clear INFO-level messages for different credential conditions:
- **Invalid or expired**: `❌ API credentials are invalid or expired: {error_description}`
- **Expired**: `❌ API credentials are expired as of {timestamp}`
- **Expiring soon**: `⚠️ API credentials expire in {N} day(s): {timestamp}`

## Error Handling Improvements

### SBOM Fetch Fallback
- **Problem**: SBOM endpoint with `vulnerability=True` returns 404 for apps without recent scans
- **Solution**: Automatically retries with `vulnerability=False` for fallback basic SBOM data
- **Location**: `get_sbom()` method

### SCA Component Extraction
- **Problem**: Build info endpoint returns XML error responses that were causing "'str' object has no attribute 'get'" errors
- **Solution**: 
  - Detect error responses (XML root tag is "error")
  - Return None gracefully instead of crashing
  - Added comprehensive debug logging for diagnosis
- **Location**: `get_build_info()` method with `_xml_to_dict()` helper

### Credential Expiration Check
- **Problem**: Mixed response types from `get_creds()` causing KeyError exceptions
- **Solution**: 
  - Handle both dict and Response object types
  - Check for error responses in credentials
  - Distinguish between invalid, expired, and valid credentials
  - All errors logged at DEBUG level to avoid false alarms
- **Location**: `check_credentials_expiration()` function

## Logging & Verbosity

### Library Logging Suppression
- Set veracode_api_py, urllib3, requests, and httpie logging to CRITICAL level
- **Reason**: Reduces noise from expected HTTP 404 errors that are handled gracefully
- **Result**: Clean INFO level output focusing on application workflow

### Debug Logging
- Added detailed debug logging for:
  - Credential source identification (which credentials file section, env var, or argument)
  - API response structure and types
  - Credential validation checks
  - XML-to-dict conversion process
- **Usage**: Set log level to DEBUG to see detailed diagnostic information

## Testing & Development Features

### Application Limit Parameter
- **New parameter**: `--limit N`
- **Purpose**: Test the script with a subset of applications instead of full portfolio
- **Usage**: `python3 api_fetcher.py --limit 5` processes only first 5 applications
- **Benefits**: Faster iteration during development, quicker validation of fixes

## Data Handling

### XML to Dictionary Conversion
- Added `_xml_to_dict()` helper method to properly convert Veracode API XML responses
- Ensures consistent dictionary structure for component extraction
- Located in: `VeracodeApiFetcher` class

### Component Aggregation
- SCA components now properly aggregated from `extract_sca_vulnerabilities()`
- SBOM components extracted from CycloneDX format via `extract_sbom_components()`
- Components collected into global lists for cross-application analysis

## Matching & Output

### Multi-Stage Component Matching
- Uses `VulnerabilityMatcher` from `vulnerability_matcher.py`
- Implements five matching strategies in precedence order:
  1. SHA1 hash matching
  2. Package URL (purl) matching
  3. Composite key (vendor/name/version)
  4. Library ID matching
  5. Fuzzy name matching (fallback)

### Output Files
- `matched_components.csv`: Components that matched across SCA/SBOM
- `unmatched_components.csv`: Components only in one source
- `all_sca_components.json`: Raw SCA data collected
- `all_sbom_components.json`: Raw SBOM data collected

## Usage Examples

```bash
# Basic usage with default credentials
python3 api_fetcher.py

# Test with limit to first 3 apps
python3 api_fetcher.py --limit 3

# Use specific credentials via command line
python3 api_fetcher.py \
  --veracode_api_key_id "your_api_id" \
  --veracode_api_key_secret "your_api_secret" \
  --limit 10

# List available credential profiles
python3 api_fetcher.py --list-profiles

# Use environment variables
export VERACODE_API_KEY_ID="your_api_id"
export VERACODE_API_KEY_SECRET="your_api_secret"
python3 api_fetcher.py --limit 5
```

## Key Files Modified

- `api_fetcher.py`: Main implementation file with library migration and all improvements
- `requirements.txt`: Updated to use `veracode-api-py` instead of direct `requests`
- `vulnerability_matcher.py`: Unchanged, provides multi-stage matching logic

## Backward Compatibility

- Script signature changed from profile-based to argument-based credentials
- Old `python3 api_fetcher.py profile_name` syntax no longer works
- Use `--veracode_api_key_id` and `--veracode_api_key_secret` for explicit credentials
- Credentials file is still supported as default fallback (no arguments or env vars needed)

