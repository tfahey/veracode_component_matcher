# Phase 5: Error Handling & Resilience - Execution Guide

## Overview

**Phase 5** implements comprehensive error handling and resilience features in `api_fetcher.py` to ensure robust and reliable API integration with Veracode services.

**Time Estimate**: 2 hours  
**Status**: IN PROGRESS  
**Deliverable**: Error handling and resilience methods in `api_fetcher.py`

---

## What Phase 5 Includes

### Task 5.1: Retry Logic with Exponential Backoff ✅

#### Method: `_retry_api_call(func, max_retries, backoff_factor)`

```python
def _retry_api_call(self, func, max_retries: int = 3, backoff_factor: float = 1.0):
    """Retry API calls with exponential backoff
    
    Args:
        func: Callable that makes the API request
        max_retries: Maximum number of retry attempts
        backoff_factor: Base for exponential backoff calculation
        
    Returns:
        Result of successful API call
        
    Raises:
        Exception: If all retries fail
    """
    import time
    
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt == max_retries - 1:
                logger.error(f"All retry attempts failed: {e}")
                raise
            
            wait_time = backoff_factor ** attempt
            logger.warning(f"API call failed (attempt {attempt + 1}/{max_retries}), "
                         f"retrying in {wait_time}s: {e}")
            time.sleep(wait_time)
```

**Features**:
- Exponential backoff: 1s → 2s → 4s → ... (configurable)
- Comprehensive logging of retry attempts
- Preserves original exception on final failure
- Configurable number of retries

**Usage**:
```python
def get_build_list_with_retry(app_id):
    return self._retry_api_call(
        lambda: self.get_build_list(app_id),
        max_retries=3,
        backoff_factor=2.0
    )
```

---

### Task 5.2: Request Timeout Handling ✅

#### Features:
- Add timeout parameter to all API calls
- Default timeout: 30 seconds
- Configurable per operation
- Graceful timeout exception handling

**Implementation**:
```python
# In get_build_list, get_detailed_report, get_sbom, etc.
# Add timeout to API calls:
response = self.api.get_sbom(
    app_guid=UUID(application_guid),
    vulnerability=True,
    timeout=30  # 30-second timeout
)
```

---

### Task 5.3: Rate Limiting ✅

#### Method: `_apply_rate_limit()`

```python
def _apply_rate_limit(self, min_interval: float = 0.5):
    """Apply rate limiting between API calls
    
    Args:
        min_interval: Minimum seconds between calls (default 0.5)
    """
    if self._last_api_call_time is not None:
        elapsed = time.time() - self._last_api_call_time
        if elapsed < min_interval:
            wait_time = min_interval - elapsed
            logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
            time.sleep(wait_time)
    
    self._last_api_call_time = time.time()
```

**Features**:
- Track last API call time
- Enforce minimum interval between requests
- Prevent API rate limit violations
- Configurable interval

---

### Task 5.4: Graceful Degradation ✅

#### Features:
- Skip failed applications, continue processing
- Return partial results instead of failing entirely
- Log all failures for audit trail
- Track success/failure metrics

**Implementation**:
```python
try:
    # Process application
    vulnerabilities = self.get_detailed_report(build_id)
except Exception as e:
    logger.warning(f"Failed to process {app_name}: {e}")
    failed_apps.append({'app_id': app_id, 'reason': str(e)})
    continue  # Continue processing other apps
```

---

### Task 5.5: Comprehensive Error Logging ✅

#### Enhanced Logging Levels:
- `DEBUG`: Detailed diagnostic information (retries, rate limiting)
- `INFO`: Major operations (app processing, data collection)
- `WARNING`: Recoverable errors (failed API calls, retries)
- `ERROR`: Unrecoverable errors (all retries failed, invalid data)

**Logging Points**:
- API call initiation and completion
- Retry attempts with wait times
- Rate limiting delays
- Validation failures
- Partial data collection
- Summary statistics

---

## Integration Points

### Update Existing Methods

All data collection methods now include:

1. **Retry Logic**: Wrapped API calls with `_retry_api_call()`
2. **Error Handling**: Try/except with logging and graceful degradation
3. **Rate Limiting**: Applied between sequential API calls
4. **Validation**: Check required fields before processing

### Methods Updated:
- `fetch_all_vulnerability_data()`
- `fetch_all_sbom_data()`
- `get_build_list()`
- `get_detailed_report()`
- `get_sbom()`

---

## File Changes

### api_fetcher.py (Updated)

**New Attributes**:
```python
self._last_api_call_time: Optional[float] = None
self.max_retries: int = 3
self.backoff_factor: float = 2.0
self.request_timeout: int = 30
self.rate_limit_interval: float = 0.5
```

**New Methods**:
```python
def _retry_api_call(func, max_retries, backoff_factor) → Any
def _apply_rate_limit(min_interval) → None
def _handle_api_error(error, context) → Dict
def get_failure_summary() → Dict
```

**Enhanced Methods**:
- All fetch_* methods with retry logic
- All API methods with timeout handling
- All processing loops with error tracking

---

## Usage Examples

### Example 1: Basic Usage (No Changes Required)
```python
from api_fetcher import VeracodeApiFetcher

fetcher = VeracodeApiFetcher()

# Automatically uses retry logic and timeouts
vulns = fetcher.fetch_all_vulnerability_data(app_limit=5)
components = fetcher.fetch_all_sbom_data(app_limit=5)

print(f"Collected: {len(vulns)} vulnerabilities, {len(components)} components")
```

### Example 2: Custom Retry Configuration
```python
fetcher = VeracodeApiFetcher()
fetcher.max_retries = 5        # Increase retry attempts
fetcher.backoff_factor = 3.0   # Longer backoff between retries
fetcher.request_timeout = 60   # 60-second timeout

vulns = fetcher.fetch_all_vulnerability_data()
```

### Example 3: Get Failure Summary
```python
fetcher = VeracodeApiFetcher()
vulns = fetcher.fetch_all_vulnerability_data()

# Get statistics on failures and retries
summary = fetcher.get_failure_summary()
print(f"Failures: {summary['failed_apps']}")
print(f"Retry count: {summary['total_retries']}")
```

---

## Error Scenarios Handled

### Scenario 1: Temporary API Timeout
**Without Phase 5**: Request fails, entire process stops  
**With Phase 5**: Retries up to 3 times with exponential backoff, continues if successful

### Scenario 2: Rate Limit Hit
**Without Phase 5**: Multiple rapid requests hit rate limit  
**With Phase 5**: Automatic rate limiting prevents hitting limits

### Scenario 3: One App Fails
**Without Phase 5**: One failure stops processing all apps  
**With Phase 5**: Logs failure, continues with other apps, returns partial results

### Scenario 4: Network Blip
**Without Phase 5**: Single network error fails  
**With Phase 5**: Automatic retry with backoff recovers from transient errors

---

## Configuration

### Default Settings (Conservative)
```python
max_retries = 3              # Retry 3 times
backoff_factor = 2.0         # 1s, 2s, 4s delays
request_timeout = 30         # 30-second timeout per request
rate_limit_interval = 0.5    # 500ms minimum between requests
```

### Aggressive Settings (Fast)
```python
max_retries = 5
backoff_factor = 1.5
request_timeout = 60
rate_limit_interval = 0.1
```

### Conservative Settings (Safe)
```python
max_retries = 5
backoff_factor = 3.0
request_timeout = 120
rate_limit_interval = 1.0
```

---

## Testing Phase 5

### Test Coverage:

Run the Phase 5 resilience tests:

```bash
python tests/test_phase_5_resilience.py
```

Test validations include:
- Retry logic verification
- Timeout handling
- Rate limiting
- Graceful degradation

### Manual Testing:
- Simulate API failures
- Verify retry behavior
- Check rate limiting
   - Validate error logging

---

## Data Flow with Error Handling

```
API Request
    ↓
Rate Limit Check ← Applied before each call
    ↓
Try API Call (with Timeout)
    ↓
    ├─ Success → Return Data
    │
    └─ Failure → Check Retry Count
        ├─ Retries Remaining → Backoff & Retry
        │   ↓ (Exponential delay)
        │   Try API Call Again
        │
        └─ Max Retries Exceeded → Log & Continue
            ↓
            Return Partial/Null Data
            ↓
            Process Next Item
```

---

## Checklist: Phase 5 Complete

- ✅ Retry logic with exponential backoff
- ✅ Request timeout handling (30s default)
- ✅ Rate limiting between API calls
- ✅ Graceful degradation (skip failures, continue)
- ✅ Comprehensive error logging
- ✅ Failure tracking and statistics
- ✅ Configuration options
- ✅ Error recovery in all workflows
- ✅ Partial result handling
- ⏳ Test coverage (pending)

---

## Next Steps: Phase 6

**Phase 6: Integration & Testing (3 hours)**

Will include:
1. Update main() function with CLI arguments
2. Integration testing
3. Performance validation
4. Documentation finalization

---

## References

- [API_FETCHER_UPDATE_PLAN.md](API_FETCHER_UPDATE_PLAN.md) - Full project plan
- [Phase 4 Guide](PHASE_4_EXECUTION_GUIDE.md) - Export implementation
- [Data Models](data_models.py) - Type definitions

---

**Phase 5 Status**: IN PROGRESS  
**Next Phase**: Phase 6 - Integration & Testing (3 hours)  
**Total Plan Progress**: 4/7 phases complete, Phase 5 in progress (13 hours done, 7 hours remaining)
