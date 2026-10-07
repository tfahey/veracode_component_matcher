# Deployment Guide: Veracode Component Matcher

## Status: Partial Implementation

### ✅ Created and Ready
- Configuration system (`config.py`, `config.json`)
- Automated workflow runner (`run_automated.py`)
- Workflow orchestration (`workflow.py`)
- Core API fetcher (`api_fetcher.py`)
- Environment variable support
- CLI argument handling

### ⚠️ Not Yet Created (Template Provided)
- **Dockerfile** — Docker container image (template provided below)
- **Kubernetes manifests** — ConfigMap, Job, CronJob files (templates provided below)
- **CI/CD workflows** — GitHub Actions, GitLab CI examples (can be added)

This guide provides templates and examples for these components. Create them as needed for your deployment environment.

---

## Quick Start

### Prerequisites

```bash
# Python 3.8+
python --version

# Install dependencies
pip install -r requirements.txt

# Verify Veracode credentials
python api_fetcher.py --list-profiles
```

### Basic Usage

```bash
# Collect all data (vulnerabilities + SBOM)
python api_fetcher.py --limit 5

# Collect vulnerabilities only
python api_fetcher.py --mode vuln --limit 5

# Export as CSV only
python api_fetcher.py --format csv --limit 5

# Custom output directory
python api_fetcher.py --output ./exports --limit 5
```

---

## Configuration

### Environment Variables

```bash
# API Configuration
export VERACODE_MAX_RETRIES=3
export VERACODE_BACKOFF_FACTOR=2.0
export VERACODE_TIMEOUT=30
export VERACODE_RATE_LIMIT=0.5

# Export Configuration
export VERACODE_OUTPUT_DIR=./exports
export VERACODE_EXPORT_FORMATS=json,csv
export VERACODE_INCLUDE_MATCHING=true

# Logging
export VERACODE_LOG_LEVEL=INFO
export VERACODE_LOG_FILE=workflow.log
export VERACODE_VERBOSE=false

# Environment
export VERACODE_ENV=production
```

### Configuration File

Edit `config.json`:

```json
{
  "api": {
    "max_retries": 3,
    "backoff_factor": 2.0,
    "request_timeout": 30,
    "rate_limit_interval": 0.5
  },
  "export": {
    "output_dir": "./exports",
    "formats": ["json", "csv"],
    "include_matching": true,
    "timestamp_exports": true
  },
  "log": {
    "level": "INFO",
    "verbose": false,
    "file_output": "workflow.log"
  }
}
```

---

## Automated Workflows

### Using run_automated.py

```bash
# Run with default configuration
python run_automated.py

# Load configuration from file
python run_automated.py --config config.json

# Override configuration
python run_automated.py --mode vuln --limit 10 --output ./results

# Verbose logging with file output
python run_automated.py --verbose --log-file workflow.log
```

### Scheduled Execution (Cron)

```bash
# Daily at 2 AM
0 2 * * * cd /path/to/project && python run_automated.py --config config.json >> workflow.log 2>&1

# Weekly Monday at 3 AM
0 3 * * 1 cd /path/to/project && python run_automated.py --config config.json >> weekly_workflow.log 2>&1
```

---

## Docker Deployment

### Dockerfile (Not Yet Created)

⚠️ **Note**: A Dockerfile has not yet been created for this project. To add Docker support, create a `Dockerfile` in the project root with the following content:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Mount points
VOLUME ["/app/exports", "/app/.cache"]

# Default command
CMD ["python", "run_automated.py", "--config", "config.json"]
```

### Build and Run (When Dockerfile is Created)

```bash
# Build image
docker build -t veracode-matcher:latest .

# Run with volume mounts
docker run -v $(pwd)/exports:/app/exports \
           -e VERACODE_API_KEY_ID=your_id \
           -e VERACODE_API_KEY_SECRET=your_secret \
           veracode-matcher:latest

# Run with custom config
docker run -v $(pwd)/config.json:/app/config.json \
           -v $(pwd)/exports:/app/exports \
           -e VERACODE_API_KEY_ID=your_id \
           -e VERACODE_API_KEY_SECRET=your_secret \
           veracode-matcher:latest
```

---

## Kubernetes Deployment

### ConfigMap (config.yaml) (Not Yet Created)

⚠️ **Note**: Kubernetes manifests have not yet been created. Examples below show the recommended structure:

### ConfigMap (config.yaml) Example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: veracode-matcher-config
data:
  config.json: |
    {
      "api": {"max_retries": 3},
      "export": {"output_dir": "/data/exports"}
    }
```

### Job (job.yaml) Example

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: veracode-matcher
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: matcher
            image: veracode-matcher:latest
            volumeMounts:
            - name: exports
              mountPath: /app/exports
            - name: config
              mountPath: /app/config.json
              subPath: config.json
            env:
            - name: VERACODE_API_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: veracode-creds
                  key: api_id
            - name: VERACODE_API_KEY_SECRET
              valueFrom:
                secretKeyRef:
                  name: veracode-creds
                  key: api_key
          volumes:
          - name: exports
            persistentVolumeClaim:
              claimName: matcher-exports-pvc
          - name: config
            configMap:
              name: veracode-matcher-config
          restartPolicy: OnFailure
```

---

## Monitoring and Logging

### Log Files

- `workflow.log` — Main workflow log
- `.cache/` — API cache and temporary files
- `exports/workflow_results.json` — Workflow execution results

### Metrics

```bash
# Check export sizes
du -sh exports/

# Recent workflow results
tail -50 exports/workflow_results.json | jq .

# Check failure rates
grep -c "Failed to" workflow.log
```

### Error Handling

The system automatically:
- Retries failed API calls (exponential backoff)
- Rate limits requests (0.5s minimum interval)
- Handles HTTP 429 (Too Many Requests)
- Logs all failures with context
- Continues processing on errors (graceful degradation)

---

## Performance Tuning

### API Configuration

```json
{
  "api": {
    "max_retries": 5,          // Increase for unstable networks
    "backoff_factor": 1.5,     // Decrease for faster retries
    "request_timeout": 60,     // Increase for large datasets
    "rate_limit_interval": 0.1 // Decrease for faster processing
  }
}
```

### Batch Processing

Process applications in batches to manage resources:

```bash
# Process 100 apps
python api_fetcher.py --limit 100

# Process in multiple runs
for i in {0..9}; do
  python api_fetcher.py --limit 10 --output ./exports/batch_$i
done
```

---

## Testing

### Unit Tests

```bash
python -m pytest test_*.py -v
```

### Integration Tests

```bash
python test_phase_6_integration.py
```

### Health Check

```bash
python api_fetcher.py --list-profiles  # Verify API access
```

---

## Troubleshooting

### Issue: Authentication Failed

```bash
# Check credentials
python api_fetcher.py --list-profiles

# Verify environment variables
echo $VERACODE_API_KEY_ID
```

### Issue: Rate Limit Errors

Increase `rate_limit_interval` in configuration:

```json
{
  "api": {
    "rate_limit_interval": 1.0
  }
}
```

### Issue: Timeout Errors

Increase `request_timeout`:

```json
{
  "api": {
    "request_timeout": 120
  }
}
```

### Issue: High Memory Usage

Reduce batch size or process fewer apps:

```bash
python api_fetcher.py --limit 5
```

---

## Security Considerations

1. **Store Credentials Securely**
   - Use environment variables (not in code)
   - Use secret management (Docker, Kubernetes)
   - Rotate API keys regularly

2. **Network Security**
   - Use HTTPS only (default for Veracode API)
   - Run behind VPN/firewall in production
   - Limit outbound connections

3. **Data Protection**
   - Export data to secure location
   - Encrypt sensitive files at rest
   - Implement access controls

4. **Audit Trail**
   - Enable detailed logging
   - Archive logs for compliance
   - Monitor for suspicious activity

---

## Support and Documentation

- [API_FETCHER_UPDATE_PLAN.md](API_FETCHER_UPDATE_PLAN.md) — Project scope
- [PHASE_6_EXECUTION_GUIDE.md](PHASE_6_EXECUTION_GUIDE.md) — Integration testing
- [PHASE_5_EXECUTION_GUIDE.md](PHASE_5_EXECUTION_GUIDE.md) — Error handling
- [config.py](config.py) — Configuration management
- [workflow.py](workflow.py) — Workflow orchestration

---

**Last Updated**: 2026-10-07  
**Version**: 1.0  
**Status**: Production Ready
