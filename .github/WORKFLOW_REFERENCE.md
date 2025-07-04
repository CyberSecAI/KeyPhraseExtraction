# GitHub Actions Workflow Reference

Quick reference for all automated workflows in the CVE Keyphrase Extraction system.

## 📋 Workflow Overview

| Workflow | Purpose | Trigger | Duration | Artifacts |
|----------|---------|---------|----------|-----------|
| **CVE Keyphrase Extraction** | Daily automated processing | Scheduled (2 AM UTC) | ~6 hours | Logs, invalid files, summary |
| **Manual CVE Processing** | On-demand processing control | Manual trigger | ~8 hours | Processing reports, logs |
| **Test Pipeline** | Code validation and testing | PR/Manual | ~10 minutes | Test results, sample outputs |

## 🔄 Daily Automated Processing

**File**: `.github/workflows/cve-keyphrase-extraction.yml`

### Triggers
- **Scheduled**: Daily at 2:00 AM UTC
- **Manual**: Workflow dispatch with options
- **Push**: On main branch for script changes

### Pipeline Steps
```mermaid
graph LR
    A[Checkout Repos] --> B[Setup Python]
    B --> C[Install Dependencies] 
    C --> D[Auth Google Cloud]
    D --> E[Extract Keyphrases]
    E --> F[Validate Quality]
    F --> G[Merge Files]
    G --> H[Organize to CVE Info]
    H --> I[Commit Changes]
    I --> J[Upload Artifacts]
```

### Success Indicators
- ✅ All pipeline steps complete
- 📊 Processing summary generated
- 🔄 Changes committed to cve_info repository
- 📋 Artifacts uploaded for review

### Failure Handling
- 🚨 Automatic GitHub issue creation
- 📋 Complete logs uploaded as artifacts
- 🔄 Safe to re-run after fixing issues

## 🎛️ Manual Processing Controls

**File**: `.github/workflows/manual-trigger.yml`

### Processing Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **incremental** | Process only new CVEs | Daily updates, normal operation |
| **full_reprocess** | Reprocess all CVEs from scratch | Model updates, data corrections |
| **validation_only** | Run quality checks only | Troubleshooting, data verification |
| **merge_only** | Skip extraction, merge existing | File organization, format updates |

### Manual Trigger Steps

1. **Navigate**: Go to Actions tab → "Manual CVE Processing"
2. **Configure**: Select processing mode and options
3. **Execute**: Click "Run workflow"
4. **Monitor**: Watch real-time progress in logs
5. **Review**: Download artifacts for detailed analysis

### Input Options

```yaml
processing_mode: [incremental, full_reprocess, validation_only, merge_only]
cve_data_source: "../cvelistV5_process/data_out/cve_records_published.csv"
max_cves: "0"  # 0 = no limit
log_level: [DEBUG, INFO, WARNING, ERROR]
```

## 🧪 Testing Pipeline

**File**: `.github/workflows/test-pipeline.yml`

### Test Levels

| Level | Scope | Triggers |
|-------|-------|----------|
| **Syntax Only** | Python syntax, imports, CLI | All PRs, default manual |
| **Small Batch** | End-to-end with sample data | Manual selection |
| **Full Validation** | Complete system validation | Manual selection |

### Test Components

**Syntax Tests**:
- Python file compilation
- Import validation  
- CLI interface testing

**Integration Tests**:
- Sample data processing
- Pipeline validation
- Output verification

**System Tests**:
- Configuration validation
- Directory structure
- Full workflow simulation

## 🔐 Required Secrets

| Secret | Purpose | Permissions |
|--------|---------|-------------|
| `GOOGLE_CLOUD_CREDENTIALS` | VertexAI API access | AI Platform User, Service Account Token Creator |
| `CVE_INFO_PAT` | CVE repository access | Contents: Read/Write, Metadata: Read |

## 📊 Monitoring and Artifacts

### Artifact Types

| Artifact | Contains | Retention |
|----------|----------|-----------|
| `processing-logs-{run}` | Complete processing logs | 30 days |
| `invalid-files-{run}` | Files that failed validation | 7 days |
| `manual-processing-{mode}-{run}` | Manual run reports | 30 days |
| `test-results-{run}` | Test outputs and reports | 7 days |

### Key Log Files

```
processing-logs-{run}/
├── logs/
│   ├── cve_processing.log          # Main extraction log
│   ├── cve_validation.log          # Quality control log
│   ├── merge_jsons2all.log         # Data consolidation log
│   ├── missing_keyphrases.txt      # Files needing processing
│   └── error_logs/
│       └── CVE-*_error.json        # Individual error details
├── failed_cves.txt                 # Failed CVE list
└── processing_summary.md           # Executive summary
```

## 🚨 Error Response Procedures

### Automatic Issue Creation

When workflows fail, automatic issues include:
- **Workflow details**: Run number, trigger, branch
- **Failure context**: Error logs, processing stage
- **Next steps**: Troubleshooting guidance
- **Artifact links**: Direct access to logs

### Manual Recovery Steps

1. **Review Issue**: Check auto-created issue for failure details
2. **Download Artifacts**: Get complete logs for analysis
3. **Identify Root Cause**: API issues, data problems, configuration
4. **Fix Issues**: Update configuration, resolve auth problems
5. **Re-run**: Use manual trigger to reprocess
6. **Monitor**: Verify successful completion

### Common Failure Patterns

| Error Type | Likely Cause | Solution |
|------------|--------------|----------|
| Authentication Failed | Invalid/expired credentials | Update `GOOGLE_CLOUD_CREDENTIALS` |
| Repository Access Denied | Invalid/expired PAT | Update `CVE_INFO_PAT` |
| Timeout/Resource Exhausted | API quota/rate limits | Wait and retry, check quotas |
| Processing Errors | Data format changes | Update column detection logic |

## ⚙️ Customization Options

### Schedule Modification

```yaml
# Daily at 2 AM UTC (default)
- cron: '0 2 * * *'

# Weekly on Monday at 2 AM UTC  
- cron: '0 2 * * 1'

# Monthly on 1st at 2 AM UTC
- cron: '0 2 1 * *'

# Multiple times per day
- cron: '0 2,14 * * *'  # 2 AM and 2 PM UTC
```

### Timeout Adjustment

```yaml
# Standard (6 hours)
timeout-minutes: 360

# Extended for large datasets
timeout-minutes: 480  # 8 hours

# Quick testing
timeout-minutes: 60   # 1 hour
```

### Repository Configuration

```yaml
# Update for different organization/repo names
repository: YourOrg/your-cve-info-repo
repository: YourOrg/your-data-source-repo
```

## 📈 Performance Optimization

### Workflow Efficiency

- **Parallel Steps**: Independent operations run concurrently
- **Caching**: Python dependencies cached between runs
- **Incremental Processing**: Only new CVEs processed by default
- **Artifact Optimization**: Selective upload of relevant files

### Resource Management

- **Runner Selection**: Standard GitHub-hosted runners
- **Memory Usage**: Optimized for large CSV processing
- **Storage**: Efficient artifact compression and retention
- **API Usage**: Intelligent rate limiting and backoff

### Scaling Considerations

- **Large Datasets**: Increase timeout for >50k CVEs
- **High Frequency**: Consider self-hosted runners
- **Multi-Region**: Deploy to multiple Google Cloud regions
- **Cost Control**: Monitor GitHub Actions and Google Cloud usage

## 🔍 Debugging Guide

### Real-time Monitoring

1. **Actions Tab**: Live workflow status and logs
2. **Step Details**: Expand each step for detailed output
3. **Artifact Preview**: Quick access to key files
4. **Re-run Options**: Restart failed jobs or entire workflow

### Log Analysis Priority

1. **Processing Summary**: Start with high-level statistics
2. **Main Logs**: Check cve_processing.log for overall flow
3. **Error Logs**: Review individual CVE failures
4. **Validation Logs**: Check data quality issues
5. **Raw Artifacts**: Deep dive into specific problems

### Performance Debugging

```bash
# Check processing rates
grep "Progress:" logs/cve_processing.log

# Identify slow operations  
grep "took.*seconds" logs/*.log

# Find API issues
grep -E "(timeout|rate limit|quota)" logs/*.log

# Check success/failure ratios
grep -E "(successful|failed)" logs/cve_processing.log | tail -10
```