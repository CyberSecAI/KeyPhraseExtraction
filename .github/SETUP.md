# GitHub Actions Setup Guide

This guide explains how to set up the automated CVE keyphrase extraction pipeline using GitHub Actions.

## Prerequisites

1. **Repository Structure**: Ensure you have the following repositories at the same organization level:
   - `KeyPhraseExtraction` (this repository)
   - `cve_info` (target repository for processed CVEs)
   - `cvelistV5_process` (data source repository)

2. **Google Cloud Access**: A Google Cloud project with VertexAI API enabled and appropriate credentials

## Required Secrets

### 1. Google Cloud Credentials

Create a service account with the following permissions:
- **Vertex AI User** (`roles/aiplatform.user`)
- **Service Account Token Creator** (`roles/iam.serviceAccountTokenCreator`)

```bash
# Create service account
gcloud iam service-accounts create github-actions-cve \
  --description="GitHub Actions for CVE processing" \
  --display-name="GitHub Actions CVE"

# Get the service account email
SA_EMAIL=$(gcloud iam service-accounts list \
  --filter="displayName:GitHub Actions CVE" \
  --format="value(email)")

# Grant necessary roles
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/aiplatform.user"

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/iam.serviceAccountTokenCreator"

# Create and download key
gcloud iam service-accounts keys create github-actions-key.json \
  --iam-account=$SA_EMAIL
```

Add the contents of `github-actions-key.json` as a repository secret named `GOOGLE_CLOUD_CREDENTIALS`.

### 2. Personal Access Token

Create a Personal Access Token (PAT) with the following permissions:
- **Contents**: Read and Write (to access and modify cve_info repository)
- **Metadata**: Read
- **Pull requests**: Read (if needed)

Add this token as a repository secret named `CVE_INFO_PAT`.

## Repository Secrets Setup

In your GitHub repository, go to **Settings** → **Secrets and variables** → **Actions** and add:

| Secret Name | Description | Value |
|-------------|-------------|-------|
| `GOOGLE_CLOUD_CREDENTIALS` | Google Cloud service account JSON | Full JSON content from service account key |
| `CVE_INFO_PAT` | Personal Access Token for cve_info repository | ghp_... token |

## Configuration

### 1. Update config.py

Ensure your `config.py` has the correct Google Cloud configuration:

```python
GOOGLE_CLOUD_CONFIG = {
    "project_id": "your-project-id",
    "location": "europe-west4"  # or your preferred region
}

MAIN_MODEL_CONFIG = {
    "model_endpoint": "projects/your-project/locations/europe-west4/endpoints/your-endpoint-id",
    "model_type": "vertexai",
    # ... other config
}
```

### 2. Workflow Customization

Edit `.github/workflows/cve-keyphrase-extraction.yml` to customize:

**Schedule**: Change the cron expression for different timing
```yaml
schedule:
  - cron: '0 2 * * *'  # Daily at 2 AM UTC
  # - cron: '0 2 * * 1'  # Weekly on Monday at 2 AM UTC
  # - cron: '0 2 1 * *'  # Monthly on 1st at 2 AM UTC
```

**Timeout**: Adjust based on your expected processing time
```yaml
timeout-minutes: 360  # 6 hours (adjust as needed)
```

**Repository Names**: Update if your repositories have different names
```yaml
- name: Checkout CVE info repository
  uses: actions/checkout@v4
  with:
    repository: YourOrg/your-cve-info-repo  # Update this
    token: ${{ secrets.CVE_INFO_PAT }}
    path: cve_info
```

## Workflow Features

### 1. Automatic Daily Processing (`cve-keyphrase-extraction.yml`)

- **Runs daily** at 2 AM UTC
- **Full pipeline** execution (extract → validate → merge → organize)
- **Automatic commits** to cve_info repository
- **Error notifications** via GitHub issues
- **Artifact uploads** for logs and invalid files

### 2. Manual Processing (`manual-trigger.yml`)

Trigger via GitHub UI with options:
- **Incremental**: Process only new CVEs (default)
- **Full reprocess**: Reprocess all CVEs
- **Validation only**: Run validation checks only
- **Merge only**: Skip extraction, only merge existing files

### Manual Trigger Usage

1. Go to **Actions** tab in your repository
2. Select **"Manual CVE Processing"**
3. Click **"Run workflow"**
4. Choose your options:
   - **Processing mode**: incremental/full_reprocess/validation_only/merge_only
   - **CVE data source**: Path to CSV file (optional)
   - **Max CVEs**: Limit processing (0 = no limit)
   - **Log level**: DEBUG/INFO/WARNING/ERROR

## Monitoring and Maintenance

### 1. Workflow Status

Monitor workflow status in the **Actions** tab. Each run provides:
- **Real-time logs** during execution
- **Processing summary** with statistics
- **Artifact downloads** for detailed logs
- **Automatic issue creation** on failures

### 2. Log Analysis

Download artifacts to analyze:
- `processing-logs-{run-number}`: Complete logs from all scripts
- `invalid-files-{run-number}`: Files that failed validation
- `manual-processing-{mode}-{run-number}`: Manual run details

### 3. Error Handling

The workflow automatically handles:
- **API timeouts**: 5-minute timeout per API call
- **Rate limiting**: Automatic backoff and retry
- **Authentication issues**: Clear error messages
- **Data validation**: Invalid files moved to separate directory

### 4. Success Indicators

A successful run includes:
- ✅ All pipeline steps completed
- 📊 Processing summary generated
- 🔄 Changes committed to cve_info repository
- 📋 Artifacts uploaded for review

## Troubleshooting

### Common Issues

**1. Authentication Failures**
```yaml
Error: Failed to authenticate to Google Cloud
```
- Verify `GOOGLE_CLOUD_CREDENTIALS` secret is correctly set
- Check service account has required permissions
- Ensure VertexAI API is enabled in your project

**2. Repository Access Issues**
```yaml
Error: Repository not found or access denied
```
- Verify `CVE_INFO_PAT` token has correct permissions
- Check repository names in workflow file
- Ensure token hasn't expired

**3. Processing Timeouts**
```yaml
Error: The job was canceled because it exceeded the maximum execution time
```
- Increase `timeout-minutes` in workflow file
- Use manual trigger with smaller batch sizes
- Check for API issues or network problems

**4. Quota Exceeded**
```yaml
Error: 429 Resource has been exhausted
```
- Workflow automatically handles this with 1-hour sleep
- Consider upgrading Google Cloud quotas
- Use manual processing with smaller batches

### Debug Mode

Enable debug logging by:
1. Using manual trigger with **Log Level**: DEBUG
2. Checking detailed logs in artifacts
3. Reviewing individual error files in `error_logs/`

### Manual Recovery

If automatic processing fails:
1. Check the generated GitHub issue for details
2. Download processing logs from artifacts
3. Use manual trigger to reprocess specific portions
4. Fix any data or configuration issues
5. Re-run the workflow

## Best Practices

### 1. Regular Monitoring
- Check workflow status weekly
- Review processing statistics for trends
- Monitor Google Cloud quotas and usage

### 2. Configuration Management
- Keep `config.py` updated with latest model endpoints
- Test configuration changes with manual triggers
- Document any custom modifications

### 3. Error Response
- Address GitHub issues promptly
- Analyze error patterns in artifacts
- Update workflow configuration based on learnings

### 4. Resource Management
- Monitor Google Cloud costs and quotas
- Adjust processing frequency based on data volume
- Use appropriate instance types for workflow runners

## Security Considerations

### 1. Secret Management
- Rotate service account keys regularly
- Use minimal required permissions
- Monitor access logs in Google Cloud

### 2. Repository Access
- Use dedicated PAT for automation
- Regularly review repository permissions
- Enable branch protection on target repositories

### 3. Workflow Security
- Pin action versions to specific tags
- Review and audit workflow changes
- Monitor for unauthorized workflow modifications

## Cost Optimization

### 1. Processing Efficiency
- Use incremental processing (default)
- Adjust processing frequency based on data updates
- Monitor API usage and costs

### 2. GitHub Actions
- Use appropriate runner types
- Optimize artifact retention periods
- Consider self-hosted runners for large-scale processing

### 3. Google Cloud
- Monitor VertexAI API usage
- Use appropriate model configurations
- Consider regional deployment for cost optimization