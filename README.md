# CVE Keyphrase Extraction

A comprehensive Python-based system for processing CVE (Common Vulnerabilities and Exposures) descriptions to extract structured keyphrases using AI models. This project provides a complete pipeline from raw CVE data to structured, validated output with professional error handling, logging, and quality control.

## Features

- 🤖 **Dual AI API Support**: VertexAI (fine-tuned models) with automatic fallback to standard Gemini models
- 📊 **Intelligent Column Detection**: Automatically identifies CVE ID and description columns in various data formats
- 🔄 **Robust Processing Pipeline**: Multi-stage processing with retry logic, timeout handling, and error recovery
- 🎯 **Automatic Quality Enhancement**: Real-time detection and improvement of insufficient keyphrases (0-1 fields)
- 🔧 **Smart Enhancement Prompts**: Context-aware prompts that review and improve existing keyphrases rather than extracting from scratch
- 📝 **Comprehensive Logging**: Structured logging with detailed error tracking and performance monitoring
- 🏗️ **Professional Python Architecture**: Object-oriented design with full command-line interfaces
- 🛡️ **Advanced Data Validation**: JSON validation, duplicate detection, empty/single keyphrase detection, and quality control
- ⚙️ **Flexible Configuration**: Centralized configuration with support for multiple models and custom parameters
- 🧹 **Automated Cleanup**: Smart filtering of empty, invalid, and orphaned files
- 📊 **Progress Tracking**: Real-time progress reporting with comprehensive statistics

## Prerequisites

- Python 3.12+
- Git
- Google AI credentials (API key or VertexAI authentication)
- Required Python packages (see `requirements.txt`)

## Setup

### 1. Environment Setup

```bash
# Clone the repository
git clone <repository-url>
cd KeyPhraseExtraction

# Create and activate virtual environment
python -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Required Repositories

Clone the related CVE info repository at the same directory level:
```bash
cd ..
git clone https://github.com/CyberSecAI/cve_info
cd KeyPhraseExtraction
```

### 3. Data Sources

The scripts automatically detect and work with CVE data from:
- **Primary**: `../cvelistV5_process/data_out/cve_records_published.csv` (latest published CVEs)
- **Legacy**: `../nvd_cve_data/data_out/CVSSData.csv.gz` (fallback source)

### 4. Authentication

#### For VertexAI (Recommended)
```bash
# Set up Google Cloud authentication
gcloud auth application-default login
```

#### For Standard Gemini API
Set your API key in `config.py` or as an environment variable.

## GitHub Actions Automation

[![CVE Keyphrase Extraction](https://github.com/CyberSecAI/KeyPhraseExtraction/actions/workflows/cve-keyphrase-extraction.yml/badge.svg)](https://github.com/CyberSecAI/KeyPhraseExtraction/actions/workflows/cve-keyphrase-extraction.yml)

The system includes comprehensive GitHub Actions workflows for automated processing:

### 🔄 Automated Daily Processing

**Workflow**: `.github/workflows/cve-keyphrase-extraction.yml`
- **Schedule**: Daily at 2 AM UTC
- **Full Pipeline**: Extract → Validate → Merge → Organize
- **Auto-commit**: Changes pushed to CVE info repository
- **Error Handling**: Automatic issue creation on failures
- **Artifacts**: Processing logs and invalid files uploaded

### 🎛️ Manual Processing Controls

**Workflow**: `.github/workflows/manual-trigger.yml`
- **Incremental**: Process only new CVEs (default)
- **Full Reprocess**: Reprocess all CVEs from scratch
- **Validation Only**: Run quality control checks
- **Merge Only**: Skip extraction, only merge existing files

### 🧪 Testing Pipeline

**Workflow**: `.github/workflows/test-pipeline.yml`
- **Syntax Validation**: Python syntax and import testing
- **Small Batch**: End-to-end testing with sample data
- **Full Validation**: Comprehensive configuration and structure testing

### Setup Instructions

See [`.github/SETUP.md`](.github/SETUP.md) for complete setup instructions including:
- Required secrets configuration (Google Cloud credentials, PAT tokens)
- Service account setup with proper permissions
- Workflow customization options
- Monitoring and troubleshooting guides

## Usage

### Automated Processing (Recommended)

1. **Setup GitHub Actions** (one-time):
   ```bash
   # Follow instructions in .github/SETUP.md
   # Configure Google Cloud credentials
   # Set up repository secrets
   ```

2. **Monitor Automated Runs**:
   - Check **Actions** tab for daily processing status
   - Review artifacts for detailed logs and statistics
   - Address any auto-generated issues for failures

3. **Manual Control When Needed**:
   - Navigate to **Actions** → **Manual CVE Processing**
   - Choose processing mode and options
   - Monitor progress in real-time

### Complete Processing Workflow (Local)

Run the scripts in sequence for full processing:

```bash
# 1. Extract keyphrases from CVE descriptions
python keyphraseExtract.py

# 2. Validate and check for quality issues
python keyphraseExtract_check.py

# 3. Merge descriptions and keyphrases into final format
python merge_jsons2all.py

# 4. Move processed files to CVE info repository
python move2cve_dir_hash.py
```

### Individual Script Usage

#### 1. Main Keyphrase Extraction (`keyphraseExtract.py`)

**Purpose**: Extracts structured keyphrases from CVE descriptions using AI models.

```bash
# Run with default settings
python keyphraseExtract.py

# Use custom data source
python keyphraseExtract.py --cve-data-path /path/to/your/cve_data.csv

# Use custom CVE info directory
python keyphraseExtract.py --cve-info-dir /path/to/cve_info

# Reprocess existing files with insufficient keyphrases (0 or 1 fields)
python keyphraseExtract.py --reprocess-insufficient

# Get help and see all options
python keyphraseExtract.py --help
```

**Features**:
- Loads existing processed CVEs from `../cve_info`
- Intelligent column detection for various CSV formats
- Filters out already processed CVEs for efficiency
- Cleans and normalizes CVE descriptions
- Uses fine-tuned VertexAI model with automatic fallback
- **Automatic Quality Enhancement**: Detects insufficient keyphrases (0-1 fields) and automatically retries with enhancement prompts
- **Smart Enhancement Prompts**: Uses context-aware prompts that review existing keyphrases and improve them
- **Reprocessing Mode**: `--reprocess-insufficient` flag to improve existing files with poor keyphrase quality
- 5-minute timeout protection for hanging API calls
- Comprehensive retry logic with exponential backoff
- Saves extracted keyphrases to `CVEs/keyphrases/`

#### 2. Quality Control and Validation (`keyphraseExtract_check.py`)

**Purpose**: Validates generated JSON files and identifies missing keyphrases in the CVE repository.

```bash
# Run full validation and missing keyphrases check
python keyphraseExtract_check.py

# Use custom directories
python keyphraseExtract_check.py --input-dir ./custom/keyphrases --cve-info-dir ./custom/cve_info

# Skip validation, only check for missing keyphrases
python keyphraseExtract_check.py --skip-validation

# Skip missing check, only validate files
python keyphraseExtract_check.py --skip-missing-check

# Get help and see all options
python keyphraseExtract_check.py --help
```

**Features**:
- Validates JSON structure and required keyphrase fields
- **Empty Keyphrase Detection**: Identifies files where all keyphrase fields are empty
- **Single Keyphrase Detection**: Identifies files with only one non-empty keyphrase field
- Detects and moves invalid files to `CVEs/invalid/`
- Identifies duplicate content using MD5 hashing
- Searches entire CVE repository for missing keyphrases sections
- Generates comprehensive validation reports including separate reports for empty and single keyphrase files
- Outputs results to `logs/` directory (`empty_keyphrases.txt`, `single_keyphrases.txt`)

#### 3. Data Consolidation (`merge_jsons2all.py`)

**Purpose**: Merges descriptions, keyphrases, and technical impacts into consolidated JSON files.

```bash
# Run with default settings
python merge_jsons2all.py

# Use custom directories and version
python merge_jsons2all.py --base-dir ./data --output-dir ./merged --version 1.1.0

# Enable debug logging
python merge_jsons2all.py --log-level DEBUG

# Get help and see all options
python merge_jsons2all.py --help
```

**Features**:
- Combines data from `CVEs/description/`, `CVEs/keyphrases/`, and `CVEs/technical_impacts/`
- Normalizes field names to camelCase conventions (cveId, mitreTechnicalImpacts)
- Validates impact text consistency between sources
- Merges component-prefixed fields intelligently
- Adds metadata (version, timestamp) to all outputs
- Only processes CVEs that have keyphrases (more efficient)
- Creates consolidated files in `CVEs/all/`
- Generates detailed validation error logs

#### 4. File Organization (`move2cve_dir_hash.py`)

**Purpose**: Organizes processed files into the CVE info repository with deduplication.

```bash
# Run file organization
python move2cve_dir_hash.py

# Get help and see options
python move2cve_dir_hash.py --help
```

**Features**:
- Moves files from `CVEs/all/` to appropriate subdirectories in `../cve_info`
- Organizes by CVE year and number ranges (e.g., `2024/1xxx/`)
- Uses SHA-256 hashing to prevent duplicates
- Provides detailed operation statistics
- Maintains proper directory structure

### Utility Scripts

```bash
# Convert Jupyter notebooks to Python scripts (if needed)
python notebook2python.py
```

## Configuration

Edit `config.py` to customize model settings:

```python
# Main VertexAI Configuration (Primary)
MAIN_MODEL_CONFIG = {
    "model_endpoint": "projects/your-project/locations/europe-west4/endpoints/123456",
    "model_type": "vertexai",
    "temperature": 1,
    "top_p": 0.95,
    "max_output_tokens": 8192
}

# Fallback Gemini Configuration
FALLBACK_MODEL_CONFIG = {
    "model_name": "gemini-2.0-flash-exp",
    "model_type": "standard", 
    "temperature": 1,
    "response_mime_type": "application/json"
}

# Google Cloud Settings
GOOGLE_CLOUD_CONFIG = {
    "project_id": "your-project-id",
    "location": "europe-west4"
}
```

## Project Structure

```
.
├── keyphraseExtract.py          # Main keyphrase extraction script
├── keyphraseExtract_check.py    # Quality control and validation
├── merge_jsons2all.py           # Data consolidation script  
├── move2cve_dir_hash.py         # File organization and deduplication
├── config.py                    # Model and API configuration
├── notebook2python.py          # Utility to convert notebooks to scripts
├── requirements.txt             # Python dependencies
├── CLAUDE.md                    # Development guidance for Claude Code
├── README.md                    # This documentation file
├── .gitignore                   # Git ignore patterns
│
├── CVEs/                        # Processing outputs (gitignored)
│   ├── description/            # Extracted CVE descriptions  
│   ├── keyphrases/            # AI-generated keyphrases
│   ├── all/                   # Merged JSON files
│   └── invalid/               # Failed validation files
│
├── logs/                       # Logging directory (gitignored)
│   ├── cve_processing.log         # Main processing log
│   ├── cve_validation.log         # Validation process log
│   ├── merge_jsons2all.log        # Merging process log
│   ├── keyphrases_already.csv     # Processing status tracking
│   ├── missing_keyphrases.txt     # Quality control output
│   ├── impact_validation_errors.log # Data consistency issues
│   ├── cve_keyphrases_validation.csv # Validation summary
│   ├── invalid_cve_keyphrases.csv    # Invalid files report
│   └── error_logs/                   # Individual error details
│       └── CVE-*_error.json
│
├── tmp/                        # Temporary files (gitignored)
│   └── *.csv                   # Temporary analysis files
│
└── *.ipynb                     # Legacy Jupyter notebooks (if any)
```

## Keyphrase Quality Enhancement System

The system includes an advanced quality enhancement feature that automatically detects and improves insufficient keyphrase extraction results in real-time.

### How Quality Enhancement Works

#### 1. **Real-Time Quality Assessment**
- Every extracted keyphrase result is immediately analyzed using `check_keyphrase_quality()`
- Counts non-empty keyphrase fields across all 8 categories: `rootcause`, `weakness`, `impact`, `vector`, `attacker`, `product`, `version`, `component`
- Flags results with ≤1 non-empty fields as "insufficient" and needing enhancement

#### 2. **Automatic Enhancement Trigger**
When the primary model produces insufficient results (0 or 1 keyphrases):
```python
# Primary extraction result: {"rootcause": "", "weakness": "SQL injection", "impact": "", ...}
# System detects: only 1 keyphrase field filled
# Automatically triggers enhancement process
```

#### 3. **Context-Aware Enhancement Prompts**
The enhancement process uses a fundamentally different approach than initial extraction:

**Initial Extraction Prompt:**
```
<INSTRUCTION>Only use these json fields:rootcause, weakness, impact, vector, attacker, product, version, component</INSTRUCTION>
[CVE Description]
```

**Enhancement Prompt:**
```
<INSTRUCTION>
You are tasked with REVIEWING and ENHANCING existing keyphrases for a CVE description.

EXISTING KEYPHRASES:
{
  "rootcause": "",
  "weakness": "SQL injection",
  "impact": "",
  "vector": "",
  "attacker": "",
  "product": "",
  "version": "",
  "component": ""
}

CVE DESCRIPTION:
[Original vulnerability description]

Your job is to:
1. Review the existing keyphrases below against the CVE description
2. Add any missing keyphrases that can be extracted from the description
3. Correct any incorrect or incomplete keyphrases
4. Ensure all relevant fields are populated when information is available
</INSTRUCTION>
```

#### 4. **Smart Result Selection**
- Compares original result (e.g., 1 keyphrase) with enhanced result (e.g., 4 keyphrases)
- Automatically selects the better result (more non-empty fields)
- Saves the improved version immediately

### Quality Enhancement Features

#### **Automatic Processing Mode** (Default)
- Runs during normal `keyphraseExtract.py` execution
- No additional commands needed
- Real-time enhancement for every insufficient result
- Transparent logging shows when enhancement is triggered

#### **Reprocessing Mode** 
```bash
# Improve existing files with poor keyphrase quality
python keyphraseExtract.py --reprocess-insufficient
```
- Scans all existing keyphrase files
- Identifies files with 0 or 1 keyphrases
- Applies enhancement prompts to improve them
- Only overwrites files if enhancement actually improves the result

### Example Enhancement Flow

**Before Enhancement:**
```json
{
  "rootcause": "",
  "weakness": "SQL injection",
  "impact": "",
  "vector": "",
  "attacker": "",
  "product": "",
  "version": "",
  "component": ""
}
```

**After Enhancement:**
```json
{
  "rootcause": "improper input validation",
  "weakness": "SQL injection",
  "impact": "execute arbitrary SQL commands",
  "vector": "web application",
  "attacker": "remote authenticated attacker",
  "product": "MyApp",
  "version": "version 2.1",
  "component": "admin panel"
}
```

### Benefits

1. **Immediate Quality Improvement**: Issues are detected and fixed during initial processing
2. **Context-Aware Enhancement**: Model sees existing work and builds upon it rather than starting from scratch
3. **No Data Loss**: Preserves good existing keyphrases while adding missing ones
4. **Transparent Process**: Clear logging shows exactly when and how enhancement occurs
5. **Efficiency**: Only triggers enhancement when actually needed (insufficient results)

## Processing Pipeline

The system follows a 4-stage pipeline with professional Python scripts:

### 1. Keyphrase Extraction (`keyphraseExtract.py`)

**CVEProcessor Class Architecture**:
- Object-oriented design with comprehensive error handling
- Intelligent data source detection and column mapping
- Dual API support with automatic fallback mechanisms
- **Real-time Quality Assessment**: `check_keyphrase_quality()` method analyzes extracted keyphrases immediately
- **Automatic Enhancement**: Triggers enhancement prompts when primary model produces insufficient results
- **Context-Aware Enhancement**: Uses `create_enhancement_prompt()` to show existing keyphrases and request improvements
- Timeout protection (5-minute limit per API call)
- Enhanced retry logic for connection issues, server errors, and rate limits
- Progress tracking with detailed statistics including keyphrase quality metrics

**Key Features**:
- Filters invalid descriptions (empty, "DO NOT USE", duplicates)
- Cleans Linux kernel debug traces automatically
- Saves individual description files for transparency
- Comprehensive logging with error isolation
- Performance optimization with efficient DataFrame operations

### 2. Quality Control (`keyphraseExtract_check.py`)

**CVEKeyphraseValidator & CVEKeyphraseChecker Classes**:
- Professional validation with comprehensive checks
- **Quality-Based Classification**: Uses same `check_keyphrase_quality()` logic as main extractor
- **Empty Keyphrase Detection**: Identifies files where all 8 keyphrase fields are empty
- **Single Keyphrase Detection**: Identifies files with only 1 non-empty keyphrase field
- Duplicate detection using MD5 content hashing
- Missing keyphrases identification across entire repository
- Invalid file isolation and detailed error reporting

**Validation Features**:
- JSON structure validation
- Required field verification
- **Keyphrase Quality Assessment**: Counts non-empty fields and flags insufficient content
- Content consistency checks
- Automated file organization (moves invalid files)
- **Separate Quality Reports**: Creates `empty_keyphrases.txt` and `single_keyphrases.txt`
- Comprehensive reporting system with quality statistics

### 3. Data Consolidation (`merge_jsons2all.py`)

**CVEDataMerger Class Architecture**:
- Multi-source data merging with validation
- camelCase field normalization (cveId, mitreTechnicalImpacts)
- Component field intelligent merging
- Impact consistency validation between sources
- UTF-8 encoding support with proper character handling

**Consolidation Features**:
- Only processes CVEs with keyphrases (efficiency)
- Validates data consistency across sources
- Generates comprehensive error logs
- Adds metadata (version, timestamp)
- Professional logging with statistics tracking

### 4. File Organization (`move2cve_dir_hash.py`)

**Features**:
- SHA-256 based deduplication
- Organized directory structure by year/number ranges
- Comprehensive operation statistics
- Duplicate handling with detailed reporting

## Output Format

The final consolidated JSON follows this standardized structure:

```json
{
    "cveId": "CVE-YYYY-XXXXX",
    "version": "1.0.0", 
    "timestamp": "2025-07-04T12:00:00.000000+00:00",
    "description": "CVE description text",
    "keyphrases": {
        "rootcause": "buffer overflow",
        "weakness": "improper input validation", 
        "impact": "arbitrary code execution",
        "vector": "network",
        "attacker": "remote unauthenticated attacker",
        "product": "Example Software",
        "version": "1.0 to 2.5",
        "component": "authentication module"
    },
    "mitreTechnicalImpacts": []
}
```

## Logging and Monitoring

### Comprehensive Logging System

| Log File | Purpose | Script | Location |
|----------|---------|--------|----------|
| `cve_processing.log` | Main keyphrase extraction activity | `keyphraseExtract.py` | `logs/` |
| `cve_validation.log` | Validation and quality control | `keyphraseExtract_check.py` | `logs/` |
| `merge_jsons2all.log` | Data consolidation process | `merge_jsons2all.py` | `logs/` |
| `CVE-*_error.json` | Individual error details | `keyphraseExtract.py` | `logs/error_logs/` |
| `keyphrases_already.csv` | Processing status tracking | `keyphraseExtract.py` | `logs/` |
| `missing_keyphrases.txt` | Files needing keyphrases | `keyphraseExtract_check.py` | `logs/` |
| `empty_keyphrases.txt` | Files with all empty keyphrase fields | `keyphraseExtract_check.py` | `logs/` |
| `single_keyphrases.txt` | Files with only 1 non-empty keyphrase field | `keyphraseExtract_check.py` | `logs/` |
| `impact_validation_errors.log` | Data consistency issues | `merge_jsons2all.py` | `CVEs/all/` |
| `failed_cves.txt` | Failed CVE processing list | `keyphraseExtract.py` | Root directory |

### Log Content Examples

**Main Processing Log (`logs/cve_processing.log`):**
```
2025-07-04 12:00:00,123 - INFO - Using new VertexAI API
2025-07-04 12:00:01,456 - INFO - Found 24807 new CVEs to process
2025-07-04 12:00:05,789 - INFO - CVE-2024-45774: Primary model produced 1 keyphrases. Retrying with fallback model for enhancement.
2025-07-04 12:00:08,012 - INFO - CVE-2024-45774: Fallback enhancement produced 4 keyphrases (improved from 1)
2025-07-04 12:00:08,345 - INFO - Processed CVE-2024-45774 (4 keyphrases: rootcause, weakness, impact, product)
2025-07-04 12:00:12,678 - WARNING - Connection/timeout error: API call timed out. Sleeping for 30 seconds...
2025-07-04 12:00:45,234 - INFO - Progress: 100/24807 CVEs processed (98 successful, 95 via primary, 3 via fallback)
```

**Quality Control Log (`logs/cve_validation.log`):**
```
2025-07-04 12:30:00,123 - INFO - Starting keyphrase file validation
2025-07-04 12:30:01,456 - INFO - Found 122 keyphrase files to validate
2025-07-04 12:30:02,789 - INFO - Validation Summary: 110 valid, 12 invalid files
2025-07-04 12:30:02,890 - INFO - Zero-byte files: 0, Empty keyphrase files: 3, Single keyphrase files: 9
2025-07-04 12:30:03,123 - INFO - Empty keyphrase files report saved to logs/empty_keyphrases.txt
2025-07-04 12:30:03,234 - INFO - Single keyphrase files report saved to logs/single_keyphrases.txt
2025-07-04 12:30:05,012 - INFO - Found 15 files missing keyphrases section
```

**Data Merging Log (`logs/merge_jsons2all.log`):**
```
2025-07-04 13:00:00,123 - INFO - Starting CVE file merging process
2025-07-04 13:00:01,456 - INFO - Found 122 CVEs with keyphrases files
2025-07-04 13:00:02,789 - INFO - Processing description files...
2025-07-04 13:00:05,012 - INFO - Validating impact consistency...
2025-07-04 13:00:06,234 - INFO - Successfully processed: 122 CVEs
```

## Error Handling and Recovery

### Advanced Error Management

**API Error Handling**:
- **Rate Limiting**: Automatic 1-hour sleep on quota exhaustion
- **Timeouts**: 5-minute timeout per API call with signal-based interruption
- **Connection Issues**: 30-second sleep and retry for network problems
- **Server Errors** (5xx): 60-second sleep and retry for service issues
- **Fallback Strategy**: Automatic switch to secondary model after primary failure

**Data Error Handling**:
- **Invalid JSON**: Detailed error logging with raw response capture
- **Missing Fields**: Automatic field completion with empty values
- **Malformed Data**: Graceful handling with comprehensive error reporting
- **File Issues**: Automatic directory creation and permission handling

**Recovery Mechanisms**:
- **Progress Persistence**: Resume from interruptions automatically
- **Incremental Processing**: Only processes new CVEs, skips already completed
- **Error Isolation**: Individual CVE failures don't stop batch processing
- **Comprehensive Logging**: Full context for debugging and recovery

## Performance and Scalability

### Optimization Features

- **Efficient Data Operations**: Optimized pandas operations for large datasets
- **Memory Management**: Streaming processing to handle large CSV files
- **Incremental Updates**: Only processes new CVEs, maintains processing state
- **Parallel File Operations**: Multi-threaded file reading where appropriate
- **Smart Filtering**: Early filtering of invalid descriptions saves API calls
- **Progress Tracking**: Real-time progress reporting with ETA estimation

### Scalability Considerations

- **API Rate Management**: Handles quotas and implements backoff strategies
- **Resource Monitoring**: Tracks API usage (primary vs fallback models)
- **Batch Processing**: Efficient handling of large CVE datasets
- **Storage Optimization**: Organized file structure prevents directory bloat

## Data Sources and Compatibility

### Supported Input Formats

The scripts automatically detect column names for various data sources:

| Data Source | CVE Column | Description Column | Format | Compression |
|-------------|------------|-------------------|---------|-------------|
| cvelistV5_process | `cve_id` | `description` | CSV | None |
| nvd_cve_data | `CVE` | `Description` | CSV | GZIP |
| Custom formats | Auto-detected | Auto-detected | CSV/CSV.GZ | Auto-detected |

### Intelligent Column Detection

**CVE ID Detection**: Searches for columns named `cve`, `cveid`, `cve_id`, `id`, `identifier` or columns containing CVE-format values (CVE-YYYY-NNNNN).

**Description Detection**: Looks for `description`, `desc`, `summary`, `text`, `details` or automatically selects the column with the longest average text length.

**Additional Fields**: Automatically detects and handles `state`, `rejected_reason` fields for CVE status information.

## Development and Architecture

### Code Quality Standards

**Object-Oriented Design**:
- Professional class architecture (`CVEProcessor`, `CVEKeyphraseValidator`, `CVEDataMerger`)
- Clear separation of concerns with modular methods
- Comprehensive type hints throughout all codebases
- Detailed docstrings following Google style guide

**Error Handling**:
- Exception hierarchy with specific error types
- Comprehensive logging at all levels
- Graceful degradation and recovery mechanisms
- Detailed error context preservation

**Testing and Validation**:
- Input validation for all user parameters
- Data consistency checks at multiple levels
- JSON schema validation and structure verification
- Comprehensive file integrity checks

### Script Dependencies and Data Flow

```
Raw CVE Data (CSV) 
    ↓
[keyphraseExtract.py] → CVEs/description/ + CVEs/keyphrases/
    ↓
[keyphraseExtract_check.py] → Validation reports + CVEs/invalid/
    ↓  
[merge_jsons2all.py] → CVEs/all/
    ↓
[move2cve_dir_hash.py] → ../cve_info/ (organized structure)
```

**Dependency Requirements**:
1. `keyphraseExtract.py` must run first to create keyphrases
2. `keyphraseExtract_check.py` validates and reports issues
3. `merge_jsons2all.py` requires both descriptions and keyphrases
4. `move2cve_dir_hash.py` requires merged files from step 3

## Troubleshooting

### Common Issues and Solutions

**1. Script Hanging During Processing**
```bash
# The script now has 5-minute timeout protection
# If hanging persists, check logs for:
tail -f logs/cve_processing.log

# Look for timeout or connection errors
# Script will automatically retry with backoff
```

**2. Column Detection Failures**
```bash
# Check available columns in your data file
python -c "import pandas as pd; print(pd.read_csv('path/to/data.csv', nrows=1).columns.tolist())"

# The script will show detected columns in logs:
# "Detected columns - CVE ID: 'cve_id', Description: 'description'"
```

**3. API Authentication Issues**
```bash
# Verify VertexAI authentication
gcloud auth application-default print-access-token

# Check if credentials are properly configured
gcloud config list

# Test API access
gcloud ai models list --region=europe-west4
```

**4. No CVEs with Keyphrases Found**
```bash
# Ensure keyphraseExtract.py ran successfully first
python keyphraseExtract.py

# Check if keyphrase files were created
ls -la CVEs/keyphrases/

# Verify log files for processing status
tail logs/cve_processing.log
```

**5. Missing Input Directories**
```bash
# Scripts automatically create required directories
# But you can create them manually if needed:
mkdir -p CVEs/description CVEs/keyphrases CVEs/all CVEs/invalid logs
```

**6. Empty or Invalid Files**
```bash
# Run quality control to identify and clean up issues
python keyphraseExtract_check.py

# Check validation report
cat logs/cve_validation.log

# Invalid files are automatically moved to CVEs/invalid/
```

### Log Analysis Guide

**Processing Status**:
- Check `logs/cve_processing.log` for overall extraction progress
- Monitor `logs/keyphrases_already.csv` for previously processed CVEs
- Review `failed_cves.txt` for patterns in processing failures

**Quality Issues**:
- Check `logs/cve_validation.log` for validation results
- Review `logs/missing_keyphrases.txt` for files needing processing  
- Monitor `logs/invalid_cve_keyphrases.csv` for problematic files

**Data Consistency**:
- Check `logs/merge_jsons2all.log` for merging process status
- Review `CVEs/all/impact_validation_errors.log` for consistency issues
- Monitor statistics in log files for processing efficiency

**Individual Errors**:
- Review `logs/error_logs/CVE-*_error.json` for specific failure details
- Check raw API responses and error context
- Analyze patterns in failed CVEs for systematic issues

## Contributing

### Development Guidelines

1. **Code Style**: Follow existing object-oriented architecture and type hints
2. **Logging**: Add comprehensive logging for all new features with appropriate levels
3. **Error Handling**: Implement robust error handling with recovery mechanisms
4. **Documentation**: Update docstrings, README, and CLAUDE.md for changes
5. **Testing**: Ensure backward compatibility and test with various data sources
6. **Performance**: Consider scalability and resource usage for large datasets

### Code Review Checklist

- [ ] Proper error handling and logging added
- [ ] Type hints and docstrings complete
- [ ] Command-line interface updated if needed
- [ ] Documentation updated (README.md, CLAUDE.md)
- [ ] Performance impact considered
- [ ] Backward compatibility maintained

## License

[Include your license information here]

---

## Schema References and Future Compatibility

### CVE Schema Evolution

This project is designed to align with ongoing CVE schema developments:

- **Root Cause Tags**: [CVE Schema Issue #22](https://github.com/CVEProject/cve-schema/issues/22)
- **Impact Fields**: [CVE Record Schema](https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json)
- **Technical Impact Classification**: MITRE technical impact standardization

### Output Compatibility

The extracted keyphrases are designed to be compatible with:
- **MITRE CVE Schema**: Standard CVE record format compliance
- **CAPEC**: Attack pattern classifications for vector mapping
- **CWE**: Weakness categorizations for systematic analysis
- **Industry Tools**: Integration with vulnerability assessment platforms
- **Research Applications**: Structured data for security research and analytics

### Future Enhancements

Planned improvements include:
- **Batch Processing**: Enhanced batch processing for very large datasets
- **Model Improvements**: Integration with newer fine-tuned models
- **Additional Validation**: Extended validation rules and consistency checks
- **Performance Optimization**: Further speed improvements for large-scale processing
- **API Extensions**: Support for additional AI model providers
- **Schema Updates**: Automatic adaptation to CVE schema changes