# CVE Keyphrase Extraction

This project processes CVE (Common Vulnerabilities and Exposures) descriptions to extract structured keyphrases using AI models. It supports both new VertexAI and legacy Google Generative AI APIs with automatic fallback, organizes data into standardized JSON format, and integrates with a larger CVE information database.

## Features

- 🤖 **Dual AI API Support**: VertexAI (fine-tuned models) with automatic fallback to standard Gemini models
- 📊 **Intelligent Column Detection**: Automatically identifies CVE ID and description columns in various data formats
- 🔄 **Robust Processing Pipeline**: Multi-stage processing with retry logic and error handling
- 📝 **Comprehensive Logging**: Structured logging with detailed error tracking
- 🏗️ **Professional Python Architecture**: Object-oriented design with command-line interface
- 🛡️ **Data Validation**: JSON validation, duplicate detection, and quality control
- ⚙️ **Flexible Configuration**: Centralized configuration with support for multiple models

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

The script automatically detects and works with CVE data from:
- **Primary**: `../cvelistV5_process/data_out/cve_records.csv` (default)
- **Legacy**: `../nvd_cve_data/data_out/CVSSData.csv.gz`

### 4. Authentication

#### For VertexAI (Recommended)
```bash
# Set up Google Cloud authentication
gcloud auth application-default login
```

#### For Standard Gemini API
Set your API key in `config.py` or as an environment variable.

## Usage

### Complete Processing Workflow

Run the scripts in sequence for full processing:

```bash
# 1. Extract keyphrases from CVE descriptions
python keyphraseExtract.py

# 2. Check for quality issues and missing keyphrases
python keyphraseExtract_check.py

# 3. Merge descriptions and keyphrases into final format
python merge_jsons2all.py

# 4. Move processed files to CVE info repository
python move2cve_dir_hash.py
```

### Individual Script Usage

#### 1. Main Keyphrase Extraction
```bash
# Run with default settings
python keyphraseExtract.py

# Use custom data source
python keyphraseExtract.py --cve-data-path /path/to/your/cve_data.csv

# Use custom CVE info directory
python keyphraseExtract.py --cve-info-dir /path/to/cve_info

# Get help
python keyphraseExtract.py --help
```

#### 2. Quality Control Check
```bash
# Check for missing keyphrases in CVE files
python keyphraseExtract_check.py
# Output: logs/missing_keyphrases.txt
```

#### 3. Data Consolidation
```bash
# Merge description and keyphrase files
python merge_jsons2all.py
# Input: CVEs/description/ and CVEs/keyphrases/
# Output: CVEs/all/
```

#### 4. File Organization
```bash
# Move processed files to CVE info repository
python move2cve_dir_hash.py
# Input: CVEs/all/
# Output: ../cve_info/ (organized by year/number)
```

### Utility Scripts

```bash
# Convert Jupyter notebooks to Python scripts (if needed)
python notebook2python.py
```

### Configuration

Edit `config.py` to customize:
- **Main Model**: Fine-tuned VertexAI endpoint configuration
- **Fallback Model**: Standard Gemini model settings
- **Google Cloud**: Project and location settings
- **Safety Settings**: Content filtering configurations

Example configuration:
```python
MAIN_MODEL_CONFIG = {
    "model_endpoint": "projects/your-project/locations/region/endpoints/123456",
    "model_type": "vertexai",
    "temperature": 1,
    "top_p": 0.95,
    "max_output_tokens": 8192
}

FALLBACK_MODEL_CONFIG = {
    "model_name": "gemini-2.0-flash-exp",
    "model_type": "standard",
    "temperature": 1,
    "response_mime_type": "application/json"
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
├── CLAUDE.md                    # Development guidance
├── README.md                    # This file
├── .gitignore                   # Git ignore patterns
│
├── CVEs/                        # Processing outputs (gitignored)
│   ├── description/            # Extracted CVE descriptions
│   ├── keyphrases/            # AI-generated keyphrases
│   ├── all/                   # Merged JSON files
│   └── invalid/               # Failed validation files
│
├── logs/                       # Logging directory (gitignored)
│   ├── cve_processing.log     # Main processing log
│   ├── keyphrases_already.csv # Processing status
│   ├── missing_keyphrases.txt  # Quality control output
│   ├── impact_validation_errors.log # Validation errors
│   └── error_logs/            # Individual error details
│       └── CVE-YYYY-XXXXX_error.json
│
└── *.ipynb                     # Legacy Jupyter notebooks (if any)
```

## Processing Pipeline

The system follows a 4-stage Python script pipeline:

### 1. Keyphrase Extraction (`keyphraseExtract.py`)
- **Purpose**: Main AI processing script for extracting keyphrases from CVE descriptions
- **Features**:
  - Loads existing processed CVEs from `../cve_info`
  - Reads new CVE data with intelligent column detection
  - Filters out already processed CVEs
  - Cleans and normalizes descriptions
  - Uses fine-tuned VertexAI model with fallback to standard Gemini
  - Implements retry logic with exponential backoff
  - Saves extracted keyphrases to `CVEs/keyphrases/`

### 2. Quality Control (`keyphraseExtract_check.py`)
- **Purpose**: Validates generated JSON files and identifies missing keyphrases
- **Features**:
  - Searches for files missing keyphrases sections
  - Validates JSON structure and required fields
  - Generates reports of files needing processing
  - Outputs results to `logs/missing_keyphrases.txt`

### 3. Data Consolidation (`merge_jsons2all.py`)
- **Purpose**: Merges descriptions and keyphrases into final JSON format
- **Features**:
  - Combines data from `CVEs/description/` and `CVEs/keyphrases/`
  - Normalizes field names to camelCase format
  - Validates impact text consistency
  - Adds metadata (version, timestamp)
  - Creates consolidated files in `CVEs/all/`
  - Generates validation error logs

### 4. Data Integration (`move2cve_dir_hash.py`)
- **Purpose**: Organizes processed files into the CVE info repository
- **Features**:
  - Moves files from `CVEs/all/` to appropriate subdirectories in `../cve_info`
  - Uses SHA-256 hashing to prevent duplicates
  - Maintains proper CVE directory structure by year and number range
  - Provides detailed operation statistics

### Output Format
The final consolidated JSON follows this structure:

```json
{
    "cveId": "CVE-YYYY-XXXXX",
    "version": "1.0.0",
    "timestamp": "2025-07-03T12:00:00Z",
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

### Log Files

| File | Purpose | Location |
|------|---------|----------|
| `cve_processing.log` | Main activity log | `logs/` |
| `CVE-*_error.json` | Individual error details | `logs/error_logs/` |
| `keyphrases_already.csv` | Processing status | `logs/` |
| `failed_cves.txt` | Failed CVE list | Root directory |

### Log Content Examples

**Main Processing Log (`logs/cve_processing.log`):**
```
2025-07-03 12:00:00,123 - INFO - Using new VertexAI API
2025-07-03 12:00:01,456 - INFO - Loaded 5000 new CVEs for processing
2025-07-03 12:00:05,789 - INFO - Processed CVE-2024-1234 (API: new)
2025-07-03 12:00:08,012 - ERROR - Error processing CVE-2024-5678: Invalid JSON
```

**Individual Error Detail (`logs/error_logs/CVE-2024-5678_error.json`):**
```json
{
    "cve": "CVE-2024-5678",
    "error": "Invalid JSON response",
    "timestamp": "2025-07-03 12:00:08",
    "api_used": "new",
    "description": "Buffer overflow in...",
    "raw_response": "malformed response..."
}
```

**Quality Control Output (`logs/missing_keyphrases.txt`):**
```
../cve_info/2024/1xxx/CVE-2024-1234.json
../cve_info/2024/1xxx/CVE-2024-1567.json
../cve_info/2024/2xxx/CVE-2024-2345.json
```

**Validation Errors (`impact_validation_errors.log`):**
```
CVE-2024-3456: Impact text mismatch between description and keyphrases
CVE-2024-4567: Missing required impact field
```

## Data Sources and Compatibility

### Supported Input Formats

The script automatically detects column names for:

| Data Source | CVE Column | Description Column | Format |
|-------------|------------|-------------------|---------|
| cvelistV5_process | `cve_id` | `description` | CSV |
| nvd_cve_data | `CVE` | `Description` | CSV/CSV.GZ |
| Custom | Auto-detected | Auto-detected | CSV/CSV.GZ |

### Column Detection Logic

- **CVE ID**: Looks for `cve`, `cveid`, `cve_id`, `id`, `identifier` or columns with CVE-like values
- **Description**: Looks for `description`, `desc`, `summary`, `text`, `details` or longest text column

## Error Handling

### Comprehensive Error Management
- **API Failures**: Automatic retry with exponential backoff
- **JSON Parsing**: Error isolation and detailed logging
- **Rate Limiting**: Sleep and retry on quota exhaustion
- **Model Failures**: Automatic fallback to secondary model
- **Data Issues**: Graceful handling of malformed inputs

### Monitoring and Debugging
- Real-time progress tracking with `tqdm`
- Detailed error logs with full context
- Performance metrics and timing
- API usage tracking (primary vs fallback)

## Performance and Scalability

- **Parallel Processing**: Multi-threaded file reading
- **Memory Efficient**: Streaming processing for large datasets
- **Incremental Updates**: Only processes new CVEs
- **Resource Management**: Handles API quotas and timeouts
- **Progress Persistence**: Resumes from interruptions

## Development

### Code Organization
- **Object-Oriented Design**: `CVEProcessor` class encapsulates functionality
- **Modular Functions**: Clear separation of concerns
- **Type Hints**: Comprehensive type annotations
- **Documentation**: Detailed docstrings and comments

### Script Dependencies

The scripts should be run in order as they depend on each other's outputs:

1. `keyphraseExtract.py` → Creates `CVEs/keyphrases/`
2. `keyphraseExtract_check.py` → Validates files, reports missing keyphrases
3. `merge_jsons2all.py` → Reads from `CVEs/description/` and `CVEs/keyphrases/`, creates `CVEs/all/`
4. `move2cve_dir_hash.py` → Reads from `CVEs/all/`, organizes into `../cve_info/`

### Testing and Validation
- Intelligent column detection for various data formats
- Comprehensive error handling and logging
- JSON validation and structure verification
- Duplicate detection using SHA-256 hashing
- Impact text consistency validation

## Troubleshooting

### Common Issues

1. **Column Detection Failures**
   ```bash
   # Check available columns in your data file
   python -c "import pandas as pd; print(pd.read_csv('path/to/data.csv', nrows=1).columns.tolist())"
   ```

2. **API Authentication Issues**
   ```bash
   # Verify VertexAI authentication
   gcloud auth application-default print-access-token
   
   # Check if credentials are properly configured
   gcloud config list
   ```

3. **Missing Dependencies**
   ```bash
   # Reinstall requirements
   pip install -r requirements.txt --upgrade
   ```

4. **Script Execution Order**
   ```bash
   # If merge_jsons2all.py reports "No CVEs with keyphrases files found"
   # Make sure you've run keyphraseExtract.py first
   python keyphraseExtract.py
   ```

5. **Missing Input Directories**
   ```bash
   # Create required directories if they don't exist
   mkdir -p CVEs/description CVEs/keyphrases CVEs/all
   ```

### Log Analysis
- **Main processing**: Check `logs/cve_processing.log` for overall status
- **Individual errors**: Review `logs/error_logs/` for specific CVE failures
- **Quality issues**: Check `logs/missing_keyphrases.txt` for files needing processing
- **Validation errors**: Review `impact_validation_errors.log` for data consistency issues
- **Failed CVEs**: Monitor `failed_cves.txt` for patterns in processing failures
- **Processing status**: Check `logs/keyphrases_already.csv` for previously processed CVEs

## Contributing

1. Follow the existing code style and architecture
2. Add comprehensive logging for new features
3. Update tests and documentation
4. Ensure backward compatibility

## License

[Include your license information here]

---

## Schema References

### CVE Schema Evolution

This project aligns with ongoing CVE schema developments:

- **Root Cause Tags**: [CVE Schema Issue #22](https://github.com/CVEProject/cve-schema/issues/22)
- **Impact Fields**: [CVE Record Schema](https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json)

### Output Compatibility

The extracted keyphrases are designed to be compatible with:
- MITRE CVE schema standards
- CAPEC attack pattern classifications
- CWE weakness categorizations
- Industry vulnerability assessment tools