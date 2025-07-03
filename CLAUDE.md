# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Development Commands

### Environment Setup
```bash
# Create and activate virtual environment
python -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Main Processing Pipeline
```bash
# Complete workflow - run scripts in sequence:

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
```bash
# Run keyphrase extraction with custom options
python keyphraseExtract.py --cve-data-path /path/to/data.csv
python keyphraseExtract.py --cve-info-dir /path/to/cve_info

# Convert legacy notebooks to Python scripts (if needed)
python notebook2python.py
```

## Architecture Overview

This is a CVE keyphrase extraction system that processes vulnerability descriptions using AI to generate structured metadata. The system follows a multi-stage pipeline:

### Core Components

1. **Keyphrase Extraction** (`keyphraseExtract.py`):
   - **CVEProcessor class**: Object-oriented architecture for processing
   - **Data Sources**: Reads from `../cvelistV5_process/data_out/cve_records.csv` (primary) or legacy sources
   - **Intelligent Column Detection**: Automatically detects CVE ID and description columns
   - **Dual AI API Support**: VertexAI (fine-tuned models) with automatic fallback to standard Gemini
   - **Processing Logic**: Compares against existing CVEs, extracts new descriptions, generates keyphrases
   - **Output**: Stores keyphrases in `CVEs/keyphrases/` directory

2. **Quality Control** (`keyphraseExtract_check.py`):
   - **JSON Validation**: Checks structure, required fields, and content validity
   - **Duplicate Detection**: Uses MD5 hashing to identify identical content
   - **File Management**: Moves invalid files to `CVEs/invalid/` directory
   - **Missing Keyphrase Detection**: Scans `../cve_info` for files missing keyphrases sections
   - **Output**: Creates validation reports and error logs

3. **Data Consolidation** (`merge_jsons2all.py`):
   - **Multi-source Merging**: Combines data from `CVEs/description/`, `CVEs/keyphrases/`, and `CVEs/technical_impacts/`
   - **Field Normalization**: Converts to camelCase (cveId, impactTexts, mitreTechnicalImpacts)
   - **Component Field Handling**: Intelligently merges component-prefixed fields
   - **Impact Validation**: Cross-validates impact text consistency
   - **Metadata Addition**: Adds version and timestamp information
   - **Output**: Creates consolidated JSON files in `CVEs/all/`

4. **File Organization** (`move2cve_dir_hash.py`):
   - **Directory Structure**: Organizes files by CVE year and number ranges (e.g., 2024/1xxx/)
   - **Duplicate Prevention**: Uses SHA-256 hashing to detect and handle duplicates
   - **Integration**: Moves processed files from `CVEs/all/` to `../cve_info` repository
   - **Statistics**: Provides detailed operation reports (moved, skipped, deleted)

### Directory Structure
```
.
├── keyphraseExtract.py          # Main keyphrase extraction script
├── keyphraseExtract_check.py    # Quality control and validation
├── merge_jsons2all.py           # Data consolidation script
├── move2cve_dir_hash.py         # File organization and deduplication
├── config.py                    # Model and API configuration
├── notebook2python.py          # Utility to convert notebooks to scripts
├── requirements.txt             # Python dependencies
├── CLAUDE.md                    # This development guidance file
├── README.md                    # Project documentation
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
│   └── error_logs/            # Individual error details
│
└── *.ipynb                     # Legacy Jupyter notebooks (if any)
```

### JSON Schema
The system outputs standardized JSON with this structure:
```json
{
    "cveId": "CVE-YYYY-XXXXX",
    "version": "1.0.0", 
    "timestamp": "ISO-8601-timestamp",
    "description": "CVE description text",
    "keyphrases": {
        "rootcause": "", "weakness": "", "impact": "", "vector": "",
        "attacker": "", "product": "", "version": "", "component": ""
    },
    "mitreTechnicalImpacts": []
}
```

## Key Dependencies

- **google-cloud-aiplatform**: VertexAI API for fine-tuned models (primary)
- **google-generativeai**: Standard Gemini API (fallback)
- **pandas**: Data manipulation and CSV processing
- **tqdm**: Progress tracking for batch operations
- **pytz**: Timezone handling for timestamps
- **pathlib**: Modern path handling
- **argparse**: Command-line interface support

## Error Handling & Monitoring

- **Main Activity Log**: `logs/cve_processing.log` - Overall processing status
- **Individual Error Details**: `logs/error_logs/CVE-*_error.json` - Detailed error context
- **Processing Status**: `logs/keyphrases_already.csv` - Tracks processed CVEs
- **Quality Control**: `logs/missing_keyphrases.txt` - Files needing processing
- **Validation Errors**: `impact_validation_errors.log` - Data consistency issues
- **Failed CVE Tracking**: `failed_cves.txt` - CVEs that failed processing
- **Invalid File Isolation**: `CVEs/invalid/` - Failed validation files
- **Comprehensive Hashing**: SHA-256 for duplicates, MD5 for content validation

## External Dependencies

- **CVE Info Repository**: `../cve_info` at same directory level for final file storage
- **CVE Data Source**: `../cvelistV5_process/data_out/cve_records.csv` (primary)
- **Legacy Data**: `../nvd_cve_data/data_out/CVSSData.csv.gz` (fallback)
- **Google Cloud Authentication**: `gcloud auth application-default login` for VertexAI
- **API Keys**: Google AI API key for standard Gemini access (fallback)

## Development Notes

### Script Architecture
- **Professional Python Design**: Object-oriented architecture with `CVEProcessor` class
- **Command-Line Interface**: Full argparse support with customizable options
- **Type Hints**: Comprehensive type annotations throughout codebase
- **Error Recovery**: Robust retry logic with exponential backoff for API failures
- **Dual API Strategy**: Primary VertexAI with automatic fallback to standard Gemini

### Configuration Management
- **Centralized Config**: `config.py` contains all model and API settings
- **Environment Variables**: Support for API keys and authentication
- **Model Flexibility**: Easy switching between fine-tuned and standard models

### Processing Features
- **Intelligent Data Detection**: Automatic CSV column identification
- **Incremental Processing**: Only processes new CVEs not in existing repository
- **Progress Persistence**: Recovers from interruptions and continues processing
- **Comprehensive Logging**: Detailed activity tracking at multiple levels
- **Performance Optimization**: Efficient memory usage and parallel processing capabilities

### Quality Assurance
- **Multi-stage Validation**: JSON structure, required fields, content consistency
- **Duplicate Prevention**: Hash-based detection at multiple levels
- **Error Isolation**: Failed files moved to dedicated directories with detailed logs
- **Audit Trails**: Complete tracking of all file operations and transformations