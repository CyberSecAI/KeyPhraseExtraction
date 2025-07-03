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
# Run the main keyphrase extraction process
python keyphraseExtract.py

# Validate generated JSON files
python keyphraseExtract_check.py

# Move processed files to CVE info repository
python move2cve_dir_hash.py
```

### Jupyter Notebook Operations
```bash
# Convert notebooks to Python scripts
python notebook2python.py

# Run individual notebooks
jupyter notebook keyphraseExtract.ipynb
jupyter notebook keyphraseExtract_check.ipynb
jupyter notebook merge_jsons2all.ipynb
```

## Architecture Overview

This is a CVE keyphrase extraction system that processes vulnerability descriptions using AI to generate structured metadata. The system follows a multi-stage pipeline:

### Core Components

1. **Data Ingestion** (`keyphraseExtract.py`):
   - Reads CVE data from `CVSSData.csv.gz` 
   - Compares against existing processed CVEs in `../cve_info`
   - Extracts CVE descriptions to `CVEs/description/`

2. **AI Processing Pipeline**:
   - Uses Google's Gemini model for keyphrase extraction
   - Processes CVE descriptions to extract structured keyphrases:
     - Root cause, weakness, impact, attack vector
     - Attacker profile, affected products/versions/components
   - Stores results in `CVEs/keyphrases/`

3. **Quality Assurance** (`keyphraseExtract_check.py`):
   - Validates JSON structure and required fields
   - Detects duplicates using content hashing
   - Moves invalid files to `CVEs/invalid/`

4. **Data Consolidation** (`merge_jsons2all.ipynb`):
   - Merges description and keyphrase data
   - Normalizes to camelCase field names
   - Adds version and timestamp metadata

5. **Integration** (`move2cve_dir_hash.py`):
   - Organizes files by CVE year and number ranges
   - Uses SHA-256 hashing to prevent duplicates
   - Moves processed files to `../cve_info` repository

### Directory Structure
```
CVEs/
├── description/    # Raw CVE descriptions
├── keyphrases/     # AI-extracted keyphrases
├── all/           # Merged final JSON files
└── invalid/       # Failed validation files

tmp/               # Processing logs and temporary files
data_in/          # Input data (CVSSData.csv.gz)
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

- **google-generativeai**: For AI keyphrase extraction using Gemini
- **pandas**: Data manipulation and CSV processing
- **tqdm**: Progress tracking for batch operations
- **pytz**: Timezone handling for timestamps

## Error Handling & Monitoring

- Processing logs: `tmp/cve_processing.log`
- Failed CVE tracking: `failed_cves.txt` and timestamped versions
- Invalid JSON isolation: `CVEs/invalid/` directory
- Hash-based duplicate detection for data integrity

## External Dependencies

- Requires `../cve_info` repository at same directory level
- Google AI API key for Gemini model access
- CVE dataset from https://github.com/CyberSecAI/nvd_cve_data

## Development Notes

- All Python scripts are auto-generated from Jupyter notebooks via `notebook2python.py`
- The system processes CVEs in batches with retry logic for API failures
- Uses concurrent processing for improved performance
- Maintains detailed audit trails for all file operations