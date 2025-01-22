# CVE Keyphrase Extraction

This project processes CVE (Common Vulnerabilities and Exposures) descriptions to extract structured keyphrases using a finetuned Large Language Model. It organizes the data into standardized JSON format and integrates with a larger CVE information database.

## Prerequisites

- Python 3.12+
- Git
- Access to Google AI Platform (for the Gemini model)
- Required Python packages:
  - pandas
  - google-generativeai
  - tqdm
  - pytz

## Setup

1. Clone the related CVE info repository:
```bash
git clone https://github.com/CyberSecAI/cve_info
```
Ensure it's at the same directory level as this repository.

2. Download the CVE dataset:
- Get `CVSSData.csv.gz` from https://github.com/CyberSecAI/nvd_cve_data/tree/main/data_out/
- Place it in the `data_in` directory

3. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Project Structure

```
.
├── CVEs/
│   ├── description/    # Extracted CVE descriptions
│   ├── keyphrases/    # Generated keyphrases
│   ├── all/           # Merged JSON files
│   └── invalid/       # Invalid JSON files
├── tmp/               # Temporary files and logs
└── notebooks/
    ├── keyphraseExtract.ipynb
    ├── keyphraseExtract_check.ipynb
    └── merge_jsons2all.ipynb
```

## Workflow

### 1. Keyphrase Extraction (keyphraseExtract.ipynb)
- Identifies CVEs requiring keyphrase extraction by:
  - Reading existing processed CVEs from `../cve_info`
  - Comparing against CVEs in `CVSSData.csv.gz`
  - Determining which CVEs need processing
- Processes CVEs:
  - Extracts descriptions to `CVEs/description/`
  - Uses Gemini model to extract keyphrases
  - Stores results in `CVEs/keyphrases/`
- Generates detailed logs in `tmp/cve_processing.log`

### 2. Quality Control (keyphraseExtract_check.ipynb)
- Validates generated JSON files:
  - Checks for proper JSON formatting
  - Verifies required fields presence
  - Identifies duplicate content
  - Validates field consistency
- Moves invalid files to `CVEs/invalid/`
- Generates validation reports and error logs

### 3. Data Consolidation (merge_jsons2all.ipynb)
- Merges processed data into final JSON format:
  - Combines descriptions and keyphrases
  - Normalizes field names to camelCase
  - Validates impact text consistency
  - Adds metadata (version, timestamp)
- Creates consolidated files in `CVEs/all/`

### 4. Data Integration (move2cve_dir_hash.py)
- Organizes processed files into the CVE info repository:
  - Moves files from `CVEs/all` to appropriate subdirectories in `../cve_info`
  - Uses SHA-256 hashing to prevent duplicates
  - Maintains proper CVE directory structure
  - Provides detailed operation logs

## JSON Schema

The final JSON output follows this structure:
```json
{
    "cveId": "CVE-YYYY-XXXXX",
    "version": "1.0.0",
    "timestamp": "ISO-8601-timestamp",
    "description": "CVE description text",
    "keyphrases": {
        "rootcause": "",
        "weakness": "",
        "impact": "",
        "vector": "",
        "attacker": "",
        "product": "",
        "version": "",
        "component": ""
    },
    "mitreTechnicalImpacts": []
}
```

## Error Handling

The system includes comprehensive error handling:
- Invalid JSON detection and isolation
- Duplicate content detection using hash comparison
- Impact text validation
- Detailed error logging
- Automated file organization and cleanup

## Maintenance

- Check `tmp/cve_processing.log` for processing errors
- Review `impact_validation_errors.log` for impact text inconsistencies
- Use https://jsonlint.com/ for manual JSON validation when needed
- Monitor `CVEs/invalid/` for problematic files requiring attention
# Notes

## CVE Schema root-cause tags
There is some discussion about adding **root cause tags and descriptions** to cna and adp tag files per https://github.com/CVEProject/cve-schema/issues/22.

There is a [PR](https://github.com/CVEProject/cve-schema/pull/335/commits/6b3c524fdde009d7ff8bba9ce4c41ad24f0cf336) (not merged as at Dec 15 2024) to add these tags "hardware-root-cause", "software-root-cause", "specification-root-cause"



## Impact field
The [CVE Record Schema](https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json) supports an Impact tag.

````
        "impacts": {
            "type": "array",
            "description": "Collection of impacts of this vulnerability.",
            "minItems": 1,
            "uniqueItems": true,
            "items": {
                "type": "object",
                "description": "This is impact type information (e.g. a text description.",
                "required": ["descriptions"],
                "properties": {
                    "capecId": {
                        "type": "string",
                        "description": "CAPEC ID that best relates to this impact.",
                        "minLength": 7,
                        "maxLength": 11,
                        "pattern": "^CAPEC-[1-9][0-9]{0,4}$"
                    },
                    "descriptions": {
                        "description": "Prose description of the impact scenario. At a minimum provide the description given by CAPEC.",
                        "$ref": "#/definitions/descriptions"
                    }
                },
                "additionalProperties": false
            }
        },
````

> [!NOTE]  
> CAPEC is for Attack Patterns. So it is interesting to see it being used here with Impact.

## Product
The [CVE Record Schema](https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json) supports a Product tag, which includes a Vendor tag.

````
        "product": {
            "type": "object",
            "description": "Provides information about the set of products and services affected by this vulnerability.",
            "allOf": [
                {
                    "anyOf": [
                        {"required": ["vendor", "product"]},
                        {"required": ["collectionURL", "packageName"]}
                    ]
                },
                {
                    "anyOf": [
                        {"required": ["versions"]},
                        {"required": ["defaultStatus"]}
                    ]
                }
            ],
````

Related fields include
- packageName
- cpes
- modules
- programFiles
- programRoutines
- platforms
- repo

## Version
The [CVE Record Schema](https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json) supports a Version tag.

````
 "versions": {
                    "type": "array",
                    "description": "Set of product versions or version ranges related to the vulnerability. The versions satisfy the CNA Rules [8.1.2 requirement](https://cve.mitre.org/cve/cna/rules.html#section_8-1_cve_entry_information_requirements). Versions or defaultStatus may be omitted, but not both.",
                    "minItems": 1,
                    "uniqueItems": true,
                    "items": {
                        "type": "object",
                        "description": "A single version or a range of versions, with vulnerability status.\n\nAn entry with only 'version' and 'status' indicates the status of a single version.\n\nOtherwise, an entry describes a range; it must include the 'versionType' property, to define the version numbering semantics in use, and 'limit', to indicate the non-inclusive upper limit of the range. The object describes the status for versions V such that 'version' <= V and V < 'limit', using the <= and < semantics defined for the specific kind of 'versionType'. Status changes within the range can be specified by an optional 'changes' list.\n\nThe algorithm to decide the status specified for a version V is:\n\n\tfor entry in product.versions {\n\t\tif entry.lessThan is not present and entry.lessThanOrEqual is not present and v == entry.version {\n\t\t\treturn entry.status\n\t\t}\n\t\tif (entry.lessThan is present and entry.version <= v and v < entry.lessThan) or\n\t\t   (entry.lessThanOrEqual is present and entry.version <= v and v <= entry.lessThanOrEqual) { // <= and < defined by entry.versionType\n\t\t\tstatus = entry.status\n\t\t\tfor change in entry.changes {\n\t\t\t\tif change.at <= v {\n\t\t\t\t\tstatus = change.status\n\t\t\t\t}\n\t\t\t}\n\t\t\treturn status\n\t\t}\n\t}\n\treturn product.defaultStatus\n\n.",
                        "oneOf": [
                            {
                                "required": ["version", "status"],
                                "maxProperties": 2
                            },
                            {
                                "required": ["version", "status", "versionType"],
                                "maxProperties": 3
                            },
                            {
                                "required": ["version", "status", "versionType", "lessThan"]
                            },
                            {
                                "required": ["version", "status", "versionType", "lessThanOrEqual"]
                            }
                        ],
                        "properties": {
                            "version": {
                                "description": "The single version being described, or the version at the start of the range. By convention, typically 0 denotes the earliest possible version.",
                                "$ref": "#/definitions/version"
                            },
                            "status": {
                                "description": "The vulnerability status for the version or range of versions. For a range, the status may be refined by the 'changes' list.",
                                "$ref": "#/definitions/status"
                            },
                            "versionType": {
                                "type": "string",
                                "description": "The version numbering system used for specifying the range. This defines the exact semantics of the comparison (less-than) operation on versions, which is required to understand the range itself. 'Custom' indicates that the version type is unspecified and should be avoided whenever possible. It is included primarily for use in conversion of older data files.",
                                "minLength": 1,
                                "maxLength": 128,
                                "examples": [
                                    "custom",
                                    "git",
                                    "maven",
                                    "python",
                                    "rpm",
                                    "semver"
                                ]
                            },
                            "lessThan": {
                                "description": "The non-inclusive upper limit of the range. This is the least version NOT in the range. The usual version syntax is expanded to allow a pattern to end in an asterisk `(*)`, indicating an arbitrarily large number in the version ordering. For example, `{version: 1.0 lessThan: 1.*}` would describe the entire 1.X branch for most range kinds, and `{version: 2.0, lessThan: *}` describes all versions starting at 2.0, including 3.0, 5.1, and so on. Only one of lessThan and lessThanOrEqual should be specified.",
                                "$ref": "#/definitions/version"
                            },
                            "lessThanOrEqual": {
                                "description": "The inclusive upper limit of the range. This is the greatest version contained in the range. Only one of lessThan and lessThanOrEqual should be specified. For example, `{version: 1.0, lessThanOrEqual: 1.3}` covers all versions from 1.0 up to and including 1.3.",
                                "$ref": "#/definitions/version"
                            },
                            "changes": {
                                "type": "array",
                                "description": "A list of status changes that take place during the range. The array should be sorted in increasing order by the 'at' field, according to the versionType, but clients must re-sort the list themselves rather than assume it is sorted.",
                                "minItems": 1,
                                "uniqueItems": true,
                                "items": {
                                    "type": "object",
                                    "description": "The start of a single status change during the range.",
                                    "required": ["at", "status"],
                                    "additionalProperties": false,
                                    "properties": {
                                        "at": {
                                            "description": "The version at which a status change occurs.",
                                            "$ref": "#/definitions/version"
                                        },
                                        "status": {
                                            "description": "The new status in the range starting at the given version.",
                                            "$ref": "#/definitions/status"
                                        }
                                    }
                                }
                            }
                        },
                        "additionalProperties": false
                    }
                }
````




