# Overview

## Setup
1. Git clone https://github.com/CyberSecAI/cve_info so that cve_info is at the same dir level as this repo
2. Get list of CVEs to data_in/CVSSData.csv.gz (e.g. from https://github.com/CyberSecAI/nvd_cve_data/tree/main/data_out/CVSSData.csv.gz)

## Running the Code

1. keyphraseExtract.ipynb
   1. Determines CVEs to be processed
      1. Reads existing CVEs with extracted keyphrases "../cve_info" 
      2. Reads a list of CVEs from ./data_in/CVSSData.csv.gz
      3. Determines the difference to find what CVEs need keyphrases extracted
   2. Extract Keyphrases
      1. Writes CVE descriptions to CVEs/description/
      2. Calls keyphraseExtraction model to extract the Keyphrases
      3. Stores CVEs with extracted keyphrases to CVEs/keyphrases
      4. Writes logs to tmp/cve_processing.log
2. keyphraseExtract_check.ipynb
   1. Performs checks for bad json, missing or extra fields, etc...
      1. https://jsonlint.com/ can be used to manually check json format
3. merge_jsons2all.ipynb
   1. create the final json file from keyphrases and descriptions 
4. move2cve_dir.py 
   1. Moves files in "./CVEs/all" to "../cve_info" to a specific sub-dir

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




