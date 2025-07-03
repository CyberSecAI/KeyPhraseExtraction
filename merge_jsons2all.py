#!/usr/bin/env python
# coding: utf-8

# #Use camel case for JSON fields
# 
# in the output json file 
# * use cveId instead of cve_id
# * impactTexts instead of impact_texts
# * mitreTechnicalImpacts instead of mitre_technical_impacts
# 
#     cveId -> 
#     "cve-id": "CVE-2013-0643",
#         "cveId": "CVE-2023-28012",
#         https://github.com/CVEProject/cvelistV5/blob/9909a609e34af9a8ac85a586e11eee4e7e9a5ed8/cves/2023/28xxx/CVE-2023-28012.json#L5
# 
#         impact_texts -> impactTexts
# 
#         mitre_technical_impacts -> mitreTechnicalImpacts

# 

# 

# In[1]:


#only save CVE files that have corresponding keyphrases files
import json
import os
from typing import Dict, Any, List, Tuple, Set
from pathlib import Path
from datetime import datetime
import pytz

def normalize_keyphrases(keyphrases: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure all required fields exist in keyphrases and normalize component fields.
    
    Args:
        keyphrases: Original keyphrases dictionary
    
    Returns:
        Normalized keyphrases dictionary
    """
    required_fields = [
        "rootcause",
        "weakness",
        "impact",
        "vector",
        "attacker",
        "product",
        "version",
        "component"
    ]
    
    # Initialize normalized keyphrases
    normalized = {}
    
    # Add all existing fields that don't start with 'component'
    for key, value in keyphrases.items():
        if not key.startswith('component') or key == 'component':
            normalized[key] = value
    
    # Merge any component-prefixed fields into 'component'
    component_values = []
    for key, value in keyphrases.items():
        if key.startswith('component') and key != 'component':
            if isinstance(value, list):
                component_values.extend(value)
            elif isinstance(value, str) and value:
                component_values.append(value)
    
    # If we found component values, add them to any existing component values
    if component_values:
        existing_component = normalized.get('component', '')
        if isinstance(existing_component, list):
            component_values.extend(existing_component)
        elif isinstance(existing_component, str) and existing_component:
            component_values.append(existing_component)
        normalized['component'] = component_values if len(component_values) > 1 else (component_values[0] if component_values else '')
    
    # Ensure all required fields exist
    for field in required_fields:
        if field not in normalized:
            normalized[field] = ""
    
    return normalized

def validate_impacts(cve_id: str, keyphrases_impact: Any, impact_texts: List[str]) -> List[str]:
    """
    Validate that impactTexts match keyphrases.impact values.
    
    Args:
        cve_id: The CVE identifier
        keyphrases_impact: Impact from keyphrases (can be string or list)
        impact_texts: List of impact texts from technical_impacts
    
    Returns:
        List of error messages, empty if no errors
    """
    errors = []
    
    # Convert keyphrases impact to list for comparison
    if isinstance(keyphrases_impact, str):
        keyphrases_impacts = [keyphrases_impact] if keyphrases_impact else []
    elif isinstance(keyphrases_impact, list):
        keyphrases_impacts = keyphrases_impact
    else:
        keyphrases_impacts = []
    
    # Convert to sets for comparison, ignoring empty strings
    keyphrases_set = set(filter(None, keyphrases_impacts))
    impact_texts_set = set(filter(None, impact_texts))
    
    # Check for mismatches
    if keyphrases_set != impact_texts_set:
        extra_in_keyphrases = keyphrases_set - impact_texts_set
        extra_in_impacts = impact_texts_set - keyphrases_set
        
        if extra_in_keyphrases:
            errors.append(f"{cve_id}: Found in keyphrases.impact but not in impactTexts: {extra_in_keyphrases}")
        if extra_in_impacts:
            errors.append(f"{cve_id}: Found in impactTexts but not in keyphrases.impact: {extra_in_impacts}")
    
    return errors

def get_cves_with_keyphrases(base_dir: str) -> Set[str]:
    """
    Get a set of CVE IDs that have keyphrases files.
    
    Args:
        base_dir: Base directory containing CVE subdirectories
    
    Returns:
        Set of CVE IDs that have keyphrases files
    """
    keyphrases_dir = Path(base_dir) / 'keyphrases'
    if not keyphrases_dir.exists():
        return set()
        
    cve_ids = set()
    for file_path in keyphrases_dir.glob('CVE-*_*.json'):
        cve_id = file_path.name.split('_')[0]
        cve_ids.add(cve_id)
    
    return cve_ids

def merge_cve_files(base_dir: str, version: str = "1.0.0") -> Tuple[Dict[str, Any], List[str]]:
    """
    Merge JSON files for each CVE ID into a single consolidated structure.
    Only includes CVEs that have keyphrases files.
    
    Args:
        base_dir: Base directory containing CVE subdirectories
        version: Version string to include in output
    
    Returns:
        Tuple of (Dictionary mapping CVE IDs to their consolidated data, List of error messages)
    """
    # First, get the set of CVEs that have keyphrases files
    cves_with_keyphrases = get_cves_with_keyphrases(base_dir)
    if not cves_with_keyphrases:
        return {}, []
    
    cve_data = {}
    error_logs = []
    
    # Process each type of file
    subdirs = ['description', 'keyphrases', 'technical_impacts']
    timestamp = datetime.now(pytz.UTC).isoformat()
    
    for subdir in subdirs:
        dir_path = Path(base_dir) / subdir
        if not dir_path.exists():
            continue
            
        for file_path in dir_path.glob('CVE-*_*.json'):
            cve_id = file_path.name.split('_')[0]
            
            # Skip if this CVE doesn't have a keyphrases file
            if cve_id not in cves_with_keyphrases:
                continue
            
            if cve_id not in cve_data:
                # Initialize with metadata
                cve_data[cve_id] = {
                    "cveId": cve_id,
                    "version": version,
                    "timestamp": timestamp
                }
                
            with open(file_path, 'r') as f:
                file_data = json.load(f)
                
            # Handle different file types
            if 'description' in subdir:
                cve_data[cve_id]['description'] = file_data['description']
            elif 'keyphrases' in subdir:
                # Normalize keyphrases
                normalized_keyphrases = normalize_keyphrases(file_data)
                cve_data[cve_id]['keyphrases'] = normalized_keyphrases
            elif 'technical_impacts' in subdir:
                # Store impact_texts temporarily for validation
                if 'impact_texts' in file_data:
                    cve_data[cve_id]['_temp_impact_texts'] = file_data['impact_texts']
                if 'mitre_technical_impacts' in file_data:
                    cve_data[cve_id]['mitreTechnicalImpacts'] = file_data['mitre_technical_impacts']
    
    # Validate impacts and clean up temporary data
    for cve_id, data in cve_data.items():
        if 'keyphrases' in data and '_temp_impact_texts' in data:
            keyphrases_impact = data['keyphrases'].get('impact', '')
            impact_texts = data['_temp_impact_texts']
            
            errors = validate_impacts(cve_id, keyphrases_impact, impact_texts)
            error_logs.extend(errors)
        
        # Remove temporary impact_texts
        if '_temp_impact_texts' in data:
            del data['_temp_impact_texts']
    
    return cve_data, error_logs

def save_merged_files(cve_data: Dict[str, Any], error_logs: List[str], output_dir: str) -> None:
    """
    Save each merged CVE entry as a separate JSON file and error logs.
    
    Args:
        cve_data: Dictionary containing merged CVE data
        error_logs: List of error messages
        output_dir: Directory to save the output files
    """
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Save each CVE as a separate file
    for cve_id, data in cve_data.items():
        file_path = output_path / f"{cve_id}.json"
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
            f.write('\n')
    
    # Save error logs if any
    if error_logs:
        log_path = output_path / "impact_validation_errors.log"
        with open(log_path, 'w') as f:
            for error in error_logs:
                f.write(f"{error}\n")

def main():
    base_dir = "CVEs"
    output_dir = "CVEs/all"
    version = "1.0.0"
    
    # Merge files and get error logs
    cve_data, error_logs = merge_cve_files(base_dir, version)
    
    if not cve_data:
        print("No CVEs with keyphrases files found. No files will be created.")
        return
    
    # Save merged files and error logs
    save_merged_files(cve_data, error_logs, output_dir)
    
    # Print summary
    print(f"Processed {len(cve_data)} CVE files (only those with keyphrases)")
    if error_logs:
        print(f"Found {len(error_logs)} impact validation errors. See impact_validation_errors.log for details")

if __name__ == "__main__":
    main()

