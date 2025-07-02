#!/usr/bin/env python
# coding: utf-8

# https://ai.google.dev/gemini-api/docs/model-tuning/tutorial?_gl=1*i1w58h*_ga*MTU1NDM4NzcwMC4xNzI2MzQzNTI0*_ga_P1DBVKWT6V*MTcyOTE1NDgzMC4yMC4xLjE3MjkxNTUzMjYuMC4wLjEzMTY5MzIwMjc.&lang=python

# In[59]:


"""
Install the Google AI Python SDK

$ pip install google-generativeai
"""
import pandas as pd
import json
import csv
import re
import os
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold
import hashlib


# In[72]:


# Directory containing the description files
input_dir = 'CVEs/keyphrases/'


# ## Check File size for zero

# In[73]:


# List to store the data
data = []

# Iterate through files in the directory
for filename in os.listdir(input_dir):
    if filename.endswith('_keyphrases.json'):
        # Extract CVE from filename
        cve = filename.split('_')[0]
        
        # Get full file path
        file_path = os.path.join(input_dir, filename)
        
        # Get file size in bytes
        file_size = os.path.getsize(file_path)
        
        # Add to data list
        data.append({'CVE': cve, 'File Size (bytes)': file_size})

# Create DataFrame
df = pd.DataFrame(data)

# Sort DataFrame by CVE
df = df.sort_values('CVE')

# Display the first few rows of the DataFrame
print(df.head())

# Optionally, save the DataFrame to a CSV file
# df.to_csv('cve_file_sizes.csv', index=False)

print(f"Total CVEs processed: {len(df)}")


# In[ ]:





# ## Check JSON content

# In[62]:


import json
import os
import hashlib
import shutil

# List to store the data
data = []

# Expected fields in the JSON
expected_fields = set(['rootcause', 'weakness', 'impact', 'vector', 'attacker', 'product', 'version', 'component'])

# Dictionary to store file hashes
content_hashes = {}

def validate_json(file_path):
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            json_content = json.loads(content)

        # Ensure we have a flat JSON object, not an array or nested structure
        if not isinstance(json_content, dict):
            return False, {'error': 'JSON must be a flat object'}, None, None

        # Check for any nested objects or arrays (except for version field)
        for key, value in json_content.items():
            if key != 'version' and isinstance(value, (dict, list)):
                return False, {'error': f'Nested structure found in field: {key}'}, None, None

        # Replace any 'unknown' values with empty strings
        json_content = {k: '' if isinstance(v, str) and v.lower() == 'unknown' else v 
                       for k, v in json_content.items()}

        issues = {}

        # Check for extra fields
        extra_fields = set(json_content.keys()) - expected_fields
        if extra_fields:
            issues['extra_fields'] = list(extra_fields)

        # Check for missing fields
        missing_fields = expected_fields - set(json_content.keys())
        if missing_fields:
            issues['missing_fields'] = list(missing_fields)

        # Check for duplicated fields (shouldn't be possible in valid JSON, but check anyway)
        duplicated_fields = [field for field in json_content.keys() 
                           if list(json_content.keys()).count(field) > 1]
        if duplicated_fields:
            issues['duplicated_fields'] = duplicated_fields

        is_valid = not bool(issues)
        return is_valid, issues, json_content, content

    except json.JSONDecodeError:
        return False, {'error': 'Invalid JSON'}, None, None
    except Exception as e:
        return False, {'error': str(e)}, None, None

def process_directory(input_dir):
    # Create invalid directory if it doesn't exist
    invalid_dir = os.path.join('./CVEs', 'invalid')
    os.makedirs(invalid_dir, exist_ok=True)

    for filename in os.listdir(input_dir):
        if filename.endswith('_keyphrases.json'):
            # Extract CVE from filename
            cve = filename.split('_')[0]
            
            # Get full file paths
            file_path = os.path.join(input_dir, filename)
            invalid_path = os.path.join(invalid_dir, filename)
            
            # Get file size in bytes
            file_size = os.path.getsize(file_path)
            
            # Validate JSON content
            is_valid, issues, json_content, raw_content = validate_json(file_path)
            
            # Calculate hash of the content if valid
            content_hash = None
            if raw_content:
                content_hash = hashlib.md5(raw_content.encode()).hexdigest()
                if content_hash in content_hashes:
                    content_hashes[content_hash].append(cve)
                else:
                    content_hashes[content_hash] = [cve]
            
            # Move invalid files to invalid directory
            if not is_valid:
                try:
                    shutil.move(file_path, invalid_path)
                    print(f"Moved invalid file {filename} to {invalid_dir}")
                except Exception as e:
                    print(f"Error moving file {filename}: {str(e)}")
            
            # Add to data list
            data.append({
                'CVE': cve, 
                'File Size (bytes)': file_size,
                'json_valid': is_valid,
                'Content Hash': content_hash,
                'Content' if is_valid else 'Issues': json_content if is_valid else issues
            })

    return data


# In[63]:


#input_directory = "path/to/your/input/directory"  # Replace with your input directory

results = process_directory(input_dir)
print(f"Processed {len(results)} files")
print(f"Found {len([r for r in results if not r['json_valid']])} invalid files")


# ## Save Good JSON Files

# In[64]:


df.to_csv("./tmp/good_keyphrases.csv", index=False, quoting=csv.QUOTE_ALL, escapechar='\\')


# In[65]:


df


# In[66]:


# Create DataFrame
df = pd.DataFrame(data)

# Sort DataFrame by CVE
df = df.sort_values('CVE')

# Display summary
print(f"Total CVEs processed: {len(df)}")
print(f"Valid JSON files: {df['json_valid'].sum()}")
print(f"Invalid JSON files: {len(df) - df['json_valid'].sum()}")

# Display the first few rows of the DataFrame
print("\nFirst few rows of the DataFrame:")
print(df[['CVE', 'File Size (bytes)', 'json_valid', 'Content Hash']].head())

# Check for duplicate content
duplicate_content = {hash: cves for hash, cves in content_hashes.items() if len(cves) > 1}

if duplicate_content:
    print("\nFiles with identical content:")
    for hash, cves in duplicate_content.items():
        print(f"The following CVEs have identical content (hash: {hash}):")
        print(", ".join(cves))
else:
    print("\nNo files with identical content found.")

# Optionally, save the DataFrame to a CSV file
# df.to_csv('cve_keyphrases_validation.csv', index=False)

# Display invalid files for further investigation
if len(df[~df['json_valid']]) > 0:
    print("\nInvalid files:")
    #print(df[~df['json_valid']][['CVE', 'Error']])


# In[67]:


df


# In[68]:


# Sort DataFrame by CVE
df = df.sort_values('CVE')

# Create invalid_df
invalid_df = df[(df['File Size (bytes)'] == 0) | (~df['json_valid'])]
invalid_df = invalid_df.sort_values('File Size (bytes)')
# Save invalid_df to CSV
invalid_csv_path = 'tmp/invalid_cve_keyphrases.csv'
invalid_df.to_csv(invalid_csv_path, index=False)
invalid_df


# In[69]:


invalid_df.Content.value_counts()


# # Find missing keyphrase sections files

# In[70]:


import os
import json
from pathlib import Path

def find_missing_keyphrases(base_dir):
    """
    Find JSON files that are missing the keyphrases section.
    
    Args:
        base_dir (str): Base directory to start the search from
    
    Returns:
        list: List of file paths missing the keyphrases section
    """
    missing_keyphrases = []
    
    # Walk through all subdirectories
    for year_dir in Path(base_dir).iterdir():
        if not year_dir.is_dir() or not year_dir.name.isdigit():
            continue
            
        # Process each xxx subdirectory
        for xxx_dir in year_dir.iterdir():
            if not xxx_dir.is_dir():
                continue
                
            # Process each JSON file
            for json_file in xxx_dir.glob('*.json'):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                    # Check if keyphrases section exists and is a dict
                    if 'keyphrases' not in data or not isinstance(data['keyphrases'], dict):
                        missing_keyphrases.append(str(json_file))
                        
                except json.JSONDecodeError:
                    print(f"Warning: Invalid JSON in file {json_file}")
                except Exception as e:
                    print(f"Error processing {json_file}: {str(e)}")
    
    return missing_keyphrases


# In[71]:


def main():
    # Directory containing the CVE files
    base_dir = "../cve_info"  # Adjust this path as needed
    
    print("Searching for files missing keyphrases section...")
    missing_files = find_missing_keyphrases(base_dir)
    
    if not missing_files:
        print("\nNo files found missing keyphrases section.")
        return
        
    print(f"\nFound {len(missing_files)} files missing keyphrases section:")
    for file_path in sorted(missing_files):
        print(f"- {file_path}")
        
    # Optionally write results to a file
    output_file = "./tmp/missing_keyphrases.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(missing_files))
    print(f"\nResults written to {output_file}")

if __name__ == "__main__":
    main()


# 
