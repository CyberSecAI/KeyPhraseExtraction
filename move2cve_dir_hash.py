# Usage python3 ./move2cve_dir_hash.py 

import os
import shutil
import re
import hashlib

def get_subdir_name(number):
    num = int(number)
    if num < 10000:  # 0xxx to 9xxx
        return f"{num // 1000:01d}xxx"
    else:
        return f"{num // 1000:02d}xxx"

def calculate_file_hash(filepath):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read the file in chunks to handle large files efficiently
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def organize_cve_files(source_dir, target_dir):
    # Ensure target directory exists
    os.makedirs(target_dir, exist_ok=True)

    # Regular expression to match CVE file names
    cve_pattern = re.compile(r'CVE-(\d{4})-(\d{4,7})\.json')

    # Keep track of statistics
    files_moved = 0
    files_skipped = 0
    files_deleted = 0

    # Iterate through files in the source directory
    for filename in os.listdir(source_dir):
        match = cve_pattern.match(filename)
        if match:
            year, number = match.groups()
            
            # Create year directory
            year_dir = os.path.join(target_dir, year)
            os.makedirs(year_dir, exist_ok=True)
            
            # Create subdirectory based on the custom naming convention
            subdir_name = get_subdir_name(number)
            subdir = os.path.join(year_dir, subdir_name)
            os.makedirs(subdir, exist_ok=True)
            
            # Check if target file already exists
            source_path = os.path.join(source_dir, filename)
            target_path = os.path.join(subdir, filename)
            
            if os.path.exists(target_path):
                # Calculate hashes for both files
                source_hash = calculate_file_hash(source_path)
                target_hash = calculate_file_hash(target_path)
                
                if source_hash == target_hash:
                    print(f"Deleting {filename} from source - identical file exists at {target_path}")
                    os.remove(source_path)
                    files_deleted += 1
                    continue
                else:
                    print(f"Warning: {filename} exists at {target_path} but has different content")
                    print(f"Source hash: {source_hash}")
                    print(f"Target hash: {target_hash}")
                    files_skipped += 1
                    continue
                
            # Move file to new location
            shutil.move(source_path, target_path)
            print(f"Moved {filename} to {target_path}")
            files_moved += 1

    # Print summary
    print("\nSummary:")
    print(f"Files moved: {files_moved}")
    print(f"Files skipped (different content): {files_skipped}")
    print(f"Files deleted (identical): {files_deleted}")
    print("File organization complete.")

if __name__ == "__main__":
    source_directory = "./CVEs/all"  # Replace with your source directory
    target_directory = "../cve_info"  # Replace with your target directory
    
    organize_cve_files(source_directory, target_directory)