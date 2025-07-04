#!/usr/bin/env python3
"""
CVE Keyphrase Validation and Quality Control Script

This script validates CVE keyphrase JSON files, checks for duplicates,
moves invalid files, and identifies missing keyphrases in the CVE repository.
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pandas as pd


class CVEKeyphraseValidator:
    """Validates CVE keyphrase JSON files and manages quality control."""
    
    def __init__(self, input_dir: str = 'CVEs/keyphrases/', invalid_dir: str = './CVEs/invalid'):
        self.input_dir = input_dir
        self.invalid_dir = invalid_dir
        self.expected_fields = {'rootcause', 'weakness', 'impact', 'vector', 
                               'attacker', 'product', 'version', 'component'}
        self.content_hashes: Dict[str, List[str]] = {}
        self.results: List[Dict] = []
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Create directories
        os.makedirs(self.invalid_dir, exist_ok=True)
        os.makedirs('logs', exist_ok=True)

    def is_empty_keyphrases(self, json_content: Dict) -> bool:
        """
        Check if all keyphrase fields are empty or contain only whitespace.
        
        Args:
            json_content: The JSON content to check
            
        Returns:
            True if all keyphrase fields are empty, False otherwise
        """
        for field in self.expected_fields:
            if field in json_content:
                value = json_content[field]
                if isinstance(value, str) and value.strip():
                    return False
                elif value and not isinstance(value, str):
                    return False
        return True

    def has_single_keyphrase(self, json_content: Dict) -> bool:
        """
        Check if exactly one keyphrase field contains content.
        
        Args:
            json_content: The JSON content to check
            
        Returns:
            True if exactly one keyphrase field has content, False otherwise
        """
        non_empty_count = 0
        for field in self.expected_fields:
            if field in json_content:
                value = json_content[field]
                if isinstance(value, str) and value.strip():
                    non_empty_count += 1
                elif value and not isinstance(value, str):
                    non_empty_count += 1
        return non_empty_count == 1

    def validate_json_content(self, file_path: str) -> Tuple[bool, Dict, Optional[Dict], Optional[str]]:
        """
        Validate JSON content of a keyphrase file.
        
        Args:
            file_path: Path to the JSON file
            
        Returns:
            Tuple of (is_valid, issues, json_content, raw_content)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
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
            extra_fields = set(json_content.keys()) - self.expected_fields
            if extra_fields:
                issues['extra_fields'] = list(extra_fields)

            # Check for missing fields
            missing_fields = self.expected_fields - set(json_content.keys())
            if missing_fields:
                issues['missing_fields'] = list(missing_fields)

            # Check for duplicated fields (shouldn't be possible in valid JSON, but check anyway)
            duplicated_fields = [field for field in json_content.keys() 
                               if list(json_content.keys()).count(field) > 1]
            if duplicated_fields:
                issues['duplicated_fields'] = duplicated_fields

            # Check for empty keyphrase content
            if self.is_empty_keyphrases(json_content):
                issues['empty_keyphrases'] = 'All keyphrase fields are empty or contain only whitespace'
            
            # Check for single keyphrase content
            if self.has_single_keyphrase(json_content):
                issues['single_keyphrase'] = 'Only one keyphrase field contains content'

            is_valid = not bool(issues)
            return is_valid, issues, json_content, content

        except json.JSONDecodeError:
            return False, {'error': 'Invalid JSON'}, None, None
        except Exception as e:
            return False, {'error': str(e)}, None, None

    def process_file(self, filename: str) -> Dict:
        """
        Process a single keyphrase file.
        
        Args:
            filename: Name of the keyphrase file
            
        Returns:
            Dictionary with file analysis results
        """
        # Extract CVE from filename
        cve = filename.replace('_keyphrases.json', '')
        
        # Get full file paths
        file_path = os.path.join(self.input_dir, filename)
        invalid_path = os.path.join(self.invalid_dir, filename)
        
        # Get file size in bytes
        file_size = os.path.getsize(file_path)
        
        # Validate JSON content
        is_valid, issues, json_content, raw_content = self.validate_json_content(file_path)
        
        # Calculate hash of the content if valid
        content_hash = None
        if raw_content:
            content_hash = hashlib.md5(raw_content.encode()).hexdigest()
            if content_hash in self.content_hashes:
                self.content_hashes[content_hash].append(cve)
            else:
                self.content_hashes[content_hash] = [cve]
        
        # Move invalid files to invalid directory
        if not is_valid:
            try:
                shutil.move(file_path, invalid_path)
                self.logger.info(f"Moved invalid file {filename} to {self.invalid_dir}")
            except Exception as e:
                self.logger.error(f"Error moving file {filename}: {str(e)}")
        
        return {
            'CVE': cve, 
            'File Size (bytes)': file_size,
            'json_valid': is_valid,
            'Content Hash': content_hash,
            'Content' if is_valid else 'Issues': json_content if is_valid else issues
        }

    def validate_all_files(self) -> pd.DataFrame:
        """
        Validate all keyphrase files in the input directory.
        
        Returns:
            DataFrame with validation results
        """
        self.logger.info(f"Starting validation of files in {self.input_dir}")
        
        keyphrase_files = [f for f in os.listdir(self.input_dir) 
                          if f.endswith('_keyphrases.json')]
        
        self.logger.info(f"Found {len(keyphrase_files)} keyphrase files to validate")
        
        for filename in keyphrase_files:
            result = self.process_file(filename)
            self.results.append(result)
        
        # Create DataFrame
        df = pd.DataFrame(self.results)
        if not df.empty:
            df = df.sort_values('CVE')
        
        return df

    def generate_report(self, df: pd.DataFrame) -> None:
        """
        Generate and display validation report.
        
        Args:
            df: DataFrame with validation results
        """
        if df.empty:
            self.logger.info("No files to validate")
            return
            
        valid_count = df['json_valid'].sum()
        invalid_count = len(df) - valid_count
        
        # Count empty keyphrase files
        empty_count = 0
        single_count = 0
        for result in self.results:
            if not result['json_valid'] and isinstance(result.get('Issues'), dict):
                if 'empty_keyphrases' in result['Issues']:
                    empty_count += 1
                if 'single_keyphrase' in result['Issues']:
                    single_count += 1
        
        # Count zero-byte files
        zero_byte_count = len(df[df['File Size (bytes)'] == 0])
        
        self.logger.info(f"Validation Summary:")
        self.logger.info(f"  Total CVEs processed: {len(df)}")
        self.logger.info(f"  Valid JSON files: {valid_count}")
        self.logger.info(f"  Invalid JSON files: {invalid_count}")
        self.logger.info(f"  Zero-byte files: {zero_byte_count}")
        self.logger.info(f"  Empty keyphrase files: {empty_count}")
        self.logger.info(f"  Single keyphrase files: {single_count}")
        
        # Check for duplicate content
        duplicate_content = {hash_val: cves for hash_val, cves in self.content_hashes.items() 
                           if len(cves) > 1}
        
        if duplicate_content:
            self.logger.warning("Files with identical content found:")
            for hash_val, cves in duplicate_content.items():
                self.logger.warning(f"  Hash {hash_val}: {', '.join(cves)}")
        else:
            self.logger.info("  No files with identical content found")
        
        # Save reports
        self.save_reports(df)

    def save_reports(self, df: pd.DataFrame) -> None:
        """
        Save validation reports to files.
        
        Args:
            df: DataFrame with validation results
        """
        try:
            # Save invalid files report
            invalid_df = df[(df['File Size (bytes)'] == 0) | (~df['json_valid'])]
            if not invalid_df.empty:
                invalid_df = invalid_df.sort_values('File Size (bytes)')
                invalid_csv_path = 'logs/invalid_cve_keyphrases.csv'
                invalid_df.to_csv(invalid_csv_path, index=False)
                self.logger.info(f"Invalid files report saved to {invalid_csv_path}")
            
            # Save empty keyphrase files report
            empty_files = []
            single_files = []
            for result in self.results:
                if not result['json_valid'] and isinstance(result.get('Issues'), dict):
                    if 'empty_keyphrases' in result['Issues']:
                        empty_files.append(result['CVE'])
                    if 'single_keyphrase' in result['Issues']:
                        single_files.append(result['CVE'])
            
            if empty_files:
                empty_csv_path = 'logs/empty_keyphrases.txt'
                with open(empty_csv_path, 'w', encoding='utf-8') as f:
                    f.write("Files with empty keyphrase content:\n")
                    f.write("=" * 50 + "\n")
                    for cve in sorted(empty_files):
                        f.write(f"{cve}\n")
                self.logger.info(f"Empty keyphrase files report saved to {empty_csv_path}")
            
            if single_files:
                single_csv_path = 'logs/single_keyphrases.txt'
                with open(single_csv_path, 'w', encoding='utf-8') as f:
                    f.write("Files with only one keyphrase field containing content:\n")
                    f.write("=" * 60 + "\n")
                    for cve in sorted(single_files):
                        f.write(f"{cve}\n")
                self.logger.info(f"Single keyphrase files report saved to {single_csv_path}")
            
            # Save validation summary
            validation_csv_path = 'logs/cve_keyphrases_validation.csv'
            df[['CVE', 'File Size (bytes)', 'json_valid', 'Content Hash']].to_csv(
                validation_csv_path, index=False)
            self.logger.info(f"Validation summary saved to {validation_csv_path}")
            
        except Exception as e:
            self.logger.error(f"Error saving reports: {e}")


class CVEKeyphraseChecker:
    """Checks for missing keyphrases in the CVE repository."""
    
    def __init__(self, base_dir: str = "../cve_info"):
        self.base_dir = base_dir
        self.logger = logging.getLogger(__name__)

    def find_missing_keyphrases(self) -> List[str]:
        """
        Find JSON files that are missing the keyphrases section.
        
        Returns:
            List of file paths missing the keyphrases section
        """
        missing_keyphrases = []
        
        if not os.path.exists(self.base_dir):
            self.logger.error(f"Base directory {self.base_dir} does not exist")
            return missing_keyphrases
        
        self.logger.info(f"Searching for missing keyphrases in {self.base_dir}")
        
        # Walk through all subdirectories
        for year_dir in Path(self.base_dir).iterdir():
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
                        self.logger.warning(f"Invalid JSON in file {json_file}")
                    except Exception as e:
                        self.logger.error(f"Error processing {json_file}: {str(e)}")
        
        return missing_keyphrases

    def save_missing_keyphrases_report(self, missing_files: List[str]) -> None:
        """
        Save missing keyphrases report to file.
        
        Args:
            missing_files: List of files missing keyphrases
        """
        if not missing_files:
            self.logger.info("No files found missing keyphrases section")
            return
            
        self.logger.info(f"Found {len(missing_files)} files missing keyphrases section")
        
        # Save to logs directory
        output_file = "logs/missing_keyphrases.txt"
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("Files missing keyphrases section:\n")
                f.write("=" * 50 + "\n")
                for file_path in sorted(missing_files):
                    f.write(f"{file_path}\n")
            
            self.logger.info(f"Missing keyphrases report saved to {output_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving missing keyphrases report: {e}")


def main():
    """Main function to run CVE keyphrase validation and checking."""
    parser = argparse.ArgumentParser(
        description="Validate CVE keyphrase files and check for missing keyphrases"
    )
    parser.add_argument(
        "--input-dir", 
        default="CVEs/keyphrases/",
        help="Directory containing keyphrase files (default: CVEs/keyphrases/)"
    )
    parser.add_argument(
        "--invalid-dir", 
        default="./CVEs/invalid",
        help="Directory to move invalid files (default: ./CVEs/invalid)"
    )
    parser.add_argument(
        "--cve-info-dir", 
        default="../cve_info",
        help="Directory containing CVE info files (default: ../cve_info)"
    )
    parser.add_argument(
        "--skip-validation", 
        action="store_true",
        help="Skip keyphrase file validation"
    )
    parser.add_argument(
        "--skip-missing-check", 
        action="store_true",
        help="Skip missing keyphrases check"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/cve_validation.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info("Starting CVE keyphrase validation and checking")
    
    try:
        # Validate keyphrase files
        if not args.skip_validation:
            logger.info("=== Starting Keyphrase File Validation ===")
            validator = CVEKeyphraseValidator(args.input_dir, args.invalid_dir)
            df = validator.validate_all_files()
            validator.generate_report(df)
        
        # Check for missing keyphrases
        if not args.skip_missing_check:
            logger.info("=== Starting Missing Keyphrases Check ===")
            checker = CVEKeyphraseChecker(args.cve_info_dir)
            missing_files = checker.find_missing_keyphrases()
            checker.save_missing_keyphrases_report(missing_files)
        
        logger.info("CVE keyphrase validation and checking completed")
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())