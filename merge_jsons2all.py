#!/usr/bin/env python3
"""
CVE JSON File Merger and Consolidator

This script merges CVE description, keyphrases, and technical impact files into
consolidated JSON files. It validates data consistency, normalizes field formats,
and generates comprehensive output files only for CVEs that have keyphrases.

Features:
- Merges multiple CVE data sources (descriptions, keyphrases, technical impacts)
- Validates impact consistency between keyphrases and technical impacts
- Normalizes component fields and ensures required keyphrase fields
- Uses camelCase naming conventions for JSON output
- Generates error logs for validation issues
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import pytz


class CVEDataMerger:
    """Handles merging of CVE data from multiple sources into consolidated files."""
    
    def __init__(self, base_dir: str = "CVEs", output_dir: str = "CVEs/all", version: str = "1.0.0"):
        """
        Initialize the CVE data merger.
        
        Args:
            base_dir: Base directory containing CVE subdirectories
            output_dir: Directory to save merged files
            version: Version string to include in output files
        """
        self.base_dir = Path(base_dir)
        self.output_dir = Path(output_dir)
        self.version = version
        self.timestamp = datetime.now(pytz.UTC).isoformat()
        
        # Required keyphrase fields
        self.required_keyphrase_fields = {
            "rootcause", "weakness", "impact", "vector",
            "attacker", "product", "version", "component"
        }
        
        # CVE data subdirectories to process
        self.subdirs = ['description', 'keyphrases', 'technical_impacts']
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.stats = {
            'processed': 0,
            'errors': 0,
            'skipped_no_keyphrases': 0
        }

    def normalize_keyphrases(self, keyphrases: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure all required fields exist in keyphrases and normalize component fields.
        
        Args:
            keyphrases: Original keyphrases dictionary
        
        Returns:
            Normalized keyphrases dictionary
        """
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
            normalized['component'] = (component_values if len(component_values) > 1 
                                     else (component_values[0] if component_values else ''))
        
        # Ensure all required fields exist
        for field in self.required_keyphrase_fields:
            if field not in normalized:
                normalized[field] = ""
        
        return normalized

    def validate_impacts(self, cve_id: str, keyphrases_impact: Any, impact_texts: List[str]) -> List[str]:
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

    def get_cves_with_keyphrases(self) -> Set[str]:
        """
        Get a set of CVE IDs that have keyphrases files.
        
        Returns:
            Set of CVE IDs that have keyphrases files
        """
        keyphrases_dir = self.base_dir / 'keyphrases'
        if not keyphrases_dir.exists():
            self.logger.warning(f"Keyphrases directory not found: {keyphrases_dir}")
            return set()
        
        cve_ids = set()
        for file_path in keyphrases_dir.glob('CVE-*_*.json'):
            cve_id = file_path.name.split('_')[0]
            cve_ids.add(cve_id)
        
        self.logger.info(f"Found {len(cve_ids)} CVEs with keyphrases files")
        return cve_ids

    def process_file(self, file_path: Path, cve_id: str, subdir: str, cve_data: Dict[str, Any]) -> None:
        """
        Process a single CVE file and add its data to the merged structure.
        
        Args:
            file_path: Path to the file to process
            cve_id: CVE identifier
            subdir: Subdirectory type (description, keyphrases, technical_impacts)
            cve_data: Dictionary to store merged CVE data
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_data = json.load(f)
            
            # Initialize CVE entry if not exists
            if cve_id not in cve_data:
                cve_data[cve_id] = {
                    "cveId": cve_id,
                    "version": self.version,
                    "timestamp": self.timestamp
                }
            
            # Handle different file types
            if 'description' in subdir:
                cve_data[cve_id]['description'] = file_data.get('description', '')
                
            elif 'keyphrases' in subdir:
                # Normalize keyphrases
                normalized_keyphrases = self.normalize_keyphrases(file_data)
                cve_data[cve_id]['keyphrases'] = normalized_keyphrases
                
            elif 'technical_impacts' in subdir:
                # Store impact_texts temporarily for validation (using camelCase in output)
                if 'impact_texts' in file_data:
                    cve_data[cve_id]['_temp_impact_texts'] = file_data['impact_texts']
                if 'mitre_technical_impacts' in file_data:
                    cve_data[cve_id]['mitreTechnicalImpacts'] = file_data['mitre_technical_impacts']
                    
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in file {file_path}: {e}")
            self.stats['errors'] += 1
        except Exception as e:
            self.logger.error(f"Error processing file {file_path}: {e}")
            self.stats['errors'] += 1

    def merge_cve_files(self) -> Tuple[Dict[str, Any], List[str]]:
        """
        Merge JSON files for each CVE ID into a single consolidated structure.
        Only includes CVEs that have keyphrases files.
        
        Returns:
            Tuple of (Dictionary mapping CVE IDs to their consolidated data, List of error messages)
        """
        self.logger.info("Starting CVE file merging process")
        
        # First, get the set of CVEs that have keyphrases files
        cves_with_keyphrases = self.get_cves_with_keyphrases()
        if not cves_with_keyphrases:
            self.logger.warning("No CVEs with keyphrases files found")
            return {}, []
        
        cve_data = {}
        error_logs = []
        
        # Process each type of file
        for subdir in self.subdirs:
            dir_path = self.base_dir / subdir
            if not dir_path.exists():
                self.logger.warning(f"Directory not found: {dir_path}")
                continue
            
            self.logger.info(f"Processing {subdir} files...")
            
            file_count = 0
            for file_path in dir_path.glob('CVE-*_*.json'):
                cve_id = file_path.name.split('_')[0]
                
                # Skip if this CVE doesn't have a keyphrases file
                if cve_id not in cves_with_keyphrases:
                    self.stats['skipped_no_keyphrases'] += 1
                    continue
                
                self.process_file(file_path, cve_id, subdir, cve_data)
                file_count += 1
            
            self.logger.info(f"Processed {file_count} files from {subdir}")
        
        # Validate impacts and clean up temporary data
        self.logger.info("Validating impact consistency...")
        for cve_id, data in cve_data.items():
            if 'keyphrases' in data and '_temp_impact_texts' in data:
                keyphrases_impact = data['keyphrases'].get('impact', '')
                impact_texts = data['_temp_impact_texts']
                
                errors = self.validate_impacts(cve_id, keyphrases_impact, impact_texts)
                error_logs.extend(errors)
            
            # Remove temporary impact_texts
            if '_temp_impact_texts' in data:
                del data['_temp_impact_texts']
        
        self.stats['processed'] = len(cve_data)
        self.logger.info(f"Merged data for {len(cve_data)} CVEs")
        if error_logs:
            self.logger.warning(f"Found {len(error_logs)} impact validation errors")
        
        return cve_data, error_logs

    def save_merged_files(self, cve_data: Dict[str, Any], error_logs: List[str]) -> None:
        """
        Save each merged CVE entry as a separate JSON file and error logs.
        
        Args:
            cve_data: Dictionary containing merged CVE data
            error_logs: List of error messages
        """
        self.logger.info(f"Saving merged files to {self.output_dir}")
        
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save each CVE as a separate file
        saved_count = 0
        for cve_id, data in cve_data.items():
            try:
                file_path = self.output_dir / f"{cve_id}.json"
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
                    f.write('\n')
                saved_count += 1
            except Exception as e:
                self.logger.error(f"Error saving file for {cve_id}: {e}")
                self.stats['errors'] += 1
        
        self.logger.info(f"Saved {saved_count} CVE files")
        
        # Save error logs if any
        if error_logs:
            log_path = self.output_dir / "impact_validation_errors.log"
            try:
                with open(log_path, 'w', encoding='utf-8') as f:
                    f.write("Impact Validation Errors\n")
                    f.write("=" * 50 + "\n")
                    f.write(f"Generated: {self.timestamp}\n\n")
                    for error in error_logs:
                        f.write(f"{error}\n")
                self.logger.info(f"Saved {len(error_logs)} validation errors to {log_path}")
            except Exception as e:
                self.logger.error(f"Error saving error logs: {e}")

    def generate_summary_report(self) -> None:
        """Generate and log a summary report of the merging process."""
        self.logger.info("=== CVE Data Merging Summary ===")
        self.logger.info(f"Successfully processed: {self.stats['processed']} CVEs")
        self.logger.info(f"Skipped (no keyphrases): {self.stats['skipped_no_keyphrases']} files")
        self.logger.info(f"Errors encountered: {self.stats['errors']}")
        self.logger.info(f"Output directory: {self.output_dir}")

    def run(self) -> int:
        """
        Run the complete CVE data merging process.
        
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        try:
            # Merge files and get error logs
            cve_data, error_logs = self.merge_cve_files()
            
            if not cve_data:
                self.logger.warning("No CVEs with keyphrases files found. No files will be created.")
                return 1
            
            # Save merged files and error logs
            self.save_merged_files(cve_data, error_logs)
            
            # Generate summary
            self.generate_summary_report()
            
            return 0
            
        except Exception as e:
            self.logger.error(f"Unexpected error during merging process: {e}")
            return 1


def setup_logging(log_level: str = "INFO") -> None:
    """
    Setup logging configuration.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/merge_jsons2all.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )


def main():
    """Main function to run CVE data merging."""
    parser = argparse.ArgumentParser(
        description="Merge CVE JSON files from multiple sources into consolidated files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Use default directories
  %(prog)s --base-dir ./data --output-dir ./output  # Custom directories
  %(prog)s --version 1.1.0 --log-level DEBUG # Custom version and debug logging
        """
    )
    
    parser.add_argument(
        "--base-dir",
        default="CVEs",
        help="Base directory containing CVE subdirectories (default: CVEs)"
    )
    parser.add_argument(
        "--output-dir",
        default="CVEs/all",
        help="Directory to save merged files (default: CVEs/all)"
    )
    parser.add_argument(
        "--version",
        default="1.0.0",
        help="Version string to include in output files (default: 1.0.0)"
    )
    parser.add_argument(
        "--log-level",
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default="INFO",
        help="Set the logging level (default: INFO)"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    logger = logging.getLogger(__name__)
    logger.info("Starting CVE JSON merging process")
    logger.info(f"Base directory: {args.base_dir}")
    logger.info(f"Output directory: {args.output_dir}")
    logger.info(f"Version: {args.version}")
    
    # Create merger and run
    merger = CVEDataMerger(
        base_dir=args.base_dir,
        output_dir=args.output_dir,
        version=args.version
    )
    
    exit_code = merger.run()
    
    if exit_code == 0:
        logger.info("CVE JSON merging process completed successfully")
    else:
        logger.error("CVE JSON merging process failed")
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())