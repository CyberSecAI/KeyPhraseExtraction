#!/usr/bin/env python3
"""
CVE Keyphrase Extraction Script

This script processes CVE descriptions to extract structured keyphrases using AI models.
It supports both new VertexAI API and legacy Google Generative AI API with automatic fallback.

Usage:
    python keyphraseExtract.py

Requirements:
    - Google AI credentials configured
    - Required Python packages (see requirements.txt)
    - CVE data file available
"""

import argparse
import concurrent.futures
import csv
import json
import logging
import os
import re
import time
import typing
from pathlib import Path
from typing import Dict, List

import pandas as pd
from tqdm import tqdm
from tenacity import retry, stop_after_attempt, wait_exponential

# Import new Google AI API only
from google import genai
from google.genai import types
NEW_API_AVAILABLE = True

# Import configuration
from config import GOOGLE_CLOUD_CONFIG, MAIN_MODEL_CONFIG, FALLBACK_MODEL_CONFIG


# KeyPhrases schema removed - not needed with new API


class CVEProcessor:
    """Main class for processing CVE descriptions and extracting keyphrases."""
    
    def __init__(self, cve_info_dir="../cve_info", cve_data_path="../cvelistV5_process/data_out/cve_records.csv"):
        """
        Initialize CVE Processor.
        
        Args:
            cve_info_dir: Directory containing existing CVE info
            cve_data_path: Path to CVE data CSV file
        """
        self.cve_info_dir = cve_info_dir
        self.cve_data_path = cve_data_path
        self.output_dir = 'CVEs/keyphrases'
        
        # Initialize models
        self.client = None
        self.config = None
        
        # Setup logging
        self._setup_logging()
        
        # Initialize AI models
        self._initialize_models()
        
    def _setup_logging(self):
        """Setup logging configuration."""
        os.makedirs('logs', exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/cve_processing.log'),
                logging.StreamHandler()
            ]
        )
        
    def _initialize_models(self):
        """Initialize AI models using the new Google AI API."""
        try:
            # Use new VertexAI API
            self.client = self._create_vertexai_client()
            self.config = self._create_vertexai_config()
            logging.info("Using new VertexAI API")
        except Exception as e:
            logging.error(f"Failed to initialize VertexAI API: {e}")
            raise
        
    def _create_vertexai_client(self):
        """Create and return a configured genai client for VertexAI."""
        return genai.Client(
            vertexai=True,
            project=GOOGLE_CLOUD_CONFIG["project"],
            location=GOOGLE_CLOUD_CONFIG["location"],
        )

    def _create_vertexai_config(self):
        """Create generation configuration for VertexAI model."""
        safety_settings = [
            types.SafetySetting(
                category=setting["category"],
                threshold=setting["threshold"]
            ) for setting in MAIN_MODEL_CONFIG["safety_settings"]
        ]
        
        return types.GenerateContentConfig(
            temperature=MAIN_MODEL_CONFIG["temperature"],
            top_p=MAIN_MODEL_CONFIG["top_p"],
            max_output_tokens=MAIN_MODEL_CONFIG["max_output_tokens"],
            safety_settings=safety_settings,
            system_instruction=[types.Part.from_text(text=MAIN_MODEL_CONFIG["system_instruction"])],
        )

    def _create_fallback_config(self):
        """Create generation configuration for fallback model using new API."""
        safety_settings = [
            types.SafetySetting(
                category=setting["category"],
                threshold=setting["threshold"]
            ) for setting in FALLBACK_MODEL_CONFIG["safety_settings"]
        ]
        
        return types.GenerateContentConfig(
            temperature=FALLBACK_MODEL_CONFIG["temperature"],
            top_p=FALLBACK_MODEL_CONFIG["top_p"],
            max_output_tokens=FALLBACK_MODEL_CONFIG["max_output_tokens"],
            safety_settings=safety_settings,
            system_instruction=[types.Part.from_text(text=FALLBACK_MODEL_CONFIG["system_instruction"])],
        )

    @staticmethod
    def read_json_file(file_path: str) -> Dict:
        """Read a single JSON file and return its contents with the filename."""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                data['source_file'] = os.path.basename(file_path)
                return data
        except Exception as e:
            logging.error(f"Error reading {file_path}: {e}")
            return None

    @staticmethod
    def find_cve_files(directory: str) -> List[str]:
        """Find all CVE JSON files recursively."""
        cve_files = []
        directory = Path(directory)
        
        try:
            for root, _, files in os.walk(directory):
                root_path = Path(root)
                for filename in files:
                    if filename.startswith("CVE-") and filename.endswith(".json"):
                        file_path = root_path / filename
                        cve_files.append(str(file_path))
        except Exception as e:
            logging.error(f"Error accessing directory {directory}: {e}")
            return []
        
        return sorted(cve_files)

    def create_cve_dataframe(self, max_workers: int = 4) -> pd.DataFrame:
        """
        Create a DataFrame from all CVE JSON files in the directory.
        
        Args:
            max_workers: Number of parallel workers for file reading
            
        Returns:
            DataFrame containing all CVE data
        """
        cve_files = self.find_cve_files(self.cve_info_dir)
        logging.info(f"Found {len(cve_files)} CVE files")
        
        all_data = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for data in tqdm(executor.map(self.read_json_file, cve_files), 
                            total=len(cve_files), 
                            desc="Reading CVE files"):
                if data is not None:
                    all_data.append(data)
        
        df_already = pd.DataFrame(all_data)
        logging.info(f"Created DataFrame with {len(df_already)} rows")
        return df_already

    @staticmethod
    def clean_description(text):
        """Clean and normalize CVE description text."""
        if pd.isna(text) or text is None:
            return ""
        
        try:
            text = str(text)
        except:
            return ""
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        # Remove single quotes, double quotes, newlines, colons, and semicolons
        text = re.sub(r"['\"'\n\r:;]", "", text)
        # Remove non-ASCII characters
        text = re.sub(r'[^\x00-\x7F]+', '', text)
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text

    @staticmethod
    def clean_linux_vulnerability_description(description: str) -> str:
        """Clean Linux kernel vulnerability descriptions by removing debug traces."""
        if not description.startswith('In the Linux kernel, the following vulnerability'):
            return description
        
        # Split at first occurrence of timestamp or debug trace
        main_description = re.split(r'\[\d+\.\d+\]|\[#', description)[0].strip()
        
        # If the description contains "BUG kernel", trim everything after it
        bug_index = main_description.find('BUG kernel')
        if bug_index != -1:
            main_description = main_description[:bug_index].strip()
        
        return main_description

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        reraise=True
    )
    def generate_and_parse_content(self, prompt, cve, use_fallback=False):
        """Generate content and parse JSON using new API only."""
        contents = [
            types.Content(
                role="user",
                parts=[types.Part.from_text(text=prompt)]
            )
        ]
        
        # Choose model and config based on use_fallback
        if use_fallback:
            model_endpoint = FALLBACK_MODEL_CONFIG["model_name"]
            config = self._create_fallback_config()
        else:
            model_endpoint = MAIN_MODEL_CONFIG["model_endpoint"]
            config = self.config
        
        response_text = ""
        for chunk in self.client.models.generate_content_stream(
            model=model_endpoint,
            contents=contents,
            config=config,
        ):
            response_text += chunk.text
        
        try:
            # Try to parse the JSON response
            parsed_json = json.loads(response_text)
            return parsed_json
        except json.JSONDecodeError:
            # If JSON parsing fails, try to clean/fix the response
            cleaned_response = response_text.strip()
            if not cleaned_response.startswith('{'):
                raise ValueError(f"Invalid JSON response for {cve}")
            # Remove any trailing text after the last '}'
            last_brace = cleaned_response.rindex('}')
            cleaned_response = cleaned_response[:last_brace + 1]
            return json.loads(cleaned_response)

    def process_cve(self, row, use_fallback=False):
        """Process a single CVE with error handling using new API only."""
        cve = row['CVE']
        description = row['Description']
        output_filename = f"{cve}_keyphrases.json"
        output_path = os.path.join(self.output_dir, output_filename)
        error_path = os.path.join("logs", 'error_logs', f"{cve}_error.json")
        
        # Create directories if they don't exist
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join("logs", 'error_logs'), exist_ok=True)
        
        # Skip if already processed successfully
        if os.path.exists(output_path):
            logging.info(f"Skipping {cve} - already processed")
            return True
        
        try:
            prompt = "<INSTRUCTION>Only use these json fields:rootcause, weakness, impact, vector, attacker, product, version, component</INSTRUCTION>" + description
            
            # Generate and parse content with retries and timeout
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError("API call timed out after 5 minutes")
            
            # Set timeout for 5 minutes
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(300)  # 5 minutes
            
            try:
                parsed_json = self.generate_and_parse_content(prompt, cve, use_fallback)
            finally:
                signal.alarm(0)  # Cancel the alarm
            
            # Save the response to the output file
            with open(output_path, 'w') as f:
                json.dump(parsed_json, f, indent=4)
                f.write('\n')
            
            model_type = "fallback" if use_fallback else "primary"
            logging.info(f"Processed {cve} and saved results to {output_filename} (API: new, model: {model_type})")
            return True
        
        except Exception as e:
            logging.error(f"Error processing {cve}: {str(e)}")
            
            # Save error information
            error_info = {
                "cve": cve,
                "error": str(e),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "description": description,
                "api_used": "new",
                "model_type": "fallback" if use_fallback else "primary",
                "raw_response": getattr(e, 'response', {}).get('text', None) if hasattr(e, 'response') else None
            }
            
            # Save error details to a separate file
            with open(error_path, 'w') as f:
                json.dump(error_info, f, indent=4)
                f.write('\n')
            
            logging.info(f"Saved error details to {error_path}")
            return False

    def _detect_column_names(self, df):
        """Detect CVE ID and description column names from the dataframe."""
        columns = df.columns.tolist()
        cve_col = None
        desc_col = None
        
        # Common patterns for CVE ID column
        cve_patterns = ['cve', 'cveid', 'cve_id', 'id', 'identifier']
        for pattern in cve_patterns:
            matches = [col for col in columns if pattern.lower() in col.lower()]
            if matches:
                cve_col = matches[0]
                break
        
        # Common patterns for description column
        desc_patterns = ['description', 'desc', 'summary', 'text', 'details']
        for pattern in desc_patterns:
            matches = [col for col in columns if pattern.lower() in col.lower()]
            if matches:
                desc_col = matches[0]
                break
        
        if not cve_col:
            # Try to find column with CVE-like values
            for col in columns:
                sample_values = df[col].dropna().astype(str).head(10)
                if any(val.startswith('CVE-') for val in sample_values):
                    cve_col = col
                    break
        
        if not desc_col:
            # Find column with longest text values (likely description)
            text_cols = df.select_dtypes(include=['object']).columns
            if len(text_cols) > 0:
                avg_lengths = {col: df[col].astype(str).str.len().mean() for col in text_cols if col != cve_col}
                if avg_lengths:
                    desc_col = max(avg_lengths, key=avg_lengths.get)
        
        return cve_col, desc_col
    
    def _save_cves_to_process_csv(self, df_to_process, df_all_cves, df_already):
        """Save detailed information about CVEs to be processed to CSV file."""
        os.makedirs('logs', exist_ok=True)
        
        # Create summary CSV with processing status
        summary_data = []
        
        for _, row in df_all_cves.iterrows():
            cve_id = row['CVE']
            description = row['Description']
            
            # Determine processing status
            if cve_id in df_already['CVE'].values:
                status = 'already_processed'
            elif cve_id in df_to_process['CVE'].values:
                status = 'to_be_processed'
            else:
                status = 'filtered_out'
            
            # Add additional fields if available
            additional_fields = {}
            if 'state' in row:
                additional_fields['state'] = row['state']
            if 'rejected_reason' in row:
                additional_fields['rejected_reason'] = row.get('rejected_reason', '')
            
            summary_data.append({
                'cve_id': cve_id,
                'description': description[:200] + '...' if len(str(description)) > 200 else description,
                'description_length': len(str(description)) if pd.notna(description) else 0,
                'processing_status': status,
                **additional_fields
            })
        
        # Save summary CSV
        summary_df = pd.DataFrame(summary_data)
        summary_path = 'logs/cve_processing_summary.csv'
        summary_df.to_csv(summary_path, index=False)
        logging.info(f"Saved CVE processing summary to {summary_path}")
        
        # Save list of CVEs to be processed (detailed)
        if len(df_to_process) > 0:
            to_process_path = 'logs/cves_to_process.csv'
            df_to_process.to_csv(to_process_path, index=False)
            logging.info(f"Saved {len(df_to_process)} CVEs to be processed to {to_process_path}")
        
        # Log summary statistics
        total_cves = len(df_all_cves)
        already_processed = len(df_already)
        to_process = len(df_to_process)
        filtered_out = total_cves - already_processed - to_process
        
        logging.info(f"CVE Processing Summary:")
        logging.info(f"  Total CVEs in source: {total_cves}")
        logging.info(f"  Already processed: {already_processed}")
        logging.info(f"  To be processed: {to_process}")
        logging.info(f"  Filtered out: {filtered_out}")
    
    def load_and_prepare_data(self):
        """Load CVE data and prepare for processing."""
        logging.info("Loading existing CVE data...")
        
        # Create DataFrame of already processed CVEs
        df_already = self.create_cve_dataframe()
        df_already.to_csv("./logs/keyphrases_already.csv", index=False)
        
        # Load new CVE data
        logging.info(f"Loading new CVE data from {self.cve_data_path}...")
        
        # Determine if file is compressed
        compression = 'gzip' if self.cve_data_path.endswith('.gz') else None
        
        # First, read a small sample to detect column names
        try:
            sample_df = pd.read_csv(
                self.cve_data_path,
                nrows=100,
                compression=compression
            )
            
            cve_col, desc_col = self._detect_column_names(sample_df)
            
            if not cve_col or not desc_col:
                logging.error(f"Could not detect CVE ID and description columns. Available columns: {sample_df.columns.tolist()}")
                raise ValueError("Unable to detect required columns in the CVE data file")
            
            logging.info(f"Detected columns - CVE ID: '{cve_col}', Description: '{desc_col}'")
            
            # Read columns we need: CVE ID, description, state, and rejected_reason
            required_cols = [cve_col, desc_col]
            additional_cols = []
            
            # Check if state and rejected_reason columns exist
            if 'state' in sample_df.columns:
                additional_cols.append('state')
            if 'rejected_reason' in sample_df.columns:
                additional_cols.append('rejected_reason')
            
            all_cols = required_cols + additional_cols
            
            df_cve = pd.read_csv(
                self.cve_data_path,
                compression=compression,
                usecols=all_cols
            )
            
            # Handle rejected CVEs - use rejected_reason as description if available
            if 'rejected_reason' in df_cve.columns and 'state' in df_cve.columns:
                # For rejected CVEs with empty descriptions, use rejected_reason
                rejected_mask = (df_cve['state'] == 'REJECTED') & (df_cve[desc_col].fillna('').str.strip() == '')
                df_cve.loc[rejected_mask, desc_col] = df_cve.loc[rejected_mask, 'rejected_reason']
                
                # Filter out rejected CVEs that still have no meaningful description
                df_cve = df_cve[
                    (df_cve['state'] != 'REJECTED') | 
                    (df_cve[desc_col].fillna('').str.strip() != '')
                ].reset_index(drop=True)
            
            # Rename columns to standard names
            df_cve = df_cve.rename(columns={cve_col: 'CVE', desc_col: 'Description'})
            
        except Exception as e:
            logging.error(f"Error loading CVE data: {e}")
            # Fallback to original method for backward compatibility
            try:
                df_cve = pd.read_csv(
                    self.cve_data_path, 
                    quoting=csv.QUOTE_ALL, 
                    escapechar='\\', 
                    compression=compression, 
                    usecols=['CVE', 'Description']
                )
            except Exception as fallback_error:
                logging.error(f"Fallback loading also failed: {fallback_error}")
                raise
        
        logging.info(f"Loaded {len(df_cve)} CVE records")
        
        # Remove already processed CVEs
        df_already = df_already.rename(columns={'cveId': 'CVE'})
        logging.info(f"Filtering {len(df_cve)} CVEs against {len(df_already)} existing ones...")
        
        # Optimize filtering by converting to set first for better performance
        existing_cves_set = set(df_already['CVE'].values)
        logging.info(f"Created set of {len(existing_cves_set)} existing CVEs")
        
        # Use vectorized string operations for better performance
        df = df_cve[~df_cve['CVE'].isin(existing_cves_set)].reset_index(drop=True)
        logging.info(f"Filtering complete. Found {len(df)} new CVEs to process")
        
        # Save simple list of CVEs to be processed to CSV
        if len(df) > 0:
            os.makedirs('logs', exist_ok=True)
            to_process_path = 'logs/cves_to_process.csv'
            df.to_csv(to_process_path, index=False)
            logging.info(f"Saved {len(df)} CVEs to be processed to {to_process_path}")
        
        # Log summary statistics
        logging.info(f"Processing summary: {len(df_already)} already processed, {len(df)} new CVEs to process")
        
        # Clean descriptions
        logging.info("Cleaning descriptions...")
        df['Description'] = df['Description'].apply(self.clean_description)
        df['Description'] = df['Description'].apply(self.clean_linux_vulnerability_description)
        
        # Filter out CVEs with invalid descriptions
        initial_count = len(df)
        df = df[
            (df['Description'].notna()) &
            (df['Description'].str.strip() != '') &
            (~df['Description'].str.contains('DO NOT USE THIS CANDIDATE NUMBER', case=False, na=False)) &
            (~df['Description'].str.contains('ConsultIDs', case=False, na=False)) &
            (~df['Description'].str.contains('Reason This candidate is a duplicate', case=False, na=False))
        ].reset_index(drop=True)
        
        filtered_count = initial_count - len(df)
        if filtered_count > 0:
            logging.info(f"Filtered out {filtered_count} CVEs with invalid descriptions")
        
        # Save individual description files
        logging.info("Saving description files...")
        os.makedirs("CVEs/description", exist_ok=True)
        for index, row in df.iterrows():
            data = {"description": row['Description']}
            filename = f"CVEs/description/{row['CVE']}_description.json"
            
            if not os.path.exists(filename):
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=4)
        
        logging.info(f"Prepared {len(df)} CVEs for processing")
        return df

    def process_all_cves(self, df):
        """Process all CVEs in the dataframe using new API only."""
        failed_cves = []
        successful = 0
        total = len(df)
        fallback_attempts = 0
        primary_attempts = 0

        logging.info(f"Starting processing of {total} CVEs...")

        for index, row in df.iterrows():
            attempts = 0
            max_attempts = 3
            cve_success = False
            
            # Try primary model first, then fallback if needed
            while attempts < max_attempts and not cve_success:
                try:
                    use_fallback = attempts > 0  # Use fallback after first attempt fails
                    if self.process_cve(row, use_fallback):
                        successful += 1
                        cve_success = True
                        if use_fallback:
                            fallback_attempts += 1
                        else:
                            primary_attempts += 1
                        break
                    attempts += 1
                    if attempts < max_attempts:
                        model_type = "fallback" if use_fallback else "primary"
                        logging.info(f"Retrying CVE {row['CVE']} with {'fallback' if attempts > 0 else 'primary'} model (attempt {attempts + 1})")
                        continue
                        
                except Exception as e:
                    error_str = str(e)
                    
                    # Handle different types of errors
                    if "429 Resource has been exhausted" in error_str or "quota" in error_str.lower():
                        logging.warning("Rate limit/quota exhaustion detected. Sleeping for 1 hour...")
                        time.sleep(3600)
                        continue
                    elif ("timeout" in error_str.lower() or "connection" in error_str.lower() or 
                          "TimeoutError" in error_str or "API call timed out" in error_str):
                        logging.warning(f"Connection/timeout error: {error_str}. Sleeping for 30 seconds...")
                        time.sleep(30)
                        attempts += 1
                        if attempts < max_attempts:
                            continue
                    elif "500" in error_str or "502" in error_str or "503" in error_str or "504" in error_str:
                        logging.warning(f"Server error: {error_str}. Sleeping for 60 seconds...")
                        time.sleep(60)
                        attempts += 1
                        if attempts < max_attempts:
                            continue
                    else:
                        attempts += 1
                        if attempts < max_attempts:
                            model_type = "fallback" if use_fallback else "primary"
                            logging.error(f"{model_type.title()} model error (attempt {attempts}): {error_str}")
                            time.sleep(5)  # Brief pause before retry
                            continue
            
            # If all attempts failed
            if not cve_success:
                failed_cves.append(row['CVE'])
                logging.error(f"All attempts failed for CVE: {row['CVE']}")
            
            # Log progress every 10 CVEs
            if (index + 1) % 10 == 0:
                logging.info(f"Progress: {index + 1}/{total} CVEs processed ({successful} successful, {primary_attempts} via primary, {fallback_attempts} via fallback)")

        # Save failed CVEs
        if failed_cves:
            with open('failed_cves.txt', 'w') as f:
                for cve in failed_cves:
                    f.write(f"{cve}\n")
            logging.info(f"Saved {len(failed_cves)} failed CVEs to failed_cves.txt")

        logging.info(f"Processing complete. Successful: {successful}/{total} ({primary_attempts} via primary, {fallback_attempts} via fallback)")
        return successful, failed_cves

    def run(self):
        """Main execution method."""
        logging.info("Starting CVE keyphrase extraction process...")
        
        # Load and prepare data
        df = self.load_and_prepare_data()
        
        if len(df) == 0:
            logging.info("No new CVEs to process.")
            return
        
        # Process all CVEs
        successful, failed = self.process_all_cves(df)
        
        logging.info("CVE keyphrase extraction process completed.")
        logging.info(f"Summary: {successful} successful, {len(failed)} failed")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Extract keyphrases from CVE descriptions using AI models")
    parser.add_argument(
        "--cve-info-dir", 
        default="../cve_info",
        help="Directory containing existing CVE info (default: ../cve_info)"
    )
    parser.add_argument(
        "--cve-data-path", 
        default="../cvelistV5_process/data_out/cve_records_published.csv",
        help="Path to CVE data CSV file (default: ../cvelistV5_process/data_out/cve_records_published.csv)"
    )
    
    args = parser.parse_args()
    
    try:
        processor = CVEProcessor(
            cve_info_dir=args.cve_info_dir,
            cve_data_path=args.cve_data_path
        )
        processor.run()
    except KeyboardInterrupt:
        logging.info("Process interrupted by user")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise


if __name__ == "__main__":
    main()