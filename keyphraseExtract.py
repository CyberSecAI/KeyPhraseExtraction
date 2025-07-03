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

# Import both old and new Google AI APIs
try:
    from google import genai
    from google.genai import types
    NEW_API_AVAILABLE = True
except ImportError:
    NEW_API_AVAILABLE = False
    import google.generativeai as genai
    from google.generativeai.types import HarmCategory, HarmBlockThreshold

# Import configuration
from config import GOOGLE_CLOUD_CONFIG, MAIN_MODEL_CONFIG, FALLBACK_MODEL_CONFIG


class KeyPhrases(typing.TypedDict):
    """Response schema for old API compatibility."""
    rootcause: list[str]
    weakness: list[str]
    impact: list[str]
    vector: list[str]
    attacker: list[str]
    product: list[str]
    version: list[str]
    component: list[str]


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
        self.model = None
        self.model_fallback = None
        
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
        """Initialize AI models based on API availability."""
        global NEW_API_AVAILABLE
        
        if NEW_API_AVAILABLE:
            try:
                # Use new VertexAI API
                self.client = self._create_vertexai_client()
                self.config = self._create_vertexai_config()
                logging.info("Using new VertexAI API")
            except Exception as e:
                logging.warning(f"Failed to initialize VertexAI API: {e}")
                logging.info("Falling back to old API")
                NEW_API_AVAILABLE = False
                self.model = self._create_old_api_model()
        else:
            self.model = self._create_old_api_model()
            logging.info("Using legacy Google Generative AI API")

        # Create fallback model (always using standard API)
        self.model_fallback = self._create_old_api_fallback_model()
        
    def _create_vertexai_client(self):
        """Create and return a configured genai client for VertexAI."""
        if not NEW_API_AVAILABLE:
            raise ImportError("New Google AI API not available.")
        
        return genai.Client(
            vertexai=True,
            project=GOOGLE_CLOUD_CONFIG["project"],
            location=GOOGLE_CLOUD_CONFIG["location"],
        )

    def _create_vertexai_config(self):
        """Create generation configuration for VertexAI model."""
        if not NEW_API_AVAILABLE:
            raise ImportError("New Google AI API not available.")
            
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

    def _create_old_api_model(self):
        """Create model using old Google Generative AI API."""
        generation_config = {
            "temperature": MAIN_MODEL_CONFIG["temperature"],
            "top_p": MAIN_MODEL_CONFIG["top_p"],
            "top_k": 40,
            "max_output_tokens": MAIN_MODEL_CONFIG["max_output_tokens"],
            "response_mime_type": "text/plain",
            "response_schema": KeyPhrases,
        }

        safe = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]

        return genai.GenerativeModel(
            model_name="tunedModels/keyphraseextractv010-8vfr4la1aubc",
            generation_config=generation_config,
            safety_settings=safe,    
        )

    def _create_old_api_fallback_model(self):
        """Create fallback model using old Google Generative AI API."""
        generation_config = {
            "temperature": FALLBACK_MODEL_CONFIG["temperature"],
            "top_p": FALLBACK_MODEL_CONFIG["top_p"],
            "top_k": FALLBACK_MODEL_CONFIG["top_k"],
            "max_output_tokens": FALLBACK_MODEL_CONFIG["max_output_tokens"],
            "response_mime_type": FALLBACK_MODEL_CONFIG["response_mime_type"],
        }

        safe = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]

        return genai.GenerativeModel(
            model_name=FALLBACK_MODEL_CONFIG["model_name"],
            generation_config=generation_config,
            safety_settings=safe,    
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
    def generate_and_parse_content(self, model, prompt, cve, use_new_api=False):
        """Generate content and parse JSON with retries."""
        global NEW_API_AVAILABLE
        if use_new_api and NEW_API_AVAILABLE:
            # Use new VertexAI API
            contents = [
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=prompt)]
                )
            ]
            
            response_text = ""
            for chunk in self.client.models.generate_content_stream(
                model=MAIN_MODEL_CONFIG["model_endpoint"],
                contents=contents,
                config=self.config,
            ):
                response_text += chunk.text
        else:
            # Use old API
            response = model.generate_content(prompt)
            response_text = response.text
        
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

    def process_cve(self, row, model, use_new_api=False):
        """Process a single CVE with error handling."""
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
            
            # Generate and parse content with retries
            parsed_json = self.generate_and_parse_content(model, prompt, cve, use_new_api)
            
            # Save the response to the output file
            with open(output_path, 'w') as f:
                json.dump(parsed_json, f, indent=4)
                f.write('\n')
            
            logging.info(f"Processed {cve} and saved results to {output_filename} (API: {'new' if use_new_api else 'old'})")
            return True
        
        except Exception as e:
            logging.error(f"Error processing {cve}: {str(e)}")
            
            # Save error information
            error_info = {
                "cve": cve,
                "error": str(e),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "description": description,
                "api_used": "new" if use_new_api else "old",
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
            
            # Now read the full file with only the needed columns
            df_cve = pd.read_csv(
                self.cve_data_path,
                compression=compression,
                usecols=[cve_col, desc_col]
            )
            
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
        df = df_cve[~df_cve['CVE'].isin(df_already['CVE'])].reset_index(drop=True)
        
        # Clean descriptions
        logging.info("Cleaning descriptions...")
        df['Description'] = df['Description'].apply(self.clean_description)
        df['Description'] = df['Description'].apply(self.clean_linux_vulnerability_description)
        
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
        """Process all CVEs in the dataframe."""
        failed_cves = []
        successful = 0
        total = len(df)
        fallback_attempts = 0
        new_api_attempts = 0

        logging.info(f"Starting processing of {total} CVEs...")

        for index, row in df.iterrows():
            primary_attempts = 0
            max_primary_attempts = 3
            primary_success = False
            
            # Try primary model with new API first if available, then old API
            while primary_attempts < max_primary_attempts:
                try:
                    use_new_api = NEW_API_AVAILABLE and primary_attempts == 0
                    if self.process_cve(row, self.model, use_new_api):
                        successful += 1
                        primary_success = True
                        if use_new_api:
                            new_api_attempts += 1
                        break
                    primary_attempts += 1
                    if primary_attempts < max_primary_attempts:
                        logging.info(f"Retrying primary model for CVE: {row['CVE']} (attempt {primary_attempts + 1})")
                        continue
                        
                except Exception as e:
                    error_str = str(e)
                    if "429 Resource has been exhausted" in error_str:
                        logging.warning("Resource exhaustion detected. Sleeping for 1 hour...")
                        time.sleep(3600)
                        continue
                    primary_attempts += 1
                    if primary_attempts < max_primary_attempts:
                        logging.error(f"Primary model error (attempt {primary_attempts}): {error_str}")
                        continue
            
            # Try fallback model if primary model failed all attempts
            if not primary_success:
                try:
                    if self.process_cve(row, self.model_fallback, False):  # Always use old API for fallback
                        successful += 1
                        fallback_attempts += 1
                        logging.info(f"Fallback model succeeded for CVE: {row['CVE']}")
                    else:
                        failed_cves.append(row['CVE'])
                        logging.warning(f"Both models failed for CVE: {row['CVE']}")
                except Exception as fallback_error:
                    failed_cves.append(row['CVE'])
                    logging.error(f"Fallback model error for CVE {row['CVE']}: {str(fallback_error)}")
            
            # Log progress every 10 CVEs
            if (index + 1) % 10 == 0:
                logging.info(f"Progress: {index + 1}/{total} CVEs processed ({successful} successful, {new_api_attempts} via new API, {fallback_attempts} via fallback)")

        # Save failed CVEs
        if failed_cves:
            with open('failed_cves.txt', 'w') as f:
                for cve in failed_cves:
                    f.write(f"{cve}\n")
            logging.info(f"Saved {len(failed_cves)} failed CVEs to failed_cves.txt")

        logging.info(f"Processing complete. Successful: {successful}/{total} ({new_api_attempts} via new API, {fallback_attempts} via fallback)")
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
        default="../cvelistV5_process/data_out/cve_records.csv",
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