import os
import logging
import time # Import time
from typing import Optional, Dict, Any
from datetime import datetime

import vulncheck_sdk # Import the SDK

logger = logging.getLogger(__name__)

class VulnCheckClient:
    DEFAULT_HOST = "https://api.vulncheck.com"
    DEFAULT_API = DEFAULT_HOST + "/v3"
    MAX_RETRIES = 3
    RETRY_DELAY = 2 # Simple fixed delay for retries

    def __init__(self, api_key: Optional[str]):
        if not api_key:
            logger.warning("VulnCheck API Key not provided. VulnCheck client will not function.")
            self.api_client = None
            self.indices_client = None
            return

        self.api_key = api_key
        configuration = vulncheck_sdk.Configuration(host=self.DEFAULT_API)
        configuration.api_key["Bearer"] = self.api_key
        configuration.retries = self.MAX_RETRIES # Use SDK retry mechanism if available
        # Note: The SDK might have its own retry logic; consult its docs for details.
        # We'll keep a simple manual retry loop as a fallback/example.

        # Create the API client
        self.api_client = vulncheck_sdk.ApiClient(configuration)
        self.indices_client = vulncheck_sdk.IndicesApi(self.api_client)
        # It's good practice to close the client when done, but for a long-running bot,
        # we might keep it open or manage it within request contexts if resource issues arise.

    def _parse_date(self, date_input: Any) -> Optional[str]:
        """Helper to parse date which might be datetime or string."""
        if not date_input:
            return None
        try:
            if isinstance(date_input, datetime):
                # Ensure timezone info for consistent formatting if needed, default to UTC
                # return date_input.isoformat()
                return date_input.strftime('%Y-%m-%dT%H:%M:%S')
            elif isinstance(date_input, str):
                 # Attempt to parse string into datetime then format
                 dt_obj = datetime.fromisoformat(date_input.replace('Z', '+00:00'))
                 return dt_obj.strftime('%Y-%m-%dT%H:%M:%S')
            else:
                logger.warning(f"Unexpected date type: {type(date_input)}")
                return str(date_input) # Fallback to string representation
        except (ValueError, TypeError) as e:
            logger.warning(f"Could not parse date input '{date_input}': {e}")
            return str(date_input) # Fallback

    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        if not self.indices_client:
            logger.debug("VulnCheck client not initialized (no API key).")
            return None

        retries = 0
        while retries <= self.MAX_RETRIES:
            try:
                # Use the index_nist_nvd2_get method for NIST NVD data
                api_response = self.indices_client.index_nist_nvd2_get(cve=cve_id)

                if not api_response or not api_response.data:
                    logger.warning(f"No vulnerability data found for {cve_id} using VulnCheck's NIST NVD2 endpoint.")
                    return None
                
                # Assuming the first result is the most relevant
                # Note: Verify if the structure of api_response.data[0] from index_nist_nvd2_get
                # matches the expected fields below. Adjust mapping if necessary.
                vc_data = api_response.data[0] 

                # --- Map NIST NVD 2.0 fields to our common format ---
                # Based on standard NVD CVE JSON 2.0 Schema
                # Reference: https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
                
                cvss_score = None
                cvss_version = None
                cvss_vector = None
                
                # Check for CVSS v3.x metrics
                if hasattr(vc_data, 'metrics') and hasattr(vc_data.metrics, 'cvss_metric_v31') and vc_data.metrics.cvss_metric_v31:
                    # Take the first CVSS v3.1 metric found (assuming it's primary)
                    metric_v3 = vc_data.metrics.cvss_metric_v31[0]
                    if hasattr(metric_v3, 'cvss_data') and metric_v3.cvss_data:
                        cvss_score = getattr(metric_v3.cvss_data, 'base_score', None)
                        cvss_version = f"3.1 ({getattr(metric_v3.cvss_data, 'base_severity', 'Unknown')})" # Include severity
                        cvss_vector = getattr(metric_v3.cvss_data, 'vector_string', None)
                # Fallback to CVSS v2.0 metrics if v3.x not found
                elif hasattr(vc_data, 'metrics') and hasattr(vc_data.metrics, 'cvss_metric_v2') and vc_data.metrics.cvss_metric_v2:
                     # Take the first CVSS v2.0 metric found
                    metric_v2 = vc_data.metrics.cvss_metric_v2[0]
                    if hasattr(metric_v2, 'cvss_data') and metric_v2.cvss_data:
                        cvss_score = getattr(metric_v2.cvss_data, 'base_score', None)
                        cvss_version = f"2.0 ({getattr(metric_v2, 'base_severity', 'Unknown')})" # Severity might be top-level in v2 metric
                        cvss_vector = getattr(metric_v2.cvss_data, 'vector_string', None)

                cwe_ids = []
                # Check for weaknesses structure
                if hasattr(vc_data, 'weaknesses') and vc_data.weaknesses:
                    for weakness in vc_data.weaknesses:
                        if hasattr(weakness, 'description') and weakness.description:
                            for desc in weakness.description:
                                # Check if the description is in English and contains a CWE ID
                                if getattr(desc, 'lang', '') == 'en' and 'CWE-' in getattr(desc, 'value', ''):
                                    cwe_id = desc.value.split('CWE-')[-1].split(' ')[0].split('<')[0].split(')')[0].strip()
                                    if cwe_id.isdigit(): # Basic validation
                                         cwe_ids.append(f"CWE-{cwe_id}")
                    cwe_ids = sorted(list(set(cwe_ids))) # Deduplicate and sort

                references = []
                if hasattr(vc_data, 'references') and vc_data.references:
                    for ref in vc_data.references:
                         url = getattr(ref, 'url', None) 
                         if url:
                             references.append({
                                 'url': url,
                                 # Use NVD as source if not specified, tags might exist
                                 'source': getattr(ref, 'source', 'NIST NVD'), 
                                 'tags': getattr(ref, 'tags', []) 
                             })

                description = "No description available."
                # Check for descriptions structure (list, filter by lang='en')
                if hasattr(vc_data, 'descriptions') and vc_data.descriptions:
                    for desc in vc_data.descriptions:
                        if getattr(desc, 'lang', '') == 'en':
                            description = getattr(desc, 'value', description)
                            break # Take the first English description

                # Access top-level date fields common in NVD 2.0
                published = self._parse_date(getattr(vc_data, 'published', None)) 
                modified = self._parse_date(getattr(vc_data, 'last_modified', None)) 

                # Construct the common dictionary
                cve_from_data = getattr(vc_data, 'id', cve_id) # NVD 2.0 uses 'id'
                return {
                    'id': cve_from_data, 
                    'title': f"NIST NVD Details for {cve_from_data}", # Updated title
                    'description': description,
                    'published': published,
                    'modified': modified,
                    'cvss': cvss_score,
                    'cvss_version': cvss_version,
                    'cvss_vector': cvss_vector,
                    'cwe_ids': cwe_ids,
                    'references': references,
                    'link': f"https://nvd.nist.gov/vuln/detail/{cve_from_data}", # Link to NVD
                    'source': 'NIST NVD' # Updated source
                }

            except vulncheck_sdk.ApiException as e:
                logger.error(f"VulnCheck API error fetching {cve_id}: {e.status} {e.reason} - {e.body}")
                # Simple retry for potential transient issues (customize as needed)
                if retries < self.MAX_RETRIES:
                    retries += 1
                    logger.warning(f"Retrying VulnCheck fetch for {cve_id} in {self.RETRY_DELAY}s... ({retries}/{self.MAX_RETRIES})")
                    time.sleep(self.RETRY_DELAY)
                    continue
                else:
                    return None # Max retries exceeded
            except Exception as e:
                # Catch other potential errors (network, parsing, etc.)
                logger.error(f"An unexpected error occurred processing {cve_id} with VulnCheck: {e}", exc_info=True)
                return None

        logger.error(f"Failed to fetch {cve_id} from VulnCheck after {self.MAX_RETRIES} retries.")
        return None

    def close(self):
        """Closes the API client connection."""
        if self.api_client:
            try:
                self.api_client.close()
                logger.info("VulnCheck API client closed.")
            except Exception as e:
                logger.error(f"Error closing VulnCheck API client: {e}", exc_info=True) 