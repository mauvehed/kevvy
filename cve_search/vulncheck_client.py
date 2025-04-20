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
                # Use the index_vulncheck_nvd2_get method as per VulnCheck SDK examples
                api_response = self.indices_client.index_vulncheck_nvd2_get(cve=cve_id)

                if not api_response or not api_response.data:
                    logger.warning(f"No vulnerability data found for {cve_id} in VulnCheck NVD2 response.")
                    return None
                
                # Assuming the first result is the most relevant
                vc_data = api_response.data[0] 

                # --- Map VulnCheck fields to our common format --- 
                # Mapping requires inspecting the actual structure of vc_data 
                # (which corresponds to V3IndexVulncheckNvd2 models in the SDK) 
                # This is a likely structure based on common vulnerability data models
                
                cvss_score = None
                cvss_version = None
                cvss_vector = None
                # VulnCheck SDK might structure metrics differently. Need to inspect vc_data attributes.
                # Example hypothetical access:
                if hasattr(vc_data, 'cvssv3_score') and vc_data.cvssv3_score:
                    cvss_score = vc_data.cvssv3_score
                    cvss_version = '3.x' # Version might be more specific
                    if hasattr(vc_data, 'cvssv3_vector'):
                        cvss_vector = vc_data.cvssv3_vector
                elif hasattr(vc_data, 'cvssv2_score') and vc_data.cvssv2_score:
                    cvss_score = vc_data.cvssv2_score
                    cvss_version = '2.0'
                    if hasattr(vc_data, 'cvssv2_vector'):
                        cvss_vector = vc_data.cvssv2_vector
                
                cwe_ids = []
                if hasattr(vc_data, 'cwe') and vc_data.cwe:
                    # Assuming vc_data.cwe is a list of strings
                    cwe_ids = sorted(list(set(vc_data.cwe)))

                references = []
                if hasattr(vc_data, 'references') and vc_data.references:
                    for ref in vc_data.references:
                         # Assuming ref is a dictionary-like object or has url attribute
                         url = getattr(ref, 'url', None) 
                         if url:
                             references.append({
                                 'url': url,
                                 'source': getattr(ref, 'source', 'VulnCheck'), # Guessing field names
                                 'tags': getattr(ref, 'tags', [])
                             })

                description = getattr(vc_data, 'summary', "No description available.") # Guessing field name
                published = self._parse_date(getattr(vc_data, 'published_date', None)) # Guessing
                modified = self._parse_date(getattr(vc_data, 'modified_date', None)) # Guessing

                # Construct the common dictionary
                return {
                    'id': getattr(vc_data, 'cve', cve_id), # Use actual CVE from response
                    'title': f"VulnCheck Details for {getattr(vc_data, 'cve', cve_id)}", # Generic title
                    'description': description,
                    'published': published,
                    'modified': modified,
                    'cvss': cvss_score,
                    'cvss_version': cvss_version,
                    'cvss_vector': cvss_vector,
                    'cwe_ids': cwe_ids,
                    'references': references,
                    'link': f"https://vulncheck.com/browse/vulnerabilities/{getattr(vc_data, 'cve', cve_id)}", # Construct link
                    'source': 'VulnCheck'
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