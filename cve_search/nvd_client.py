import requests
import logging
import time # Added for sleep
from typing import Optional, Dict, List, Any # Added List
from datetime import datetime

logger = logging.getLogger(__name__)

class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MAX_RETRIES = 3
    # NVD recommends 6s delay for public, 0.6s for API key
    RETRY_DELAY_PUBLIC = 6
    RETRY_DELAY_API_KEY = 1 # Use 1 second instead of 0.6 for safety margin

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.headers = {'User-Agent': 'cve-search-discord-bot/0.1.0'} # Add User-Agent
        if self.api_key:
            self.headers['apiKey'] = self.api_key
            self.retry_delay = self.RETRY_DELAY_API_KEY
        else:
            self.retry_delay = self.RETRY_DELAY_PUBLIC

    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        params = {'cveId': cve_id}
        retries = 0
        while retries <= self.MAX_RETRIES:
            try:
                response = requests.get(self.BASE_URL, params=params, headers=self.headers, timeout=15) # Increased timeout
                response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

                data = response.json()

                if not data.get('vulnerabilities'):
                    logger.warning(f"No vulnerability data found for {cve_id} in NVD response.")
                    return None

                cve_data = data['vulnerabilities'][0]['cve']

                # Extract description
                description = "No description available"
                for desc in cve_data.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value', description)
                        break
                
                # Extract CVSS metrics
                cvss_score = None
                cvss_version = None
                cvss_vector = None
                if 'metrics' in cve_data:
                    # Prioritize v3.1 -> v3.0 -> v2.0
                    if 'cvssMetricV31' in cve_data['metrics']:
                        metrics = cve_data['metrics']['cvssMetricV31'][0]
                        cvss_data = metrics.get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        cvss_vector = cvss_data.get('vectorString')
                        cvss_version = '3.1'
                    elif 'cvssMetricV30' in cve_data['metrics']:
                        metrics = cve_data['metrics']['cvssMetricV30'][0]
                        cvss_data = metrics.get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        cvss_vector = cvss_data.get('vectorString')
                        cvss_version = '3.0'
                    elif 'cvssMetricV2' in cve_data['metrics']:
                        metrics = cve_data['metrics']['cvssMetricV2'][0]
                        cvss_data = metrics.get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        cvss_vector = cvss_data.get('vectorString')
                        cvss_version = '2.0'
                
                # Extract CWEs
                cwe_ids = []
                for weakness in cve_data.get('weaknesses', []):
                    for desc in weakness.get('description', []):
                        if desc.get('lang') == 'en':
                            cwe_id = desc.get('value')
                            if cwe_id and cwe_id.startswith('CWE-'):
                                cwe_ids.append(cwe_id)
                cwe_ids = sorted(list(set(cwe_ids))) # Unique and sorted

                # Extract References
                references = []
                for ref in cve_data.get('references', []):
                    references.append({
                        'url': ref.get('url'),
                        'source': ref.get('source'),
                        'tags': ref.get('tags', [])
                    })

                # Format Dates
                published_date_str = cve_data.get('published')
                modified_date_str = cve_data.get('lastModified')

                def format_iso_date(date_str):
                    if not date_str:
                        return None
                    try:
                        # Handles ISO format with optional Z or timezone
                        return datetime.fromisoformat(date_str.replace('Z', '+00:00')).strftime('%Y-%m-%dT%H:%M:%S')
                    except ValueError:
                        logger.warning(f"Could not parse date format for {cve_id}: {date_str}")
                        return date_str # Return original if parsing fails

                published = format_iso_date(published_date_str)
                modified = format_iso_date(modified_date_str)

                return {
                    'id': cve_data.get('id'),
                    'title': f"NVD Details for {cve_data.get('id')}", # NVD API doesn't provide a concise title
                    'description': description,
                    'published': published,
                    'modified': modified,
                    'cvss': cvss_score,
                    'cvss_version': cvss_version,
                    'cvss_vector': cvss_vector,
                    'cwe_ids': cwe_ids,
                    'references': references,
                    'link': f"https://nvd.nist.gov/vuln/detail/{cve_data.get('id')}",
                    'source': 'NVD'
                }

            except requests.exceptions.HTTPError as e:
                if e.response.status_code in [403, 429] and retries < self.MAX_RETRIES:
                    retries += 1
                    logger.warning(f"Rate limit hit for {cve_id} (status {e.response.status_code}). Retrying in {self.retry_delay}s... ({retries}/{self.MAX_RETRIES})")
                    time.sleep(self.retry_delay)
                    continue # Retry the loop
                else:
                    logger.error(f"HTTP error fetching CVE details for {cve_id} from NVD: {e}", exc_info=True)
                    return None # Non-retryable HTTP error or max retries exceeded
            except requests.exceptions.RequestException as e:
                # Includes connection errors, timeouts, etc.
                if retries < self.MAX_RETRIES:
                     retries += 1
                     logger.warning(f"Network error fetching CVE details for {cve_id} ({e}). Retrying in {self.retry_delay}s... ({retries}/{self.MAX_RETRIES})")
                     time.sleep(self.retry_delay)
                     continue # Retry the loop
                else:
                    logger.error(f"Network error fetching CVE details for {cve_id} from NVD after retries: {e}", exc_info=True)
                    return None
            except KeyError as e:
                 logger.error(f"Error parsing NVD response for {cve_id}. Missing key: {e}", exc_info=True)
                 return None
            except IndexError:
                 logger.error(f"Error parsing NVD response for {cve_id}. Unexpected structure (e.g., empty vulnerabilities list).", exc_info=True)
                 return None
            except Exception as e:
                logger.error(f"An unexpected error occurred while processing {cve_id} with NVD: {e}", exc_info=True)
                return None
        
        # If loop finishes due to max retries
        logger.error(f"Failed to fetch CVE details for {cve_id} from NVD after {self.MAX_RETRIES} retries.")
        return None 