import aiohttp # Replace requests with aiohttp
import asyncio # Import asyncio
import logging
# import time # REMOVED
from typing import Optional, Dict, List, Any
from datetime import datetime
from aiohttp import ClientTimeout # Import ClientTimeout

logger = logging.getLogger(__name__)

class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MAX_RETRIES = 3
    RETRY_DELAY_PUBLIC = 6
    RETRY_DELAY_API_KEY = 1 # Use 1 second instead of 0.6 for safety margin
    REQUEST_TIMEOUT = 15 # Total request timeout in seconds

    def __init__(self, session: aiohttp.ClientSession, api_key: Optional[str] = None):
        self.session = session # Store the shared session
        self.api_key = api_key
        self.headers = {'User-Agent': 'cve-search-discord-bot/1.0'} # Updated version/agent
        if self.api_key:
            self.headers['apiKey'] = self.api_key
            self.retry_delay = self.RETRY_DELAY_API_KEY
        else:
            self.retry_delay = self.RETRY_DELAY_PUBLIC

    async def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        params = {'cveId': cve_id}
        retries = 0
        request_timeout = ClientTimeout(total=self.REQUEST_TIMEOUT)
        
        while retries <= self.MAX_RETRIES:
            try:
                # Use aiohttp session for async request
                async with self.session.get(
                    self.BASE_URL, 
                    params=params, 
                    headers=self.headers, 
                    timeout=request_timeout
                ) as response:
                    # Raise HTTPError for bad responses (4xx or 5xx)
                    # aiohttp raises ClientResponseError for this
                    response.raise_for_status()
                    
                    # Check content type before parsing JSON
                    if 'application/json' not in response.content_type:
                        logger.error(f"Unexpected content type from NVD for {cve_id}: {response.content_type}")
                        text_resp = await response.text()
                        logger.error(f"NVD Response body: {text_resp[:500]}") # Log part of the body
                        return None # Cannot parse non-JSON
                        
                    data = await response.json()

                if not data or not isinstance(data, dict) or not data.get('vulnerabilities'):
                    logger.warning(f"No vulnerability data found for {cve_id} in NVD response or unexpected format: {data}")
                    return None

                if not data['vulnerabilities']:
                     logger.warning(f"Vulnerabilities list is empty for {cve_id} in NVD response.")
                     return None
                     
                cve_data = data['vulnerabilities'][0]['cve']

                # Extract description
                description = "No description available"
                for desc in cve_data.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value', description)
                        break
                
                # Extract CVSS metrics (add checks for list existence/non-empty)
                cvss_score = None
                cvss_version = None
                cvss_vector = None
                metrics_data = cve_data.get('metrics', {})
                if metrics_data:
                    # Prioritize v3.1 -> v3.0 -> v2.0
                    if metrics_data.get('cvssMetricV31'):
                        metrics = metrics_data['cvssMetricV31'][0]
                        cvss_data = metrics.get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        cvss_vector = cvss_data.get('vectorString')
                        cvss_version = f"3.1 ({cvss_data.get('baseSeverity', '')})"
                    elif metrics_data.get('cvssMetricV30'):
                        metrics = metrics_data['cvssMetricV30'][0]
                        cvss_data = metrics.get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        cvss_vector = cvss_data.get('vectorString')
                        cvss_version = f"3.0 ({cvss_data.get('baseSeverity', '')})"
                    elif metrics_data.get('cvssMetricV2'):
                        metrics = metrics_data['cvssMetricV2'][0]
                        cvss_data = metrics.get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        cvss_vector = cvss_data.get('vectorString')
                        # V2 base severity might be at a different level
                        cvss_version = f"2.0 ({metrics.get('baseSeverity', '')})" # Check metrics level too
                
                # Extract CWEs
                cwe_ids = []
                for weakness in cve_data.get('weaknesses', []):
                    for desc in weakness.get('description', []):
                        if desc.get('lang') == 'en':
                            cwe_id = desc.get('value')
                            if cwe_id and cwe_id.startswith('CWE-'):
                                cwe_ids.append(cwe_id)
                cwe_ids = sorted(list(set(cwe_ids)))

                # Extract References
                references = []
                for ref in cve_data.get('references', []):
                    references.append({
                        'url': ref.get('url'),
                        'source': ref.get('source'),
                        'tags': ref.get('tags', [])
                    })

                # Format Dates (helper function is fine)
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

                # Add severity to version string if found
                if cvss_score is not None and cvss_version:
                   severity = None
                   if metrics_data.get('cvssMetricV31'):
                        severity = metrics_data['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity')
                   elif metrics_data.get('cvssMetricV30'):
                        severity = metrics_data['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity')
                   elif metrics_data.get('cvssMetricV2'):
                       severity = metrics_data['cvssMetricV2'][0].get('baseSeverity') # Check metrics level
                   if severity:
                       cvss_version = f"{cvss_version.split(' (')[0]} ({severity})"
                       
                return {
                    'id': cve_data.get('id'),
                    'title': f"NVD Details for {cve_data.get('id')}", 
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

            # Use aiohttp specific exceptions
            except aiohttp.ClientResponseError as e:
                # Check for retryable status codes
                if e.status in [403, 429, 503, 504] and retries < self.MAX_RETRIES:
                    retries += 1
                    logger.warning(f"NVD API error for {cve_id} (status {e.status}). Retrying in {self.retry_delay}s... ({retries}/{self.MAX_RETRIES})")
                    await asyncio.sleep(self.retry_delay) # Use asyncio.sleep
                    continue # Retry the loop
                else:
                    logger.error(f"HTTP error fetching CVE details for {cve_id} from NVD: {e.status} {e.message}", exc_info=True)
                    return None # Non-retryable HTTP error or max retries exceeded
            except asyncio.TimeoutError:
                 logger.error(f"Timeout fetching CVE details for {cve_id} from NVD.")
                 # Optionally retry timeouts
                 if retries < self.MAX_RETRIES:
                     retries += 1
                     logger.warning(f"Retrying NVD fetch for {cve_id} after timeout... ({retries}/{self.MAX_RETRIES})")
                     await asyncio.sleep(self.retry_delay)
                     continue
                 else:
                    return None
            except aiohttp.ClientError as e:
                # Includes connection errors, etc.
                if retries < self.MAX_RETRIES:
                     retries += 1
                     logger.warning(f"Network/Client error fetching NVD for {cve_id} ({e}). Retrying in {self.retry_delay}s... ({retries}/{self.MAX_RETRIES})")
                     await asyncio.sleep(self.retry_delay)
                     continue # Retry the loop
                else:
                    logger.error(f"Network/Client error fetching NVD for {cve_id} after retries: {e}", exc_info=True)
                    return None
            except (KeyError, IndexError, TypeError) as e: # Added TypeError for robustness
                 logger.error(f"Error parsing NVD response for {cve_id}. Type: {type(e).__name__}, Details: {e}", exc_info=True)
                 return None
            except Exception as e:
                logger.error(f"An unexpected error occurred while processing {cve_id} with NVD: {e}", exc_info=True)
                return None
        
        # If loop finishes due to max retries
        logger.error(f"Failed to fetch CVE details for {cve_id} from NVD after {self.MAX_RETRIES} retries.")
        return None 