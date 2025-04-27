import aiohttp
import asyncio
import logging

from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta, timezone
from aiohttp import ClientTimeout

logger = logging.getLogger(__name__)

# Custom Exception for Rate Limit Errors
class NVDRateLimitError(Exception):
    """Custom exception raised when the NVD API indicates a rate limit."""
    pass

class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MAX_RETRIES = 3
    RETRY_DELAY_PUBLIC = 6
    RETRY_DELAY_API_KEY = 1
    REQUEST_TIMEOUT = 15
    # NVD recommends max 120 days range, let's default to something smaller
    DEFAULT_RECENT_DAYS = 7 
    MAX_RESULTS_PER_PAGE = 2000 # Max allowed by NVD API v2

    def __init__(self, session: aiohttp.ClientSession, api_key: Optional[str] = None):
        self.session = session
        self.api_key = api_key
        self.headers = {'User-Agent': 'kevvy-bot/1.0'}
        if self.api_key:
            self.headers['apiKey'] = self.api_key
            self.retry_delay = self.RETRY_DELAY_API_KEY
        else:
            self.retry_delay = self.RETRY_DELAY_PUBLIC

    async def _make_request(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Makes a request to the NVD API with retry logic."""
        retries = 0
        request_timeout = ClientTimeout(total=self.REQUEST_TIMEOUT)
        last_status_code = None

        while retries <= self.MAX_RETRIES:
            last_status_code = None
            try:
                logger.debug(f"Querying NVD API with params: {params}")
                async with self.session.get(
                    self.BASE_URL,
                    params=params,
                    headers=self.headers,
                    timeout=request_timeout
                ) as response:
                    last_status_code = response.status
                    if response.status == 200:
                        return await response.json()
                    elif response.status in [403, 429, 503, 504] and retries < self.MAX_RETRIES:
                        retries += 1
                        logger.warning(f"NVD API error (status {response.status}). Retrying in {self.retry_delay}s... ({retries}/{self.MAX_RETRIES})")
                        await asyncio.sleep(self.retry_delay)
                        continue
                    else:
                        logger.error(f"HTTP error fetching from NVD: {response.status} {response.reason}")
                        if response.status in [403, 429]:
                            raise NVDRateLimitError(f"NVD API rate limit hit (Status: {response.status})")
                        return None
            except asyncio.TimeoutError:
                logger.warning("Timeout fetching from NVD.")
                if retries < self.MAX_RETRIES:
                    retries += 1
                    logger.warning(f"Retrying NVD fetch after timeout... ({retries}/{self.MAX_RETRIES})")
                    await asyncio.sleep(self.retry_delay)
                    continue
                else:
                    logger.error(f"Timeout fetching from NVD after {self.MAX_RETRIES} retries.")
                    return None
            except aiohttp.ClientError as e:
                logger.warning(f"Network/Client error fetching NVD ({e}).")
                if retries < self.MAX_RETRIES:
                    retries += 1
                    logger.warning(f"Retrying... ({retries}/{self.MAX_RETRIES})")
                    await asyncio.sleep(self.retry_delay)
                    continue
                else:
                    logger.error(f"Network/Client error fetching from NVD after {self.MAX_RETRIES} retries: {e}", exc_info=True)
                    return None
            except Exception as e:
                logger.error(f"An unexpected error occurred during NVD request: {e}", exc_info=True)
                return None

        logger.error(f"Failed to fetch from NVD after {self.MAX_RETRIES} retries.")
        if last_status_code in [403, 429]:
            raise NVDRateLimitError(f"NVD API rate limit hit after max retries (Last Status: {last_status_code})")
        return None

    async def get_cve_details(self, cve_id: str) -> Dict[str, Any] | None:
        """Fetches CVE details from the NVD API v2."""
        params = {'cveId': cve_id}
        try:
            data = await self._make_request(params)
            if data and data.get('vulnerabilities'):
                cve_item = data['vulnerabilities'][0]['cve']
                logger.info(f"Successfully fetched details for {cve_id} from NVD.")
                return self._parse_cve_data(cve_item, self.BASE_URL)
            elif data:
                logger.warning(f"NVD API returned data for {cve_id}, but no 'vulnerabilities' key found.")
                return None
            else:
                # Error already logged by _make_request or NVDRateLimitError raised
                return None
        except NVDRateLimitError as e:
            logger.warning(e) # Log rate limit warning
            raise # Re-raise for the bot to handle potentially
        except Exception as e:
            logger.error(f"Unexpected error in get_cve_details for {cve_id}: {e}", exc_info=True)
            return None

    # --- NEW Method: get_recent_cves ---
    async def get_recent_cves(self, days: int = DEFAULT_RECENT_DAYS) -> List[Dict[str, Any]] | None:
        """Fetches CVEs published within the last N days."""
        if days <= 0:
            return []
        
        # NVD API uses UTC dates
        now = datetime.now(timezone.utc)
        start_date = now - timedelta(days=days)
        
        # Format for NVD API (ISO 8601)
        # NVD Example: 2021-08-04T00:00:00.000 or 2021-08-04T00:00:00
        # Let's omit milliseconds for simplicity and add Z for UTC
        nvd_date_format = "%Y-%m-%dT%H:%M:%SZ"
        start_date_str = start_date.strftime(nvd_date_format)
        end_date_str = now.strftime(nvd_date_format)

        params = {
            'pubStartDate': start_date_str,
            'pubEndDate': end_date_str,
            'resultsPerPage': self.MAX_RESULTS_PER_PAGE # Get max results in one go
        }
        
        all_parsed_cves: List[Dict[str, Any]] = []
        start_index = 0
        total_results = -1 # Sentinel value

        while True:
            params['startIndex'] = start_index
            try:
                data = await self._make_request(params)
                if not data:
                    logger.error("Failed to fetch recent CVEs batch.")
                    # Return what we have so far, or None if first attempt failed
                    return all_parsed_cves if all_parsed_cves else None 
                
                if total_results == -1: # First request
                     total_results = data.get('totalResults', 0)
                     if total_results == 0:
                          logger.info(f"No CVEs found published between {start_date_str} and {end_date_str}.")
                          return []

                vulnerabilities = data.get('vulnerabilities', [])
                if not vulnerabilities:
                    logger.warning(f"NVD response for recent CVEs had no vulnerabilities list (startIndex: {start_index}).")
                    break # Exit loop if no vulnerabilities returned

                logger.info(f"Fetched batch of {len(vulnerabilities)} CVEs (startIndex: {start_index}, total: {total_results}).")
                for item in vulnerabilities:
                    parsed = self._parse_cve_data(item['cve'], self.BASE_URL)
                    if parsed:
                         all_parsed_cves.append(parsed)
                
                # Check if we need to fetch more pages
                start_index += len(vulnerabilities)
                if start_index >= total_results:
                    break # Got all results
                if len(vulnerabilities) < self.MAX_RESULTS_PER_PAGE:
                     logger.warning("NVD returned fewer results than requested per page, stopping pagination early.")
                     break # Stop if NVD returns fewer than requested (might indicate end)
                
                # Small delay before next page request
                await asyncio.sleep(self.retry_delay) 

            except NVDRateLimitError as e:
                logger.warning(f"Rate limit hit while fetching recent CVEs: {e}")
                # Return what we managed to get before hitting the limit
                return all_parsed_cves if all_parsed_cves else None 
            except Exception as e:
                logger.error(f"Unexpected error fetching recent CVEs batch: {e}", exc_info=True)
                # Return what we have so far or None
                return all_parsed_cves if all_parsed_cves else None

        logger.info(f"Finished fetching recent CVEs. Total parsed: {len(all_parsed_cves)}")
        return all_parsed_cves

    def _parse_cve_data(self, cve_item: Dict[str, Any], url: str) -> Dict[str, Any] | None:
        # Check if cve_item is None or not a dict before proceeding
        if not cve_item or not isinstance(cve_item, dict):
            logger.warning("_parse_cve_data received invalid input")
            return None

        cve_id = cve_item.get('id')
        if not cve_id:
             logger.warning("CVE item missing required 'id' field in _parse_cve_data")
             return None

        description = "No description available"
        for desc in cve_item.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', description)
                break

        cvss_score = None
        cvss_version = None
        cvss_vector = None
        metrics_data = cve_item.get('metrics', {})
        if metrics_data:
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
                cvss_version = f"2.0 ({metrics.get('baseSeverity', '')})"

        cwe_ids = []
        for weakness in cve_item.get('weaknesses', []):
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    cwe_id_val = desc.get('value') # Renamed variable
                    if cwe_id_val and cwe_id_val.startswith('CWE-'):
                        cwe_ids.append(cwe_id_val)
        cwe_ids = sorted(list(set(cwe_ids)))

        references = []
        for ref in cve_item.get('references', []):
            references.append({
                'url': ref.get('url'),
                'source': ref.get('source'),
                'tags': ref.get('tags', [])
            })

        published_date_str = cve_item.get('published')
        modified_date_str = cve_item.get('lastModified')

        def format_iso_date(date_str):
            if not date_str:
                return None
            try:
                return datetime.fromisoformat(date_str.replace('Z', '+00:00')).strftime('%Y-%m-%dT%H:%M:%S')
            except ValueError:
                logger.warning(f"Could not parse date format for {cve_id}: {date_str}")
                return date_str

        published = format_iso_date(published_date_str)
        modified = format_iso_date(modified_date_str)

        if cvss_score is not None and cvss_version:
            severity = None
            if metrics_data.get('cvssMetricV31'):
                severity = metrics_data['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity')
            elif metrics_data.get('cvssMetricV30'):
                severity = metrics_data['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity')
            elif metrics_data.get('cvssMetricV2'):
                severity = metrics_data['cvssMetricV2'][0].get('baseSeverity')
            if severity:
                cvss_version = f"{cvss_version.split(' (')[0]} ({severity})"

        return {
            'id': cve_id, # Use the validated cve_id
            'title': f"NVD Details for {cve_id}",
            'description': description,
            'published': published,
            'modified': modified,
            'cvss': cvss_score,
            'cvss_version': cvss_version,
            'cvss_vector': cvss_vector,
            'cwe_ids': cwe_ids,
            'references': references,
            'link': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            'source': 'NVD'
        } 