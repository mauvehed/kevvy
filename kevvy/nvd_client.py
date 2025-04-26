import aiohttp
import asyncio
import logging

from typing import Optional, Dict, List, Any
from datetime import datetime
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

    def __init__(self, session: aiohttp.ClientSession, api_key: Optional[str] = None):
        self.session = session
        self.api_key = api_key
        self.headers = {'User-Agent': 'kevvy-bot/1.0'}
        if self.api_key:
            self.headers['apiKey'] = self.api_key
            self.retry_delay = self.RETRY_DELAY_API_KEY
        else:
            self.retry_delay = self.RETRY_DELAY_PUBLIC

    async def get_cve_details(self, cve_id: str) -> Dict[str, Any] | None:
        """Fetches CVE details from the NVD API v2."""
        params = {'cveId': cve_id}
        retries = 0
        request_timeout = ClientTimeout(total=self.REQUEST_TIMEOUT)
        last_status_code = None # Variable to store the status code that caused the last retry

        while retries <= self.MAX_RETRIES:
            last_status_code = None # Reset for this attempt
            try:
                logger.debug(f"Querying NVD API for {cve_id} at {self.BASE_URL}")
                async with self.session.get(
                    self.BASE_URL,
                    params=params,
                    headers=self.headers,
                    timeout=request_timeout
                ) as response:
                    last_status_code = response.status # Store the status code
                    if response.status == 200:
                        data = await response.json()
                        if data.get('vulnerabilities'):
                            cve_item = data['vulnerabilities'][0]['cve']
                            logger.info(f"Successfully fetched details for {cve_id} from NVD.")
                            return self._parse_cve_data(cve_item, self.BASE_URL)
                        else:
                            logger.warning(f"NVD API returned 200 for {cve_id}, but no 'vulnerabilities' key found in response.")
                            return None
                    elif response.status in [403, 429, 503, 504] and retries < self.MAX_RETRIES:
                        retries += 1
                        logger.warning(f"NVD API error for {cve_id} (status {response.status}). Retrying in {self.retry_delay}s... ({retries}/{self.MAX_RETRIES})")
                        await asyncio.sleep(self.retry_delay)
                        continue
                    else:
                        logger.error(f"HTTP error fetching CVE details for {cve_id} from NVD: {response.status} {response.reason}", exc_info=True)
                        # Check if this final failure was due to a rate limit status
                        if response.status in [403, 429]:
                            raise NVDRateLimitError(f"NVD API rate limit hit for {cve_id} (Status: {response.status})")
                        return None

            except asyncio.TimeoutError:
                logger.error(f"Timeout fetching CVE details for {cve_id} from NVD.")
                if retries < self.MAX_RETRIES:
                    retries += 1
                    logger.warning(f"Retrying NVD fetch for {cve_id} after timeout... ({retries}/{self.MAX_RETRIES})")
                    await asyncio.sleep(self.retry_delay)
                    continue
                else:
                    logger.error(f"Timeout fetching {cve_id} from NVD after {self.MAX_RETRIES} retries.")
                    return None
            except aiohttp.ClientError as e:
                logger.warning(f"Network/Client error fetching NVD for {cve_id} ({e}).")
                if retries < self.MAX_RETRIES:
                    retries += 1
                    logger.warning(f"Retrying... ({retries}/{self.MAX_RETRIES})")
                    await asyncio.sleep(self.retry_delay)
                    continue
                else:
                    logger.error(f"Network/Client error fetching {cve_id} from NVD after {self.MAX_RETRIES} retries: {e}", exc_info=True)
                    return None
            except (KeyError, IndexError, TypeError) as e:
                logger.error(f"Error parsing NVD response for {cve_id}. Type: {type(e).__name__}, Details: {e}", exc_info=True)
                return None
            except Exception as e:
                logger.error(f"An unexpected error occurred while processing {cve_id} with NVD: {e}", exc_info=True)
                return None

        logger.error(f"Failed to fetch CVE details for {cve_id} from NVD after {self.MAX_RETRIES} retries.")
        # Check the status code from the *last* failed attempt within the loop
        if last_status_code in [403, 429]:
            raise NVDRateLimitError(f"NVD API rate limit hit for {cve_id} after max retries (Last Status: {last_status_code})")
        
        # If the loop finished due to other retryable errors (503/504) or other exceptions leading to 'continue'
        # we ultimately return None here.
        return None

    def _parse_cve_data(self, cve_item: Dict[str, Any], url: str) -> Dict[str, Any]:
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
                    cwe_id = desc.get('value')
                    if cwe_id and cwe_id.startswith('CWE-'):
                        cwe_ids.append(cwe_id)
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
            'id': cve_item.get('id'),
            'title': f"NVD Details for {cve_item.get('id')}",
            'description': description,
            'published': published,
            'modified': modified,
            'cvss': cvss_score,
            'cvss_version': cvss_version,
            'cvss_vector': cvss_vector,
            'cwe_ids': cwe_ids,
            'references': references,
            'link': f"https://nvd.nist.gov/vuln/detail/{cve_item.get('id')}",
            'source': 'NVD'
        } 