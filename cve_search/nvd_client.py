import requests
import logging
from typing import Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.headers = {}
        if self.api_key:
            self.headers['apiKey'] = self.api_key

    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        params = {'cveId': cve_id}
        try:
            response = requests.get(self.BASE_URL, params=params, headers=self.headers, timeout=10)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            data = response.json()

            if not data.get('vulnerabilities'):
                logger.warning(f"No vulnerability data found for {cve_id} in NVD response.")
                return None

            cve_data = data['vulnerabilities'][0]['cve']

            description = "No description available"
            for desc in cve_data.get('descriptions', []):
                if desc.get('lang') == 'en':
                    description = desc.get('value', description)
                    break
            
            cvss_score = None
            cvss_version = None
            if 'metrics' in cve_data:
                if 'cvssMetricV31' in cve_data['metrics']:
                    cvss_metrics = cve_data['metrics']['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_metrics.get('baseScore')
                    cvss_version = '3.1'
                elif 'cvssMetricV30' in cve_data['metrics']:
                    cvss_metrics = cve_data['metrics']['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_metrics.get('baseScore')
                    cvss_version = '3.0'
                elif 'cvssMetricV2' in cve_data['metrics']:
                    cvss_metrics = cve_data['metrics']['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_metrics.get('baseScore')
                    cvss_version = '2.0'


            published_date = cve_data.get('published')
            modified_date = cve_data.get('lastModified')

            # Try to parse dates, fallback to string if format is unexpected
            try:
                published = datetime.fromisoformat(published_date.replace('Z', '+00:00')).strftime('%Y-%m-%dT%H:%M:%S') if published_date else None
            except ValueError:
                logger.warning(f"Could not parse published date format for {cve_id}: {published_date}")
                published = published_date
            
            try:
                modified = datetime.fromisoformat(modified_date.replace('Z', '+00:00')).strftime('%Y-%m-%dT%H:%M:%S') if modified_date else None
            except ValueError:
                logger.warning(f"Could not parse modified date format for {cve_id}: {modified_date}")
                modified = modified_date


            return {
                'id': cve_data.get('id'),
                'title': f"NVD Details for {cve_data.get('id')}", # NVD API doesn't provide a concise title like Vulners
                'description': description,
                'published': published,
                'modified': modified,
                'cvss': cvss_score,
                'cvss_version': cvss_version,
                'link': f"https://nvd.nist.gov/vuln/detail/{cve_data.get('id')}",
                'source': 'NVD'
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CVE details for {cve_id} from NVD: {e}", exc_info=True)
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