import os
import logging
import asyncio
import functools
from typing import Optional, Dict, Any, Callable, Tuple, List
import vulncheck_sdk
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class VulnCheckClient:
    DEFAULT_HOST = "https://api.vulncheck.com"
    DEFAULT_API = DEFAULT_HOST + "/v3"
    MAX_RETRIES = 3
    RETRY_DELAY = 2

    def __init__(self, api_key: Optional[str]):
        if not api_key:
            logger.warning("VulnCheck API Key not provided. VulnCheck client will not function.")
            self.api_client = None
            self.indices_client = None
            return

        self.api_key = api_key
        configuration = vulncheck_sdk.Configuration(host=self.DEFAULT_API)
        configuration.api_key["Bearer"] = self.api_key
        configuration.retries = self.MAX_RETRIES

        self.api_client = vulncheck_sdk.ApiClient(configuration)
        self.indices_client = vulncheck_sdk.IndicesApi(self.api_client)

    def _parse_date(self, date_input: Any) -> Optional[str]:
        """Helper to parse date which might be datetime or string."""
        if not date_input:
            return None
        try:
            if isinstance(date_input, datetime):
                return date_input.strftime('%Y-%m-%dT%H:%M:%S')
            elif isinstance(date_input, str):
                 dt_obj = datetime.fromisoformat(date_input.replace('Z', '+00:00'))
                 return dt_obj.strftime('%Y-%m-%dT%H:%M:%S')
            else:
                logger.warning(f"Unexpected date type: {type(date_input)}")
                return str(date_input)
        except (ValueError, TypeError) as e:
            logger.warning(f"Could not parse date input '{date_input}': {e}")
            return str(date_input)

    async def _run_sdk_call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Runs a potentially blocking SDK function in an executor."""
        loop = asyncio.get_running_loop()
        pfunc = functools.partial(func, *args, **kwargs)
        try:
            result = await loop.run_in_executor(None, pfunc)
            return result
        except Exception as e:
            logger.debug(f"Error during executor run for {func.__name__}: {e}")
            raise # Re-raise the exception for the caller to handle

    # --- Parsing Helper Methods ---

    def _parse_cvss_from_data(self, vc_data: Any) -> Tuple[Optional[float], Optional[str], Optional[str]]:
        """Extracts CVSS score, version, and vector from NVD data."""
        cvss_score = None
        cvss_version = None
        cvss_vector = None
        if hasattr(vc_data, 'metrics') and vc_data.metrics is not None:
            if hasattr(vc_data.metrics, 'cvss_metric_v31') and vc_data.metrics.cvss_metric_v31:
                metric_v3 = vc_data.metrics.cvss_metric_v31[0]
                if hasattr(metric_v3, 'cvss_data') and metric_v3.cvss_data:
                    cvss_score = getattr(metric_v3.cvss_data, 'base_score', None)
                    severity = getattr(metric_v3.cvss_data, 'base_severity', 'Unknown')
                    cvss_version = f"3.1 ({severity})"
                    cvss_vector = getattr(metric_v3.cvss_data, 'vector_string', None)
            elif hasattr(vc_data.metrics, 'cvss_metric_v2') and vc_data.metrics.cvss_metric_v2:
                metric_v2 = vc_data.metrics.cvss_metric_v2[0]
                if hasattr(metric_v2, 'cvss_data') and metric_v2.cvss_data:
                    cvss_score = getattr(metric_v2.cvss_data, 'base_score', None)
                    severity = getattr(metric_v2, 'base_severity', 'Unknown')
                    cvss_version = f"2.0 ({severity})"
                    cvss_vector = getattr(metric_v2.cvss_data, 'vector_string', None)
        return cvss_score, cvss_version, cvss_vector

    def _parse_cwes_from_data(self, vc_data: Any) -> List[str]:
        """Extracts CWE IDs from NVD data."""
        cwe_ids = []
        if hasattr(vc_data, 'weaknesses') and vc_data.weaknesses:
            for weakness in vc_data.weaknesses:
                if hasattr(weakness, 'description') and weakness.description:
                    for desc in weakness.description:
                        desc_value = getattr(desc, 'value', None)
                        if getattr(desc, 'lang', '') == 'en' and desc_value and 'CWE-' in desc_value:
                            try:
                                parts = desc_value.split('CWE-', 1)[1]
                                cwe_num = parts.split()[0].split('<')[0].split(')')[0].strip()
                                if cwe_num.isdigit():
                                    cwe_ids.append(f"CWE-{cwe_num}")
                            except IndexError:
                                logger.warning(f"Could not parse CWE from description: {desc_value}")
        return sorted(list(set(cwe_ids)))

    def _parse_references_from_data(self, vc_data: Any) -> List[Dict[str, Any]]:
        """Extracts references from VulnCheck/NVD data, attempting to find a useful source/link text."""
        references = []
        if hasattr(vc_data, 'references') and vc_data.references:
            for ref in vc_data.references:
                url = getattr(ref, 'url', None)
                if not url: # Skip if no URL
                    continue

                original_source = getattr(ref, 'source', '')
                display_source = 'Link' # Default

                # Basic check if source looks like a potential UUID/hash (e.g., length 36 with hyphens)
                looks_like_uuid = len(original_source) == 36 and original_source.count('-') == 4

                if original_source and '@' not in original_source and not looks_like_uuid:
                    # Use original source if it exists and doesn't look like an email or UUID
                    display_source = original_source
                else:
                    # Otherwise, try to use the hostname from the URL
                    try:
                        hostname = urlparse(url).netloc
                        if hostname:
                            display_source = hostname
                        # else: keep default 'Link'
                    except Exception:
                        # Keep default 'Link' if URL parsing fails
                        pass

                references.append({
                    'url': url,
                    'source': display_source,
                    'tags': getattr(ref, 'tags', [])
                })
        return references

    def _parse_description_from_data(self, vc_data: Any) -> str:
        """Extracts the English description from NVD data."""
        description = "No description available."
        if hasattr(vc_data, 'descriptions') and vc_data.descriptions:
            for desc in vc_data.descriptions:
                if getattr(desc, 'lang', '') == 'en':
                    description = getattr(desc, 'value', description)
                    break
        return description

    def _extract_dates_from_data(self, vc_data: Any) -> Tuple[Optional[str], Optional[str]]:
        """Extracts and formats published and modified dates."""
        published = self._parse_date(getattr(vc_data, 'published', None))
        modified = self._parse_date(getattr(vc_data, 'last_modified', None))
        return published, modified

    # -------------------------------

    async def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        if not self.indices_client:
            logger.debug("VulnCheck client not initialized (no API key).")
            return None

        try:
            logger.debug(f"Querying VulnCheck API for {cve_id}")
            api_response = await self._run_sdk_call(self.indices_client.index_nist_nvd2_get, cve=cve_id)

            if not api_response or not api_response.data:
                logger.warning(f"No vulnerability data found for {cve_id} using VulnCheck's NIST NVD2 endpoint.")
                return None

            vc_data = api_response.data[0]

            cvss_score, cvss_version, cvss_vector = self._parse_cvss_from_data(vc_data)
            cwe_ids = self._parse_cwes_from_data(vc_data)
            references = self._parse_references_from_data(vc_data)
            description = self._parse_description_from_data(vc_data)
            published, modified = self._extract_dates_from_data(vc_data)
            cve_from_data = getattr(vc_data, 'id', cve_id)

            logger.info(f"Successfully fetched details for {cve_from_data} from VulnCheck.")

            return {
                'id': cve_from_data,
                'title': f"NIST NVD Details for {cve_from_data} (via VulnCheck)",
                'description': description,
                'published': published,
                'modified': modified,
                'cvss': cvss_score,
                'cvss_version': cvss_version,
                'cvss_vector': cvss_vector,
                'cwe_ids': cwe_ids,
                'references': references,
                'link': f"https://nvd.nist.gov/vuln/detail/{cve_from_data}",
                'source': 'NIST NVD (via VulnCheck)'
            }

        except vulncheck_sdk.ApiException as e:
            logger.error(f"VulnCheck API error fetching {cve_id}: {e.status} {e.reason} - {e.body}")
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred processing {cve_id} with VulnCheck: {e}", exc_info=True)
            return None