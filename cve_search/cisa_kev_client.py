import logging
import aiohttp
import asyncio
from aiohttp import ClientTimeout
from typing import Set, List, Dict, Any, Optional
from .db_utils import KEVConfigDB

logger = logging.getLogger(__name__)

class CisaKevClient:
    """
    Client to fetch and process the CISA Known Exploited Vulnerabilities (KEV) catalog.
    Monitors the KEV JSON feed for new additions.
    """
    KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    HEADERS = {'User-Agent': 'cve-search-discord-bot/1.0'}

    def __init__(self, session: aiohttp.ClientSession, db: KEVConfigDB):
        """
        Initializes the CisaKevClient.

        Args:
            session: An aiohttp.ClientSession for making HTTP requests.
            db: An instance of KEVConfigDB for persistence.
        """
        self.session = session
        self.db = db
        self.seen_kev_ids: Set[str] = self.db.load_seen_kevs()

    async def _fetch_kev_data(self) -> Optional[Dict[str, Any]]:
        """Fetches the raw KEV data from CISA."""
        request_timeout = ClientTimeout(total=30)
        try:
            async with self.session.get(
                self.KEV_CATALOG_URL,
                headers=self.HEADERS,
                timeout=request_timeout
            ) as response:
                response.raise_for_status()
                if response.content_type == 'application/json':
                    return await response.json()

                logger.error(f"Unexpected content type received from CISA KEV feed: {response.content_type}")
                try:
                    logger.warning("Attempting to parse non-JSON response as JSON...")
                    return await response.json()
                except Exception:
                    logger.error("Failed to decode CISA KEV response even after content-type mismatch.")
                    return None
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error fetching CISA KEV data: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching CISA KEV data: {e}", exc_info=True)
            return None

    async def get_kev_entry(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetches the KEV entry for a specific CVE if it exists in the catalog.
        
        Args:
            cve_id: The CVE ID to look up (e.g., 'CVE-2021-44228')
            
        Returns:
            Optional[Dict[str, Any]]: The KEV entry if found, None otherwise
        """
        data = await self._fetch_kev_data()
        if not data or 'vulnerabilities' not in data:
            logger.warning("Could not fetch or parse CISA KEV data while checking for specific CVE.")
            return None

        for vuln in data.get('vulnerabilities', []):
            if vuln.get('cveID') == cve_id:
                return vuln

        return None

    async def get_new_kev_entries(self) -> List[Dict[str, Any]]:
        """
        Fetches the latest KEV catalog and returns a list of vulnerabilities
        that are new since the last check or initial load.
        """
        logger.info("Fetching CISA KEV catalog...")
        data = await self._fetch_kev_data()
        if not data or 'vulnerabilities' not in data:
            logger.warning("Could not fetch or parse CISA KEV data, or data format unexpected.")
            return []

        current_kev_ids = {vuln.get('cveID') for vuln in data.get('vulnerabilities', []) if vuln.get('cveID')}

        new_vuln_details = []

        if new_ids := current_kev_ids - self.seen_kev_ids:
            logger.info(f"Found {len(new_ids)} new CISA KEV entries: {', '.join(sorted(list(new_ids)))}")

            try:
                self.db.add_seen_kevs(new_ids)
            except Exception as e:
                logger.error(f"Failed to persist new KEV IDs to database: {e}", exc_info=True)

            for vuln in data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID')
                if cve_id in new_ids:
                    new_vuln_details.append(vuln)
                    self.seen_kev_ids.add(cve_id)
        else:
            logger.info("No new entries found in CISA KEV catalog.")

        return new_vuln_details