import logging
import aiohttp
from aiohttp import ClientTimeout
from typing import Set, List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class CisaKevClient:
    """
    Client to fetch and process the CISA Known Exploited Vulnerabilities (KEV) catalog.
    Monitors the KEV JSON feed for new additions.
    """
    # Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    # Use a reasonable User-Agent
    HEADERS = {'User-Agent': 'cve-search-discord-bot/1.0'}

    def __init__(self, session: aiohttp.ClientSession):
        """
        Initializes the CisaKevClient.

        Args:
            session: An aiohttp.ClientSession for making HTTP requests.
        """
        self.session = session
        # Store CVE IDs that have been seen/processed to avoid duplicates
        self.seen_kev_ids: Set[str] = set()
        self._initial_load_complete = False # Flag to track initial population

    async def _fetch_kev_data(self) -> Optional[Dict[str, Any]]:
        """Fetches the raw KEV data from CISA."""
        # Define the timeout
        request_timeout = ClientTimeout(total=30) # 30 seconds total timeout
        try:
            async with self.session.get(
                self.KEV_CATALOG_URL, 
                headers=self.HEADERS, 
                timeout=request_timeout # Use the ClientTimeout object
            ) as response:
                response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
                if response.content_type == 'application/json':
                    return await response.json()
                else:
                    logger.error(f"Unexpected content type received from CISA KEV feed: {response.content_type}")
                    # Try to decode as json anyway, but log error
                    try:
                        return await response.json()
                    except Exception:
                         logger.error(f"Failed to decode CISA KEV response even after content-type mismatch.")
                         return None
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error fetching CISA KEV data: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching CISA KEV data: {e}", exc_info=True)
            return None

    async def get_new_kev_entries(self) -> List[Dict[str, Any]]:
        """
        Fetches the latest KEV catalog and returns a list of vulnerabilities
        that are new since the last check or initial load.
        Populates the initial list on the first run without returning entries.
        """
        logger.info("Fetching CISA KEV catalog...")
        data = await self._fetch_kev_data()
        if not data or 'vulnerabilities' not in data:
            logger.warning("Could not fetch or parse CISA KEV data, or data format unexpected.")
            return []

        current_kev_ids = {vuln.get('cveID') for vuln in data.get('vulnerabilities', []) if vuln.get('cveID')}

        new_vuln_details = []

        if not self._initial_load_complete:
            # First run: populate the seen list but don't report anything yet
            logger.info(f"Initial load of CISA KEV catalog. Found {len(current_kev_ids)} entries. Monitoring for new additions.")
            self.seen_kev_ids = current_kev_ids
            self._initial_load_complete = True
            return [] # Return empty list on first successful load
        else:
            # Subsequent runs: find the difference
            new_ids = current_kev_ids - self.seen_kev_ids
            if new_ids:
                logger.info(f"Found {len(new_ids)} new CISA KEV entries: {', '.join(new_ids)}")
                # Find the full details for the new IDs
                for vuln in data.get('vulnerabilities', []):
                    cve_id = vuln.get('cveID')
                    if cve_id in new_ids:
                        new_vuln_details.append(vuln)
                        self.seen_kev_ids.add(cve_id) # Update seen list
            else:
                logger.info("No new entries found in CISA KEV catalog.")

        return new_vuln_details

# Example Usage (requires an async context and aiohttp session)
# async def main():
#     async with aiohttp.ClientSession() as session:
#         kev_client = CisaKevClient(session)
#         # First call populates baseline
#         await kev_client.get_new_kev_entries()
#         print(f"Initial seen IDs count: {len(kev_client.seen_kev_ids)}")
#         # Subsequent calls would return new entries if any appear between calls
#         await asyncio.sleep(10)
#         new_entries = await kev_client.get_new_kev_entries()
#         if new_entries:
#             print("\nFound new KEV entries:")
#             for entry in new_entries:
#                 print(f" - {entry['cveID']}: {entry['vulnerabilityName']}")
#         else:
#             print("\nNo new KEV entries found on second check.")
#
# if __name__ == '__main__':
#     import asyncio
#     logging.basicConfig(level=logging.INFO)
#     # Requires python 3.7+ for asyncio.run
#     # asyncio.run(main()) 