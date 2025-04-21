import logging
import aiohttp
from aiohttp import ClientTimeout
from typing import Set, List, Dict, Any, Optional
from .db_utils import KEVConfigDB

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

    def __init__(self, session: aiohttp.ClientSession, db: KEVConfigDB):
        """
        Initializes the CisaKevClient.

        Args:
            session: An aiohttp.ClientSession for making HTTP requests.
            db: An instance of KEVConfigDB for persistence.
        """
        self.session = session
        self.db = db
        # Store CVE IDs that have been seen/processed to avoid duplicates
        # Load initial set from database
        self.seen_kev_ids: Set[str] = self.db.load_seen_kevs()
        # self._initial_load_complete = False # This flag is less relevant now

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
                # If content type is JSON, parse and return
                if response.content_type == 'application/json':
                    return await response.json()
                
                # If not JSON, log error and attempt fallback parsing
                logger.error(f"Unexpected content type received from CISA KEV feed: {response.content_type}")
                # Try to decode as json anyway, but log error
                try:
                    logger.warning("Attempting to parse non-JSON response as JSON...") # Added warning
                    return await response.json()
                except Exception:
                    # Use standard string, no f-string needed here
                    logger.error("Failed to decode CISA KEV response even after content-type mismatch.")
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

        # Compare current IDs with the persistent + in-memory seen list
        # Use walrus operator (:=) to assign and check in one step
        if new_ids := current_kev_ids - self.seen_kev_ids:
            logger.info(f"Found {len(new_ids)} new CISA KEV entries: {', '.join(sorted(list(new_ids)))}")
            
            # Persist new IDs *before* adding to in-memory set and processing
            try:
                self.db.add_seen_kevs(new_ids)
            except Exception as e:
                # Log error but continue, so we still attempt alerts
                logger.error(f"Failed to persist new KEV IDs to database: {e}", exc_info=True)
                
            # Find the full details for the new IDs
            for vuln in data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID')
                if cve_id in new_ids:
                    new_vuln_details.append(vuln)
                    # Update in-memory set *after* successful DB add attempt
                    self.seen_kev_ids.add(cve_id) 
        else:
            logger.info("No new entries found in CISA KEV catalog.")

        # Return details for newly found entries (could be empty)
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