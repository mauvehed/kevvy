import logging
import aiohttp
from aiohttp import ClientTimeout
from typing import Set, List, Dict, Any, Optional
from .db_utils import KEVConfigDB
import time

logger = logging.getLogger(__name__)


class CisaKevClient:
    """
    Client to fetch and process the CISA Known Exploited Vulnerabilities (KEV) catalog.
    Monitors the KEV JSON feed for new additions.
    """

    KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    HEADERS = {"User-Agent": "kevvy-bot/1.0"}
    CACHE_DURATION_SECONDS = 300  # Cache KEV catalog for 5 minutes

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
        self._cache: Optional[List[Dict[str, Any]]] = None
        self._cache_time: float = 0

    async def _fetch_kev_data(self) -> Optional[Dict[str, Any]]:
        """Fetches the raw KEV data from CISA."""
        request_timeout = ClientTimeout(total=30)
        try:
            async with self.session.get(
                self.KEV_CATALOG_URL, headers=self.HEADERS, timeout=request_timeout
            ) as response:
                response.raise_for_status()
                if response.content_type == "application/json":
                    return await response.json()

                logger.error(
                    f"Unexpected content type received from CISA KEV feed: {response.content_type}"
                )
                try:
                    logger.warning("Attempting to parse non-JSON response as JSON...")
                    return await response.json()
                except Exception:
                    logger.error(
                        "Failed to decode CISA KEV response even after content-type mismatch."
                    )
                    return None
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error fetching CISA KEV data: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching CISA KEV data: {e}", exc_info=True)
            return None

    async def get_full_kev_catalog(self) -> Optional[List[Dict[str, Any]]]:
        """Fetches the full KEV catalog, using a time-based cache.
        If a fresh fetch fails, it will not return stale cached data beyond its expiry.
        """
        now = time.monotonic()
        # Check if a valid, non-expired cache exists
        if self._cache is not None and (
            now - self._cache_time < self.CACHE_DURATION_SECONDS
        ):
            logger.debug(
                f"Returning KEV catalog from active cache (cached at {self._cache_time:.2f}, current time: {now:.2f}, expires ~{self._cache_time + self.CACHE_DURATION_SECONDS:.2f})."
            )
            return self._cache

        # Cache is expired or not populated; attempt a fresh fetch
        logger.info(
            "KEV cache expired or not populated. Attempting to fetch fresh catalog data."
        )
        fresh_data_payload = (
            await self._fetch_kev_data()
        )  # This is the dict like {"vulnerabilities": [...]} or None

        if not fresh_data_payload or "vulnerabilities" not in fresh_data_payload:
            logger.warning(
                "Failed to fetch or parse fresh CISA KEV data. Catalog will not be updated from this attempt."
            )
            # If the fetch fails, we do not serve any data that would be considered "current".
            # If an old cache exists but is expired (which it would be to reach here), don't return it.
            # Effectively, no current data is available.
            return None

        # Fetch was successful, update the cache
        newly_fetched_vulnerabilities = fresh_data_payload.get("vulnerabilities", [])
        self._cache = newly_fetched_vulnerabilities
        self._cache_time = (
            now  # Update cache timestamp only on successful fetch & update
        )

        # Explicitly check if cache is not None before logging its length
        if (
            self._cache is not None
        ):  # Should be true if "vulnerabilities" was present or default to []
            cache_len = len(self._cache)
            logger.info(
                f"Successfully fetched and cached {cache_len} KEV entries. Cache timestamp updated to {self._cache_time:.2f}."
            )
        else:
            # This case should ideally not be hit if fresh_data_payload had "vulnerabilities"
            # or if .get("vulnerabilities", []) worked as expected.
            logger.warning(
                "KEV data fetched, but self._cache is None after assignment. This is unexpected."
            )

        return self._cache

    async def get_kev_entry(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetches the KEV entry for a specific CVE if it exists in the catalog.
        Uses the cached catalog if available.

        Args:
            cve_id: The CVE ID to look up (e.g., 'CVE-2021-44228')

        Returns:
            Optional[Dict[str, Any]]: The KEV entry if found, None otherwise
        """
        catalog = await self.get_full_kev_catalog()
        if not catalog:
            logger.warning("Could not get KEV catalog while checking for specific CVE.")
            return None

        return next((vuln for vuln in catalog if vuln.get("cveID") == cve_id), None)

    async def get_new_kev_entries(self) -> List[Dict[str, Any]]:
        """
        Fetches the latest KEV catalog and returns a list of vulnerabilities
        that are new since the last check or initial load.
        Uses the cached catalog if available and up-to-date for efficiency.
        """
        logger.info("Checking for new CISA KEV entries...")
        # Use the cached fetch method
        catalog = await self.get_full_kev_catalog()
        if not catalog:
            logger.warning("Could not get KEV catalog data to check for new entries.")
            return []

        # Get all potential IDs, including None
        all_catalog_ids: Set[Optional[str]] = {vuln.get("cveID") for vuln in catalog}
        # Filter out None values explicitly
        current_kev_ids: Set[str] = {
            cid for cid in all_catalog_ids if isinstance(cid, str)
        }

        new_vuln_details = []

        if new_ids := current_kev_ids - self.seen_kev_ids:
            logger.info(
                f"Found {len(new_ids)} new CISA KEV entries: {', '.join(sorted(list(new_ids)))}"
            )

            try:
                self.db.add_seen_kevs(new_ids)
            except Exception as e:
                logger.error(
                    f"Failed to persist new KEV IDs to database: {e}", exc_info=True
                )

            for vuln in catalog:
                cve_id = vuln.get("cveID")
                # Check cve_id is not None before adding
                if cve_id and cve_id in new_ids:
                    new_vuln_details.append(vuln)
                    self.seen_kev_ids.add(cve_id)
        else:
            logger.info("No new entries found in CISA KEV catalog.")

        return new_vuln_details
