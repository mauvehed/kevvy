import re
import discord
import logging
from datetime import datetime

# from .vulners_client import VulnersClient # Removed VulnersClient
from .nvd_client import NVDClient, NVDRateLimitError  # Remove NVDAPIError import
from .cisa_kev_client import CisaKevClient
from typing import Optional, Dict, Any, Tuple

# Assuming VulnCheckClient and StatsManager will be imported
from .vulncheck_client import VulnCheckClient  # Add this import
from .stats_manager import StatsManager  # Add this import

# Max length for embed fields
MAX_FIELD_LENGTH = 1024
MAX_REFERENCE_LINKS = 5
MAX_DESCRIPTION_LENGTH = 2048

logger = logging.getLogger(__name__)


class CVEMonitor:
    CVE_REGEX = re.compile(r"CVE(?:-| )\d{4}(?:-| )\d{4,7}", re.IGNORECASE)

    def __init__(
        self,
        nvd_client: NVDClient,
        vulncheck_client: Optional[VulnCheckClient] = None,  # Added
        kev_client: Optional[CisaKevClient] = None,
        stats_manager: Optional[StatsManager] = None,  # Added
    ):
        self.nvd_client = nvd_client
        self.vulncheck_client = vulncheck_client  # Added
        self.kev_client = kev_client
        self.stats_manager = stats_manager  # Added
        # self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE) # Use Class attribute

    def find_cves(self, content: str) -> list:
        """Finds all occurrences of CVE patterns in a string."""
        return self.CVE_REGEX.findall(content)

    async def get_cve_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetches CVE data, trying VulnCheck first, then NVD as fallback."""
        cve_data: Optional[Dict[str, Any]] = None

        # Try VulnCheck first if available
        if self.vulncheck_client:
            try:
                logger.debug(f"Attempting to fetch {cve_id} from VulnCheck.")
                cve_data = await self.vulncheck_client.get_cve_details(cve_id)
                if cve_data:
                    logger.info(f"Successfully fetched {cve_id} from VulnCheck.")
                    if self.stats_manager:
                        await self.stats_manager.increment_vulncheck_success()
                    return cve_data  # Return early if VulnCheck succeeded
                else:
                    logger.debug(f"No data for {cve_id} from VulnCheck, will try NVD.")
            except Exception as e:
                logger.error(
                    f"Error fetching {cve_id} from VulnCheck: {e}", exc_info=True
                )
                if self.stats_manager:
                    await self.stats_manager.record_api_error(service="vulncheck")

        # Fallback to NVD if VulnCheck not available, failed, or returned no data
        try:
            logger.debug(
                f"Attempting to fetch {cve_id} from NVD as primary or fallback."
            )
            cve_data = await self.nvd_client.get_cve_details(cve_id)
            if cve_data:
                logger.info(f"Successfully fetched {cve_id} from NVD.")
                if self.stats_manager:
                    await (
                        self.stats_manager.increment_nvd_fallback_success()
                    )  # NVD success recorded here
                return cve_data
            else:
                logger.warning(f"No data returned from NVD for {cve_id}")
                return None
        except NVDRateLimitError as e:
            logger.error(f"NVD rate limit hit fetching {cve_id}: {e}")
            if self.stats_manager:
                await (
                    self.stats_manager.record_nvd_rate_limit_hit()
                )  # Record NVD rate limit
            raise  # Re-raise so the caller (on_message) can handle it
        except Exception as e:
            logger.error(
                f"Unexpected error fetching NVD data for {cve_id}: {e}", exc_info=True
            )
            if self.stats_manager:
                await self.stats_manager.record_api_error(
                    service="nvd"
                )  # Record generic NVD error
            return None

    def check_severity_threshold(
        self, cve_data: Dict[str, Any], min_threshold_str: str
    ) -> Tuple[bool, Optional[str]]:
        """Checks if the CVE severity meets the minimum threshold.
        Returns a tuple: (passes_threshold: bool, cve_severity_str: Optional[str])
        """
        severity_map = {
            "low": 0.1,
            "medium": 4.0,
            "high": 7.0,
            "critical": 9.0,
            "all": 0.0,
        }
        min_score = severity_map.get(min_threshold_str.lower(), 0.0)

        cvss_score = cve_data.get("cvss")
        cve_severity_str = self.get_severity_string(cvss_score)

        if cvss_score is None:
            # Decide how to handle CVEs without a score. Assume pass for now?
            # Or maybe only pass if threshold is 'all'?
            # Current: Pass if threshold is 'all', otherwise fail.
            return min_score == 0.0, cve_severity_str

        return cvss_score >= min_score, cve_severity_str

    def get_severity_string(self, cvss: float | None) -> str:
        if cvss is None:
            return "Unknown"
        if cvss >= 9.0:
            return "Critical"
        if cvss >= 7.0:
            return "High"
        if cvss >= 4.0:
            return "Medium"
        return "Low"

    async def check_kev(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Checks if a CVE exists in the KEV catalog."""
        if not self.kev_client:
            return None
        try:
            return await self.kev_client.get_kev_entry(cve_id)
        except Exception as e:
            logger.error(f"Error checking KEV status for {cve_id}: {e}", exc_info=True)
            return None

    def create_cve_embed(self, cve_data: dict, verbose: bool = False) -> discord.Embed:
        """Creates a Discord embed ONLY for CVE data."""
        cve_id = cve_data.get("id", "Unknown CVE")
        title = cve_id  # Keep title simple for CVE embed
        link = cve_data.get("link")
        cvss_score = cve_data.get("cvss")
        cvss_version = cve_data.get("cvss_version")

        embed = discord.Embed(
            title=title, url=link, color=self._get_severity_color(cvss_score)
        )

        # --- Fields added regardless of verbosity ---
        embed.add_field(name="CVE ID", value=cve_id, inline=True)

        cvss_score_display = str(cvss_score or "N/A")
        if cvss_version:
            cvss_score_display += f" (v{cvss_version})"
        embed.add_field(name="CVSS Score", value=cvss_score_display, inline=True)

        embed.add_field(name="Source", value=cve_data.get("source", "N/A"), inline=True)
        # --- End always-added fields ---

        if verbose:
            # Set description only in verbose mode
            description = cve_data.get("description", "No description available.")
            if len(description) > MAX_DESCRIPTION_LENGTH:
                description = f"{description[: MAX_DESCRIPTION_LENGTH - 3]}..."
            embed.description = description

            embed.add_field(
                name="Published",
                value=self._format_date(cve_data.get("published")),
                inline=True,
            )
            embed.add_field(
                name="Last Modified",
                value=self._format_date(cve_data.get("modified")),
                inline=True,
            )

            # Add placeholder field to keep layout consistent if Published/Modified are short
            embed.add_field(
                name="\u200b", value="\u200b", inline=True
            )  # Invisible field

            if cvss_vector := cve_data.get("cvss_vector"):
                if len(cvss_vector) > MAX_FIELD_LENGTH:
                    cvss_vector = f"{cvss_vector[: MAX_FIELD_LENGTH - 3]}..."
                embed.add_field(
                    name="CVSS Vector", value=f"`{cvss_vector}`", inline=False
                )

            if cwe_ids := cve_data.get("cwe_ids"):
                cwe_display = ", ".join(cwe_ids)
                if len(cwe_display) > MAX_FIELD_LENGTH:
                    cwe_display = f"{cwe_display[: MAX_FIELD_LENGTH - 3]}..."
                embed.add_field(
                    name="Weaknesses (CWE)", value=cwe_display, inline=False
                )

            if references := cve_data.get("references", []):
                ref_links = []
                count = 0
                for ref in references:
                    if ref.get("url") and count < MAX_REFERENCE_LINKS:
                        # Try to get a meaningful source name
                        source_name = ref.get("tags", [])
                        if source_name:
                            source_name = source_name[0]  # Take the first tag
                        else:
                            # Extract domain from URL as fallback source name
                            try:
                                domain_match = re.match(
                                    r"https?://(?:www\.)?([^/]+)", ref["url"]
                                )
                                source_name = (
                                    domain_match[1] if domain_match else "Link"
                                )
                            except (TypeError, re.error) as e:
                                logger.debug(f"Failed to extract domain from URL: {e}")
                                source_name = "Link"

                        link_text = f"- [{source_name}]({ref['url']})"
                        ref_links.append(link_text)
                        count += 1

                if ref_links:
                    ref_display = "\n".join(ref_links)
                    if len(references) > MAX_REFERENCE_LINKS:
                        ref_display += f"\n*({len(references) - MAX_REFERENCE_LINKS} more references not shown)*"

                    if len(ref_display) > MAX_FIELD_LENGTH:
                        ref_display = f"{ref_display[: MAX_FIELD_LENGTH - 3]}..."
                    embed.add_field(name="References", value=ref_display, inline=False)

        return embed

    def create_kev_status_embed(
        self, cve_id: str, kev_entry: Dict[str, Any], verbose: bool = False
    ) -> discord.Embed:
        """Creates a standardized embed for a KEV entry notification, adjusting for verbosity."""
        nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        if verbose:
            # Detailed KEV Embed
            embed = discord.Embed(
                title=f"🚨 CISA KEV Alert: {cve_id}",
                description=kev_entry.get(
                    "shortDescription", "No description available."
                ),
                url=nvd_link,
                color=discord.Color.dark_red(),
            )
            embed.add_field(
                name="Vulnerability Name",
                value=kev_entry.get("vulnerabilityName", "N/A"),
                inline=False,
            )
            embed.add_field(
                name="Vendor/Project",
                value=kev_entry.get("vendorProject", "N/A"),
                inline=True,
            )
            embed.add_field(
                name="Product", value=kev_entry.get("product", "N/A"), inline=True
            )
            embed.add_field(
                name="Date Added to KEV",
                value=self._format_date(kev_entry.get("dateAdded")),
                inline=True,
            )
            embed.add_field(
                name="Required Action",
                value=kev_entry.get("requiredAction", "N/A"),
                inline=False,
            )
            embed.add_field(
                name="Due Date",
                value=self._format_date(kev_entry.get("dueDate")),
                inline=True,
            )
            embed.add_field(
                name="Known Ransomware Use",
                value=kev_entry.get("knownRansomwareCampaignUse", "N/A"),
                inline=True,
            )
            if notes := kev_entry.get("notes", ""):
                notes_display = f"{notes[:1020]}..." if len(notes) > 1024 else notes
                embed.add_field(name="Notes", value=notes_display, inline=False)
        else:
            # Terse KEV Embed
            embed = discord.Embed(
                title=f"🚨 KEV Alert: {cve_id}",
                description=f"Known Exploited Vulnerability ([View on NVD]({nvd_link}))",
                url=nvd_link,  # Keep link clickable via title
                color=discord.Color.dark_red(),
            )
            # No fields in terse mode

        embed.timestamp = discord.utils.utcnow()  # Use discord utils for timestamp
        return embed

    def _get_severity_color(self, cvss: float | None) -> int:
        if cvss is None:
            return 0x808080  # Gray for unknown
        elif cvss >= 9.0:
            return 0xFF0000  # Critical
        elif cvss >= 7.0:
            return 0xFF8C00  # High
        elif cvss >= 4.0:
            return 0xFFFF00  # Medium
        else:
            return 0x00FF00  # Low

    def _format_date(self, date_str: str | None) -> str:
        if not date_str:
            return "N/A"
        # Try parsing the expected format first
        try:
            date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
            return date.strftime("%B %d, %Y")
        except ValueError:
            # Fallback for just date part if full parsing failed (e.g., if NVDClient returned original string)
            try:
                date_part = date_str.split("T")[0]
                date = datetime.strptime(date_part, "%Y-%m-%d")
                return date.strftime("%B %d, %Y")
            except Exception:
                # If all else fails, return the original string
                return date_str
