import discord
from discord.ext import commands
from discord import app_commands
import aiohttp
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

# Import the specific group object from the other cog file
from .cve_lookup import cve_group as imported_cve_group

# Use absolute imports for type checking
if TYPE_CHECKING:
    from kevvy.bot import SecurityBot

# Configure logging
logger = logging.getLogger(__name__)

# NVD API URL
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class CVEInfoCog(commands.Cog):
    """Cog for fetching CVE information."""

    def __init__(self, bot: 'SecurityBot'):
        self.bot = bot

    @imported_cve_group.command(name="latest", description="Fetches the 10 latest CVEs from NVD.")
    async def latest_subcommand(self, interaction: discord.Interaction):
        """Handles the /cve latest subcommand."""
        await interaction.response.defer() # Acknowledge interaction while fetching

        if not self.bot.http_session:
             logger.error("Bot's shared aiohttp session is not available.")
             await interaction.followup.send("An internal error occurred (HTTP session missing).", ephemeral=True)
             return

        headers = {}
        nvd_api_key = self.bot.nvd_client.api_key if self.bot.nvd_client else None
        if nvd_api_key:
             headers['apiKey'] = nvd_api_key
             logger.debug("Using NVD API key for /cve latest request.")
        else:
            logger.debug("NVD API key not found, making /cve latest request without it.")

        try:
            params = {
                'resultsPerPage': '10',
                'sortBy': 'publishedDate',
                'sortOrder': 'DESC'
            }
            # Use bot's session and pass headers
            async with self.bot.http_session.get(NVD_API_URL, params=params, headers=headers) as response:
                response.raise_for_status() # Raise exception for bad status codes (including 404)
                data = await response.json()

                if not data or 'vulnerabilities' not in data:
                    logger.error("NVD API returned unexpected data structure for /cve latest.")
                    await interaction.followup.send("Failed to fetch CVE data: Invalid API response.", ephemeral=True)
                    return

                embed = discord.Embed(
                    title="Latest 10 CVEs",
                    color=discord.Color.orange(),
                    timestamp=datetime.now(timezone.utc)
                )
                embed.set_footer(text="Data sourced from NVD")

                description_lines = []
                for item in data['vulnerabilities']:
                    cve_data = item.get('cve', {})
                    cve_id = cve_data.get('id', 'N/A')

                    # Find English description
                    description = "No description available."
                    descriptions = cve_data.get('descriptions', [])
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', description)
                            break

                    # Truncate description if too long
                    max_desc_len = 150
                    if len(description) > max_desc_len:
                        description = f"{description[:max_desc_len]}..."

                    # Get CVSS v3.1 score
                    cvss_score = "N/A"
                    metrics = cve_data.get('metrics', {})
                    if cvss_v31 := metrics.get('cvssMetricV31', []):
                        cvss_data = cvss_v31[0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 'N/A')

                        if severity := cvss_data.get('baseSeverity', ''):
                             cvss_score = f"{cvss_score} ({severity})"

                    description_lines.append(
                        f"**[{cve_id}]** (Score: {cvss_score})\\n{description}\\n"
                    )

                embed.description = "\\n".join(description_lines) if description_lines else "No CVEs found."

                await interaction.followup.send(embed=embed)

        except aiohttp.ClientResponseError as e: # Catch more specific error for status
            # Log includes URL and params, plus API key usage status now
            logger.error(f"HTTP error fetching latest CVEs: {e.status} {str(e)}. URL: {e.request_info.url}, Headers: {e.request_info.headers}")
            await interaction.followup.send(f"Failed to fetch CVE data: Network error ({e.status}). Please try again later.", ephemeral=True)
        except aiohttp.ClientError as e: # Catch other client errors
            logger.error(f"HTTP client error fetching latest CVEs: {e}")
            await interaction.followup.send(f"Failed to fetch CVE data: Network error. Please try again later.", ephemeral=True)
        except Exception as e:
            logger.exception("An unexpected error occurred in /cve latest command:") # Log full traceback
            await interaction.followup.send("An unexpected error occurred while fetching CVE data.", ephemeral=True)


async def setup(bot: 'SecurityBot'):
    """Sets up the CVEInfoCog."""
    await bot.add_cog(CVEInfoCog(bot))
    logger.info("CVEInfoCog loaded.") 