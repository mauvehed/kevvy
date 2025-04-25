import discord
from discord.ext import commands
from discord import app_commands
import aiohttp
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

# NVD API URL
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class CVEInfoCog(commands.Cog):
    """Cog for fetching CVE information."""

    def __init__(self, bot):
        self.bot = bot
        self.session = aiohttp.ClientSession() # Create a persistent session

    async def cog_unload(self):
        """Clean up the session when the cog is unloaded."""
        await self.session.close()

    @app_commands.command(name="cve-latest", description="Fetches the 10 latest CVEs from NVD.")
    async def cve_latest(self, interaction: discord.Interaction):
        """Handles the /cve latest command."""
        await interaction.response.defer() # Acknowledge interaction while fetching

        try:
            params = {
                'resultsPerPage': 10,
                'sortBy': 'publishedDate', # Correct parameter for sorting
                'sortOrder': 'DESC'       # Get the latest first
            }
            async with self.session.get(NVD_API_URL, params=params) as response:
                response.raise_for_status() # Raise exception for bad status codes
                data = await response.json()

                if not data or 'vulnerabilities' not in data:
                    logger.error("NVD API returned unexpected data structure.")
                    await interaction.followup.send("Failed to fetch CVE data: Invalid API response.", ephemeral=True)
                    return

                embed = discord.Embed(
                    title="Latest 10 CVEs",
                    color=discord.Color.orange(),
                    timestamp=datetime.utcnow()
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
                        description = description[:max_desc_len] + "..."

                    # Get CVSS v3.1 score
                    cvss_score = "N/A"
                    metrics = cve_data.get('metrics', {})
                    cvss_v31 = metrics.get('cvssMetricV31', [])
                    if cvss_v31:
                        cvss_score = cvss_v31[0].get('cvssData', {}).get('baseScore', 'N/A')
                        # Also include severity for context if available
                        severity = cvss_v31[0].get('cvssData', {}).get('baseSeverity', '')
                        if severity:
                             cvss_score = f"{cvss_score} ({severity})"

                    # Correctly format the multi-line f-string
                    description_lines.append(
                        f"**[{cve_id}]** (Score: {cvss_score})\\n"
                        f"{description}\\n"
                    )

                embed.description = "\\n".join(description_lines) if description_lines else "No CVEs found."

                await interaction.followup.send(embed=embed)

        except aiohttp.ClientResponseError as e: # Catch more specific error for status
            logger.error(f"HTTP error fetching CVEs: {e.status} {str(e)}")
            await interaction.followup.send(f"Failed to fetch CVE data: Network error ({e.status}). Please try again later.", ephemeral=True)
        except aiohttp.ClientError as e: # Catch other client errors
            logger.error(f"HTTP error fetching CVEs: {e}")
            await interaction.followup.send(f"Failed to fetch CVE data: Network error. Please try again later.", ephemeral=True)
        except Exception as e:
            logger.exception("An unexpected error occurred in cve_latest command:") # Log full traceback
            await interaction.followup.send("An unexpected error occurred while fetching CVE data.", ephemeral=True)


async def setup(bot):
    """Sets up the CVEInfoCog."""
    await bot.add_cog(CVEInfoCog(bot))
    logger.info("CVEInfoCog loaded.") 