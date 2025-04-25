import asyncio
from datetime import datetime
import logging
import discord
from discord import app_commands
from discord.ext import commands

from ..config import Config
from ..database import Vulnerability
from ..nvd import NVDClient, CVSS_V3_SEVERITY_MAP, CVSS_V2_SEVERITY_MAP
from ..util import pluralize

# Removed the group definition, it's now in the bot class

logger = logging.getLogger(__name__)


class CveLookupCog(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    # Register the command within the 'cve' group managed by the bot
    # The group association happens automatically when the cog is loaded
    # if the group name matches the one added to the tree in the bot setup.
    # Alternatively, explicitly assign to group in __init__ if needed,
    # but standard discovery should work.
    @app_commands.command(name="lookup", description="Look up CVE details from the NVD database.")
    @app_commands.describe(cve_id="The CVE ID to look up (e.g., CVE-2021-44228)")
    async def cve_lookup(self, interaction: discord.Interaction, cve_id: str):
        """Looks up CVE details from the NVD database."""
        # Access bot instance via self.bot
        if not hasattr(self.bot, 'nvd_client') or self.bot.nvd_client is None:
            logger.error("NVDClient not initialized in bot instance.")
            await interaction.response.send_message("Error: NVD Service not available.", ephemeral=True)
            return

        nvd_client: NVDClient = self.bot.nvd_client
        logger.info(f"User {interaction.user} ({interaction.user.id}) looking up CVE: {cve_id}")

        # Basic validation of CVE ID format
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            await interaction.response.send_message(
                "Invalid format. Please use the format `CVE-YYYY-NNNNN`.",
                ephemeral=True
            )
            return

        await interaction.response.defer(ephemeral=True) # Defer while fetching

        try:
            cve_data = await nvd_client.get_cve(cve_id.upper())
            if not cve_data:
                await interaction.followup.send(f"Could not find information for `{cve_id}`.", ephemeral=True)
                return

            # --- Create Embed ---
            vuln = cve_data.get('vuln', {})
            cve_id_display = vuln.get('id', cve_id.upper())
            description = "No description available."
            if vuln.get('descriptions'):
                eng_desc = next((d['value'] for d in vuln['descriptions'] if d.get('lang') == 'en'), None)
                if eng_desc:
                    description = eng_desc

            embed = discord.Embed(
                title=f"Details for {cve_id_display}",
                description=description[:4096], # Max description length
                color=discord.Color.orange() # Default color
            )

            # Severity and Score
            cvss_v3_severity = "N/A"
            cvss_v3_score = "N/A"
            cvss_v2_severity = "N/A"
            cvss_v2_score = "N/A"
            severity_color = discord.Color.greyple() # Default/unknown severity color

            if metrics := vuln.get('metrics'):
                if cvss_v31 := metrics.get('cvssMetricV31'):
                    data = cvss_v31[0].get('cvssData', {})
                    cvss_v3_score = data.get('baseScore', 'N/A')
                    cvss_v3_severity = data.get('baseSeverity', 'N/A').capitalize()
                    if cvss_v3_severity in CVSS_V3_SEVERITY_MAP:
                        severity_color = CVSS_V3_SEVERITY_MAP[cvss_v3_severity]
                elif cvss_v30 := metrics.get('cvssMetricV30'):
                     data = cvss_v30[0].get('cvssData', {})
                     cvss_v3_score = data.get('baseScore', 'N/A')
                     cvss_v3_severity = data.get('baseSeverity', 'N/A').capitalize()
                     if cvss_v3_severity in CVSS_V3_SEVERITY_MAP:
                         severity_color = CVSS_V3_SEVERITY_MAP[cvss_v3_severity]
                # Fallback to V2 if V3 not present
                elif cvss_v2 := metrics.get('cvssMetricV2') and cvss_v3_severity == "N/A":
                    data = cvss_v2[0].get('cvssData', {})
                    cvss_v2_score = data.get('baseScore', 'N/A')
                    cvss_v2_severity = cvss_v2[0].get('baseSeverity', 'N/A').capitalize()
                    if cvss_v2_severity in CVSS_V2_SEVERITY_MAP:
                        severity_color = CVSS_V2_SEVERITY_MAP[cvss_v2_severity]


            embed.color = severity_color # Set color based on severity
            embed.add_field(name="CVSS v3 Score", value=f"{cvss_v3_score} ({cvss_v3_severity})", inline=True)
            # Only show V2 if V3 wasn't available or V2 has data
            if cvss_v3_severity == "N/A" or cvss_v2_score != "N/A":
                 embed.add_field(name="CVSS v2 Score", value=f"{cvss_v2_score} ({cvss_v2_severity})", inline=True)

            # References
            if references := vuln.get('references'):
                ref_list = [f"- <{ref['url']}> ({ref.get('source', 'N/A')})" for ref in references[:5]] # Limit refs
                embed.add_field(name="References", value="
".join(ref_list), inline=False)

            # Weaknesses (CWE)
            if weaknesses := vuln.get('weaknesses'):
                cwe_list = []
                for weakness in weaknesses[:3]: # Limit CWEs
                    cwe_id = "N/A"
                    desc = "N/A"
                    if weakness.get('description'):
                        eng_cwe_desc = next((d['value'] for d in weakness['description'] if d.get('lang') == 'en'), None)
                        if eng_cwe_desc:
                            # Try to extract CWE ID if present
                            if "CWE-" in eng_cwe_desc:
                                parts = eng_cwe_desc.split(":", 1)
                                cwe_id = parts[0].strip()
                                desc = parts[1].strip() if len(parts) > 1 else eng_cwe_desc
                            else:
                                desc = eng_cwe_desc
                    cwe_list.append(f"- {cwe_id}: {desc}")

                embed.add_field(name="Weaknesses (CWE)", value="
".join(cwe_list), inline=False)


            # Published and Modified Dates
            published_date = vuln.get('published', 'N/A')
            modified_date = vuln.get('lastModified', 'N/A')
            try:
                if published_date != 'N/A':
                    published_dt = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                    published_date = f"<t:{int(published_dt.timestamp())}:f>"
                if modified_date != 'N/A':
                    modified_dt = datetime.fromisoformat(modified_date.replace('Z', '+00:00'))
                    modified_date = f"<t:{int(modified_dt.timestamp())}:R>" # Relative time
            except ValueError:
                 logger.warning(f"Could not parse date for {cve_id_display}: pub={published_date}, mod={modified_date}")
                 # Keep original string if parsing fails

            embed.add_field(name="Published", value=published_date, inline=True)
            embed.add_field(name="Last Modified", value=modified_date, inline=True)

            # NVD Link
            nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id_display}"
            embed.add_field(name="NVD Link", value=f"<{nvd_link}>", inline=False)


            embed.set_footer(text="Data provided by NVD API")
            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.exception(f"Error looking up CVE {cve_id}: {e}")
            await interaction.followup.send(f"An error occurred while looking up `{cve_id}`.", ephemeral=True)


async def setup(bot: commands.Bot):
    await bot.add_cog(CveLookupCog(bot)) 