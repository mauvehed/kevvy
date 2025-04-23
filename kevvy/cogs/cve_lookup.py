import discord
from discord import app_commands
from discord.ext import commands
import re
import logging
from typing import Optional, TYPE_CHECKING

# Use absolute imports for type checking
if TYPE_CHECKING:
    from kevvy.bot import SecurityBot
    from kevvy.nvd_client import NVDClient

logger = logging.getLogger(__name__)

# Basic regex for CVE ID format
CVE_REGEX = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

# Define the command group
class CVELookupCog(commands.Cog):
    """Cog for handling CVE lookup commands."""

    def __init__(self, bot: 'SecurityBot'):
        self.bot = bot
        self.nvd_client: Optional['NVDClient'] = self.bot.nvd_client

    # Define the base group - this won't be directly callable
    # You can add a description here if desired
    cve_group = app_commands.Group(name="cve", description="Commands related to CVE information.")

    def create_cve_embed(self, cve_data: dict) -> discord.Embed:
        """Creates a Discord embed from fetched CVE data."""
        embed = discord.Embed(
            title=f"{cve_data.get('id', 'Unknown CVE')}",
            url=cve_data.get('link'),
            description=cve_data.get('description', 'No description provided.'),
            color=discord.Color.purple() # Or choose another color
        )

        if cve_data.get('cvss'):
            cvss_info = f"**Score:** {cve_data['cvss']}"
            if cve_data.get('cvss_version'):
                cvss_info += f" ({cve_data['cvss_version']})"
            if cve_data.get('cvss_vector'):
                 embed.add_field(name="CVSS Vector", value=f"`{cve_data['cvss_vector']}`", inline=False)
            embed.add_field(name="CVSS Score", value=cvss_info, inline=True)

        if cve_data.get('cwe_ids'):
            cwe_text = ", ".join(cve_data['cwe_ids'])
            embed.add_field(name="Weakness (CWE)", value=cwe_text, inline=True)

        if cve_data.get('published'):
            embed.add_field(name="Published", value=cve_data['published'], inline=True)
        if cve_data.get('modified'):
             embed.add_field(name="Last Modified", value=cve_data['modified'], inline=True)

        if references := cve_data.get('references', []):
            ref_limit = 5
            ref_text = ""
            for i, ref in enumerate(references[:ref_limit]):
                ref_text += f"- [{ref.get('source', 'Link')}]({ref.get('url')})"
                if ref.get('tags'):
                    ref_text += f" ({', '.join(ref['tags'])})"
                ref_text += "\n"
            if len(references) > ref_limit:
                ref_text += f"*...and {len(references) - ref_limit} more.*"
            embed.add_field(name="References", value=ref_text.strip(), inline=False)


        embed.set_footer(text=f"Source: {cve_data.get('source', 'N/A')}")
        embed.timestamp = discord.utils.utcnow()

        return embed

    @cve_group.command(name="lookup", description="Look up details for a specific CVE ID from NVD.")
    @app_commands.describe(cve_id="The CVE ID (e.g., CVE-2023-12345)")
    async def lookup_subcommand(self, interaction: discord.Interaction, cve_id: str):
        """Handles the /cve lookup subcommand."""
        await interaction.response.defer()

        if not CVE_REGEX.match(cve_id):
            await interaction.followup.send(
                "❌ Invalid CVE ID format. Please use `CVE-YYYY-NNNNN...` (e.g., CVE-2023-12345).",
                ephemeral=True,
            )
            return

        if not self.nvd_client:
             logger.error("NVDClient is not available for /cve command.")
             await interaction.followup.send("❌ The NVD client is not configured or failed to initialize. Cannot perform lookup.", ephemeral=True)
             return

        try:
            logger.info(f"User {interaction.user} ({interaction.user.id}) looking up CVE: {cve_id} via /cve lookup")
            cve_details = await self.nvd_client.get_cve_details(cve_id.upper())

            if cve_details:
                embed = self.create_cve_embed(cve_details)
                await interaction.followup.send(embed=embed)
            else:
                await interaction.followup.send(f"🤷 Could not find details for `{cve_id}` in NVD, or an error occurred during fetch.")

        except Exception as e:
            logger.error(f"Unexpected error during /cve lookup command for {cve_id}: {e}", exc_info=True)
            await interaction.followup.send(f"❌ An unexpected error occurred while looking up `{cve_id}`. Please try again later.", ephemeral=True)


async def setup(bot: 'SecurityBot'):
    """Sets up the CVE Lookup Cog."""
    if not bot.nvd_client:
         logger.warning("NVDClient not initialized. CVE Lookup Cog will not be loaded.")
         return # Don't load cog if NVD client isn't ready

    await bot.add_cog(CVELookupCog(bot))
    logger.info("CVE Lookup Cog loaded.") 