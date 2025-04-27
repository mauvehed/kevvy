import discord
from discord import app_commands
from discord.ext import commands
import re
import logging
from typing import Optional, TYPE_CHECKING, Literal
import datetime

# Use absolute imports for type checking
if TYPE_CHECKING:
    from kevvy.bot import SecurityBot
    from kevvy.nvd_client import NVDClient
    from kevvy.db_utils import KEVConfigDB, SeverityLevel # Import SeverityLevel

logger = logging.getLogger(__name__)

# Basic regex for CVE ID format
CVE_REGEX = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

# Define SeverityLevel choices for commands
SeverityLevelChoices = Literal["critical", "high", "medium", "low", "all"]

# Define the command group
class CVELookupCog(commands.Cog):
    """Cog for handling CVE lookup and configuration commands."""

    def __init__(self, bot: 'SecurityBot'):
        self.bot = bot
        self.nvd_client: Optional['NVDClient'] = self.bot.nvd_client
        self.db: Optional['KEVConfigDB'] = self.bot.db # Add DB reference

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

        # Use helper method for lookup logic
        await self._perform_cve_lookup(interaction, cve_id.upper())

    # Helper for lookup logic shared by command and potentially message scanning
    async def _perform_cve_lookup(self, interaction: discord.Interaction, cve_id_upper: str):
        if not self.nvd_client:
             logger.error("NVDClient is not available for CVE lookup.")
             await interaction.followup.send("❌ The NVD client is not configured or failed to initialize. Cannot perform lookup.", ephemeral=True)
             return

        try:
            logger.info(f"User {interaction.user} ({interaction.user.id}) looking up CVE: {cve_id_upper} via /cve lookup")
            
            # --- Add Stat Increment ---
            async with self.bot.stats_lock:
                self.bot.stats_cve_lookups += 1
            # --- End Stat Increment ---
            
            cve_details = await self.nvd_client.get_cve_details(cve_id_upper)

            if cve_details:
                # --- Add Stat Increment ---
                # Using nvd_fallback_success counter here for simplicity as this command only uses NVD
                async with self.bot.stats_lock:
                    self.bot.stats_nvd_fallback_success += 1
                # --- End Stat Increment ---
                
                embed = self.create_cve_embed(cve_details)
                await interaction.followup.send(embed=embed)
            else:
                await interaction.followup.send(f"🤷 Could not find details for `{cve_id_upper}` in NVD, or an error occurred during fetch.")

        except Exception as e:
            logger.error(f"Unexpected error during CVE lookup for {cve_id_upper}: {e}", exc_info=True)
            
            # --- Add Stat Increment ---
            async with self.bot.stats_lock:
                self.bot.stats_api_errors_nvd += 1
            # --- End Stat Increment ---
            
            await interaction.followup.send(f"❌ An unexpected error occurred while looking up `{cve_id_upper}`. Please try again later.", ephemeral=True)

    # --- NEW /cve latest command (incorporating Future Enhancements) ---
    @cve_group.command(name="latest", description="Display the most recent CVEs with filters.")
    @app_commands.describe(
        count="Number of CVEs to show (default 5, max 10)",
        days="Look back N days (default 7, max 30)",
        severity="Filter by minimum severity (critical, high, medium, low)",
        vendor="Filter by vendor name (case-insensitive match)",
        product="Filter by product name (case-insensitive match)",
        # type="Filter by vulnerability type (e.g., rce, xss) - NOT IMPLEMENTED",
        # has_exploit="Filter for CVEs with known exploits (True/False) - NOT IMPLEMENTED",
        in_kev="Filter for CVEs also in the KEV catalog (True/False)"
    )
    @app_commands.choices(severity=[
        app_commands.Choice(name="Critical", value="critical"),
        app_commands.Choice(name="High", value="high"),
        app_commands.Choice(name="Medium", value="medium"),
        app_commands.Choice(name="Low", value="low"),
    ])
    async def cve_latest_command(
        self, interaction: discord.Interaction,
        count: app_commands.Range[int, 1, 10] = 5,
        days: app_commands.Range[int, 1, 30] = 7,
        severity: Optional[SeverityLevelChoices] = None, # Re-added severity
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        # type: Optional[str] = None, # Not implemented yet
        # has_exploit: Optional[bool] = None, # Not implemented yet
        in_kev: Optional[bool] = None
    ):
        """Displays the most recent CVEs with optional filters."""
        # Check necessary clients
        if not self.nvd_client:
            await interaction.response.send_message("❌ NVD client is not available. Cannot fetch CVE data.", ephemeral=True)
            return
        # KEV client needed if in_kev filter is used
        kev_client_needed = in_kev is not None
        if kev_client_needed and not self.bot.cisa_kev_client:
             await interaction.response.send_message("❌ KEV client is not available for the 'in_kev' filter.", ephemeral=True)
             return

        await interaction.response.defer(ephemeral=True)

        try:
            # Fetch recent CVEs from NVD (or potentially another source in future)
            # NVDClient needs a method like get_recent_cves - assuming it exists for now
            # Placeholder: Assume nvd_client.get_recent_cves returns a list of CVE dicts like get_cve_details
            logger.info(f"Fetching recent CVEs for /cve latest (days={days})...")
            recent_cves = await self.nvd_client.get_recent_cves(days=days)
            if recent_cves is None: # Check for None explicitly
                 await interaction.followup.send("❌ Failed to fetch recent CVE data from NVD.", ephemeral=True)
                 return
            if not recent_cves:
                 await interaction.followup.send(f"⚪ No CVEs found published in the last {days} days.", ephemeral=True)
                 return
            
            logger.info(f"Fetched {len(recent_cves)} CVEs. Applying filters...")

            # --- Apply Filters ---
            filtered_cves = recent_cves

            # 1. Severity Filter (requires CVSS score in data)
            if severity:
                min_score = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1}.get(severity, 0)
                filtered_cves = [cve for cve in filtered_cves if cve.get('cvss', 0) >= min_score]

            # 2. Vendor Filter (requires vendor/product info - NVD API provides CPEs)
            # This is a simplification - real CPE matching is complex
            if vendor:
                 # Placeholder logic: Check if vendor name appears in description or CPEs if available
                 # filtered_cves = [cve for cve in filtered_cves if vendor.lower() in cve.get('description', '').lower()] 
                 logger.warning("Vendor filtering for /cve latest is basic, checks description only currently.")
                 filtered_cves = [cve for cve in filtered_cves if vendor.lower() in cve.get('description', '').lower()]
            
            # 3. Product Filter (similar complexity to vendor)
            if product:
                 # Placeholder logic:
                 logger.warning("Product filtering for /cve latest is basic, checks description only currently.")
                 filtered_cves = [cve for cve in filtered_cves if product.lower() in cve.get('description', '').lower()]
            
            # 4. In KEV Filter
            if in_kev is not None and self.bot.cisa_kev_client:
                 kev_catalog_cves = {kev.get('cveID') for kev in (await self.bot.cisa_kev_client.get_full_kev_catalog() or [])}
                 if in_kev:
                      filtered_cves = [cve for cve in filtered_cves if cve.get('id') in kev_catalog_cves]
                 else:
                      filtered_cves = [cve for cve in filtered_cves if cve.get('id') not in kev_catalog_cves]
            
            # --- Sorting & Limiting --- 
            # Sort by published date (most recent first) - assuming 'published' field exists and is sortable
            try:
                 # Ensure the key function handles potential None or invalid dates gracefully
                 def get_sort_key(cve_entry):
                     pub_date_str = cve_entry.get('published', '1970-01-01T00:00:00.000')
                     try:
                         # Attempt to parse, default to epoch on failure
                         return datetime.datetime.fromisoformat(pub_date_str.replace('Z', '+00:00'))
                     except (ValueError, TypeError):
                         return datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
                 
                 filtered_cves.sort(key=get_sort_key, reverse=True)
                 logger.debug("Sorted CVEs by published date.")
            except Exception as sort_e:
                 # Log the error but continue with unsorted list
                 logger.warning(f"Could not sort CVEs by published date: {sort_e}")
                 # No need for pass, just logging the warning is enough

            results_to_show = filtered_cves[:count]

            # --- Create Embed --- 
            if not results_to_show:
                await interaction.followup.send(f"⚪ No CVEs found matching your criteria in the last {days} days.", ephemeral=True)
                return
            
            embed_title = f"Recent CVEs (Last {days} days)"
            # Add filter indicators to title?
            filter_details = []
            if severity: filter_details.append(f"severity>={severity}")
            if vendor: filter_details.append(f"vendor={vendor}")
            if product: filter_details.append(f"product={product}")
            if in_kev is not None: filter_details.append(f"in_kev={in_kev}")
            if filter_details:
                 embed_title += f" | Filters: {', '.join(filter_details)}"

            embed = discord.Embed(
                title=embed_title,
                color=discord.Color.blue() # Different color for CVE latest
            )

            description_lines = []
            for i, cve in enumerate(results_to_show, 1):
                cve_id = cve.get('id', 'N/A')
                title = cve.get('description', 'No description')[:80] # Shorter description for list
                cvss_score = cve.get('cvss', 'N/A')
                published = cve.get('published', 'N/A')
                nvd_link = cve.get('link', '#')

                # Ensure all parts are strings before joining
                id_part = f"**{i}. [{cve_id}]({nvd_link})** - Score: {cvss_score}"
                title_part = f"   *{title}...*"
                published_part = f"   Published: {published}"
                line = f"{id_part}\n{title_part}\n{published_part}"
                description_lines.append(line)

                if i >= 5 and len(results_to_show) > 5:
                     description_lines.append(f"\n*... and {len(results_to_show) - 5} more*")
                     break
            embed.description = "\n\n".join(description_lines) # Add extra newline for spacing
            embed.set_footer(text=f"Found {len(filtered_cves)} CVEs matching criteria. Showing top {len(results_to_show)}.")
            embed.timestamp = discord.utils.utcnow()

            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error handling /cve latest command: {e}", exc_info=True)
            await interaction.followup.send("❌ An unexpected error occurred while fetching latest CVEs.", ephemeral=True)

    # --- NEW /cve channel Group (PRD Section 3.1.2) ---
    channel_group = app_commands.Group(name="channel", description="Configure the channel for CVE monitoring.", parent=cve_group, guild_only=True)

    @channel_group.command(name="enable", description="Enable CVE monitoring alerts in the specified channel.")
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.describe(channel="The channel where CVE alerts should be sent.")
    async def channel_enable_command(self, interaction: discord.Interaction, channel: discord.TextChannel):
        if not self.db:
            await interaction.response.send_message("❌ Database connection is not available.", ephemeral=True)
            return
        if interaction.guild_id is None:
            await interaction.response.send_message("❌ Cannot determine server ID.", ephemeral=True)
            return
        
        try:
            # Get current config to preserve other settings like threshold/verbose
            config = self.db.get_cve_channel_config(interaction.guild_id)
            verbose = config.get('verbose_mode', False) if config else False
            threshold = config.get('severity_threshold', 'all') if config else 'all'
            
            self.db.set_cve_channel_config(interaction.guild_id, channel.id, enabled=True, verbose_mode=verbose, severity_threshold=threshold)
            await interaction.response.send_message(f"✅ CVE monitoring enabled. Alerts will be sent to {channel.mention}.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error enabling CVE channel for guild {interaction.guild_id}: {e}", exc_info=True)
            await interaction.response.send_message("❌ An error occurred while enabling CVE monitoring.", ephemeral=True)

    @channel_group.command(name="disable", description="Disable CVE monitoring alerts for this server.")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def channel_disable_command(self, interaction: discord.Interaction):
        if not self.db:
            await interaction.response.send_message("❌ Database connection is not available.", ephemeral=True)
            return
        if interaction.guild_id is None:
            await interaction.response.send_message("❌ Cannot determine server ID.", ephemeral=True)
            return
        
        try:
            self.db.disable_cve_channel_config(interaction.guild_id)
            await interaction.response.send_message("❌ CVE monitoring disabled for this server.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error disabling CVE channel for guild {interaction.guild_id}: {e}", exc_info=True)
            await interaction.response.send_message("❌ An error occurred while disabling CVE monitoring.", ephemeral=True)

    @channel_group.command(name="set", description="Set/update the channel for CVE alerts (implicitly enables).")
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.describe(channel="The channel where CVE alerts should be sent.")
    async def channel_set_command(self, interaction: discord.Interaction, channel: discord.TextChannel):
        # This is functionally the same as enable, just different feedback perhaps?
        # Let's just reuse the enable logic for simplicity.
        await self.channel_enable_command(interaction, channel)
        # Or provide slightly different feedback:
        # await interaction.response.send_message(f"✅ CVE monitoring channel set to {channel.mention}. Monitoring is enabled.", ephemeral=True) 

    @channel_group.command(name="all", description="List channels configured for CVE alerts (currently only one per server).")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def channel_all_command(self, interaction: discord.Interaction):
        # Note: Current implementation only supports one channel per guild.
        # The PRD description for this command might anticipate future multi-channel support.
        if not self.db:
            await interaction.response.send_message("❌ Database connection is not available.", ephemeral=True)
            return
        if interaction.guild_id is None:
            await interaction.response.send_message("❌ Cannot determine server ID.", ephemeral=True)
            return

        config = self.db.get_cve_channel_config(interaction.guild_id)
        if config and config.get('enabled'):
            channel_id = config.get('channel_id')
            channel = self.bot.get_channel(channel_id) if channel_id else None
            channel_mention = channel.mention if isinstance(channel, discord.TextChannel) else f"ID: {channel_id} (Not Found?)"
            await interaction.response.send_message(f"ℹ️ CVE monitoring is **enabled** in: {channel_mention}", ephemeral=True)
        else:
            await interaction.response.send_message("ℹ️ CVE monitoring is currently **disabled** for this server.", ephemeral=True)

    # --- NEW /cve verbose Group (PRD Section 3.1.4) ---
    verbose_group = app_commands.Group(name="verbose", description="Configure verbosity of CVE alerts.", parent=cve_group, guild_only=True)

    @verbose_group.command(name="enable", description="Enable detailed (verbose) CVE alerts.")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def verbose_enable_command(self, interaction: discord.Interaction):
        if not self.db:
            await interaction.response.send_message("❌ Database connection is not available.", ephemeral=True)
            return
        if interaction.guild_id is None:
            await interaction.response.send_message("❌ Cannot determine server ID.", ephemeral=True)
            return
        
        try:
            config = self.db.get_cve_channel_config(interaction.guild_id)
            if not config or not config.get('enabled'):
                 await interaction.response.send_message("ℹ️ Please enable CVE monitoring first using `/cve channel enable` before setting verbosity.", ephemeral=True)
                 return

            channel_id = config.get('channel_id', 0)
            threshold = config.get('severity_threshold', 'all')
            
            self.db.set_cve_channel_config(interaction.guild_id, channel_id, enabled=True, verbose_mode=True, severity_threshold=threshold)
            await interaction.response.send_message("✅ Verbose CVE alerts **enabled**.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error enabling verbose CVE alerts for guild {interaction.guild_id}: {e}", exc_info=True)
            await interaction.response.send_message("❌ An error occurred while enabling verbose alerts.", ephemeral=True)

    @verbose_group.command(name="disable", description="Disable detailed (verbose) CVE alerts, use standard format.")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def verbose_disable_command(self, interaction: discord.Interaction):
        if not self.db:
            await interaction.response.send_message("❌ Database connection is not available.", ephemeral=True)
            return
        if interaction.guild_id is None:
            await interaction.response.send_message("❌ Cannot determine server ID.", ephemeral=True)
            return
        
        try:
            config = self.db.get_cve_channel_config(interaction.guild_id)
            # If config doesn't exist or not enabled, disabling verbose doesn't really do anything
            # but we can still set the flag in the DB for consistency if they enable later.
            channel_id = config.get('channel_id', 0) if config else 0
            enabled = config.get('enabled', False) if config else False
            threshold = config.get('severity_threshold', 'all') if config else 'all'

            self.db.set_cve_channel_config(interaction.guild_id, channel_id, enabled=enabled, verbose_mode=False, severity_threshold=threshold)
            await interaction.response.send_message("✅ Verbose CVE alerts **disabled**. Standard format will be used.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error disabling verbose CVE alerts for guild {interaction.guild_id}: {e}", exc_info=True)
            await interaction.response.send_message("❌ An error occurred while disabling verbose alerts.", ephemeral=True)

    # --- NEW /cve threshold Group (PRD Section 3.1.5) ---
    threshold_group = app_commands.Group(name="threshold", description="Configure minimum severity for CVE alerts.", parent=cve_group, guild_only=True)

    @threshold_group.command(name="set", description="Set the minimum severity level for CVE alerts.")
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.describe(level="The minimum severity level (critical, high, medium, low, all)")
    @app_commands.choices(level=[
        app_commands.Choice(name="Critical", value="critical"),
        app_commands.Choice(name="High", value="high"),
        app_commands.Choice(name="Medium", value="medium"),
        app_commands.Choice(name="Low", value="low"),
        app_commands.Choice(name="All (Default)", value="all"),
    ])
    async def threshold_set_command(self, interaction: discord.Interaction, level: SeverityLevelChoices):
        if not self.db:
            await interaction.response.send_message("❌ Database connection is not available.", ephemeral=True)
            return
        if interaction.guild_id is None:
            await interaction.response.send_message("❌ Cannot determine server ID.", ephemeral=True)
            return
        
        try:
            self.db.set_cve_severity_threshold(interaction.guild_id, level)
            await interaction.response.send_message(f"✅ CVE alert severity threshold set to **{level}**.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error setting CVE threshold for guild {interaction.guild_id}: {e}", exc_info=True)
            await interaction.response.send_message("❌ An error occurred while setting the severity threshold.", ephemeral=True)

    @threshold_group.command(name="view", description="View the current minimum severity level for CVE alerts.")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def threshold_view_command(self, interaction: discord.Interaction):
        if not self.db:
            await interaction.response.send_message("❌ Database connection is not available.", ephemeral=True)
            return
        if interaction.guild_id is None:
            await interaction.response.send_message("❌ Cannot determine server ID.", ephemeral=True)
            return

        config = self.db.get_cve_channel_config(interaction.guild_id)
        current_threshold = config.get('severity_threshold', 'all') if config else 'all'
        await interaction.response.send_message(f"ℹ️ Current CVE alert severity threshold is **{current_threshold}**.", ephemeral=True)

    @threshold_group.command(name="reset", description="Reset the CVE alert severity threshold to default ('all').")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def threshold_reset_command(self, interaction: discord.Interaction):
        if not self.db:
            await interaction.response.send_message("❌ Database connection is not available.", ephemeral=True)
            return
        if interaction.guild_id is None:
            await interaction.response.send_message("❌ Cannot determine server ID.", ephemeral=True)
            return

        try:
            self.db.set_cve_severity_threshold(interaction.guild_id, 'all')
            await interaction.response.send_message(f"✅ CVE alert severity threshold reset to **all**.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error resetting CVE threshold for guild {interaction.guild_id}: {e}", exc_info=True)
            await interaction.response.send_message("❌ An error occurred while resetting the severity threshold.", ephemeral=True)

    # --- Error Handler for Cog ---
    async def cog_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        if isinstance(error, app_commands.MissingPermissions):
            await interaction.response.send_message("🚫 You need the 'Manage Server' permission to use this command.", ephemeral=True)
        # Add other specific error handling if needed
        else:
            # Log the error if it wasn't handled
            logger.error(f"Unhandled error in CVELookupCog command '{interaction.command.qualified_name if interaction.command else 'unknown'}': {error}", exc_info=error)
            # Inform the user generically
            if not interaction.response.is_done():
                await interaction.response.send_message("❌ An unexpected error occurred processing this command.", ephemeral=True)
            else:
                 # May need followup if response already sent (e.g., deferred)
                 try:
                      await interaction.followup.send("❌ An unexpected error occurred processing this command.", ephemeral=True)
                 except discord.HTTPException:
                      logger.error(f"Failed to send followup error message for command {interaction.command.qualified_name if interaction.command else 'unknown'}")


async def setup(bot: 'SecurityBot'):
    """Sets up the CVE Lookup Cog."""
    # Keep NVD client check, but also check for DB
    if not bot.nvd_client:
         logger.warning("NVDClient not initialized. CVE Lookup Cog features requiring NVD will be limited.")
    if not bot.db:
         logger.error("KEVConfigDB (Database) not initialized. CVE Lookup Cog cannot be loaded.")
         return # Don't load cog if DB isn't ready

    await bot.add_cog(CVELookupCog(bot))
    logger.info("CVE Lookup Cog loaded.") 