import discord
from discord import app_commands
from discord.ext import commands
import logging
import datetime
from typing import TYPE_CHECKING, Optional, Literal

from ..db_utils import KEVConfigDB
from ..cisa_kev_client import CisaKevClient
if TYPE_CHECKING:
    from ..bot import SecurityBot

logger = logging.getLogger(__name__)

# Define SeverityLevel for command choices
# SeverityLevelChoices = Literal["critical", "high", "medium", "low"] # No longer needed

class KEVCog(commands.Cog):
    """Cog containing slash commands for CISA KEV configuration and lookups."""

    # --- Root KEV Group --- 
    kev_group = app_commands.Group(name="kev", description="Manage CISA KEV monitoring and lookups.", guild_only=True)

    # --- Feed Sub-Group --- 
    feed_group = app_commands.Group(name="feed", parent=kev_group, description="Manage KEV feed monitoring for this server.")

    def __init__(self, bot: 'SecurityBot'):
        self.bot = bot
        self.db: Optional[KEVConfigDB] = self.bot.db
        self.kev_client: Optional[CisaKevClient] = self.bot.cisa_kev_client

    # --- /kev feed commands ---
    @feed_group.command(name="enable", description="Enable KEV feed alerts in the specified channel.")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def kev_feed_enable_command(self, interaction: discord.Interaction, channel: discord.TextChannel):
        """Enable CISA KEV monitoring alerts in the specified channel for this server."""
        if not self.db:
            await interaction.response.send_message("Database is not available. Cannot enable KEV monitoring.", ephemeral=True)
            return

        # Redundant check if decorator works, but safe to keep
        if not isinstance(interaction.user, discord.Member) or not interaction.user.guild_permissions.manage_guild:
             await interaction.response.send_message("You need the 'Manage Server' permission to use this command.", ephemeral=True)
             return

        try:
            if interaction.guild_id is None:
                 await interaction.response.send_message("Could not determine server ID.", ephemeral=True)
                 return
            self.db.set_kev_config(interaction.guild_id, channel.id)
            await interaction.response.send_message(f"✅ KEV feed monitoring enabled. Alerts will be sent to {channel.mention}.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error enabling KEV feed for guild {interaction.guild_id}: {e}", exc_info=True)
            if not interaction.response.is_done():
                 await interaction.response.send_message("An error occurred while enabling KEV feed monitoring.", ephemeral=True)

    @feed_group.command(name="disable", description="Disable KEV feed alerts for this server.")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def kev_feed_disable_command(self, interaction: discord.Interaction):
        """Disable CISA KEV monitoring alerts for this server."""
        if not self.db:
            await interaction.response.send_message("Database is not available. Cannot disable KEV monitoring.", ephemeral=True)
            return

        if not isinstance(interaction.user, discord.Member) or not interaction.user.guild_permissions.manage_guild:
             await interaction.response.send_message("You need the 'Manage Server' permission to use this command.", ephemeral=True)
             return

        try:
            if interaction.guild_id is None:
                 await interaction.response.send_message("Could not determine server ID.", ephemeral=True)
                 return
            self.db.disable_kev_config(interaction.guild_id)
            await interaction.response.send_message("❌ KEV feed monitoring disabled.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error disabling KEV feed for guild {interaction.guild_id}: {e}", exc_info=True)
            if not interaction.response.is_done():
                 await interaction.response.send_message("An error occurred while disabling KEV feed monitoring.", ephemeral=True)

    @feed_group.command(name="status", description="Check KEV feed alert status for this server.")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def kev_feed_status_command(self, interaction: discord.Interaction):
        """Check the CISA KEV monitoring status for this server."""
        if not self.db:
            await interaction.response.send_message("Database is not available. Cannot check KEV status.", ephemeral=True)
            return

        if interaction.guild_id is None:
             await interaction.response.send_message("Could not determine server ID.", ephemeral=True)
             return

        config = self.db.get_kev_config(interaction.guild_id)
        if config and config['enabled']:
            channel_mention = f"ID: {config['channel_id']} (Channel not found or inaccessible?)"
            channel = self.bot.get_channel(config['channel_id'])
            if isinstance(channel, discord.TextChannel):
                channel_mention = channel.mention

            last_check_ts = self.bot.timestamp_last_kev_check_success
            last_alert_ts = self.bot.timestamp_last_kev_alert_sent

            message = (
                f"🟢 KEV feed monitoring is **enabled**.\n"
                f"Alerts channel: {channel_mention}\n"
                f"Last successful check: {discord.utils.format_dt(last_check_ts, 'R') if last_check_ts else 'Never'}\n"
                f"Last alert sent: {discord.utils.format_dt(last_alert_ts, 'R') if last_alert_ts else 'Never'}"
            )
            await interaction.response.send_message(message, ephemeral=True)
        else:
            await interaction.response.send_message("⚪ KEV feed monitoring is **disabled**.", ephemeral=True)

    # --- /kev latest command --- 
    @kev_group.command(name="latest", description="Display the most recent KEV entries.")
    @app_commands.describe(
        count="Number of entries to show (default 5, max 10)",
        days="Look back N days (default 7, max 30)",
        vendor="Filter by vendor name (case-insensitive match)",
        product="Filter by product name (case-insensitive match)"
    )
    async def kev_latest_command(
        self, interaction: discord.Interaction,
        count: app_commands.Range[int, 1, 10] = 5,
        days: app_commands.Range[int, 1, 30] = 7,
        vendor: Optional[str] = None,
        product: Optional[str] = None
    ):
        """Displays the most recent KEV entries with optional filters."""
        if not self.kev_client:
            await interaction.response.send_message("❌ KEV client is not available. Cannot fetch latest entries.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)

        try:
            # Log the query attempt
            if self.db and interaction.guild_id:
                query_params = {
                    'count': count, 'days': days, 'vendor': vendor,
                    'product': product
                }
                self.db.log_kev_latest_query(interaction.guild_id, interaction.user.id, query_params)

            # Fetch all KEV data (client likely caches this)
            all_kevs = await self.kev_client.get_full_kev_catalog()
            if all_kevs is None: # Check for client failure first
                await interaction.followup.send("❌ Could not retrieve KEV data.", ephemeral=True)
                return
            # NEW CHECK: Check if the list is empty *after* confirming it's not None
            if not all_kevs:
                await interaction.followup.send(f"⚪ No KEV entries found matching your criteria in the last {days} days.", ephemeral=True)
                return

            # Filter by date
            cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
            # Ensure dateAdded is valid before parsing
            recent_kevs = []
            for k in all_kevs:
                date_added_str = k.get('dateAdded')
                if isinstance(date_added_str, str):
                    try:
                        parsed_date = datetime.datetime.fromisoformat(date_added_str.replace('Z', '+00:00'))
                        
                        # Ensure the parsed date is offset-aware (assume UTC if naive)
                        if parsed_date.tzinfo is None:
                            entry_date = parsed_date.replace(tzinfo=datetime.timezone.utc)
                            logger.debug(f"Made naive date {parsed_date} aware for KEV entry {k.get('cveID')}")
                        else:
                            # If already aware, ensure it's in UTC for consistent comparison
                            entry_date = parsed_date.astimezone(datetime.timezone.utc)
                            
                        # Now compare offset-aware dates
                        if entry_date >= cutoff_date:
                            recent_kevs.append(k)
                    except ValueError:
                         logger.warning(f"Could not parse dateAdded '{date_added_str}' for KEV entry {k.get('cveID')}")
                else:
                     logger.warning(f"Missing or invalid dateAdded for KEV entry {k.get('cveID')}")

            # Apply optional filters (excluding severity)
            if vendor:
                recent_kevs = [k for k in recent_kevs if vendor.lower() in k.get('vendorProject', '').lower()]
            if product:
                recent_kevs = [k for k in recent_kevs if product.lower() in k.get('product', '').lower()]
            
            # Sort by date added (most recent first)
            recent_kevs.sort(key=lambda k: k['dateAdded'], reverse=True)

            # Take the top N results
            results_to_show = recent_kevs[:count]

            # Final check if filters removed everything
            if not results_to_show:
                await interaction.followup.send(f"⚪ No KEV entries found matching your criteria in the last {days} days.", ephemeral=True)
                return

            # --- Create Embed --- 
            embed = discord.Embed(
                title=f"Latest KEV Entries (Last {days} days)",
                color=discord.Color.orange()
            )

            description_lines = []
            for i, kev in enumerate(results_to_show, 1):
                cve_id = kev.get('cveID', 'N/A')
                name = kev.get('vulnerabilityName', 'N/A')[:60] # Truncate long names
                added = kev.get('dateAdded', 'N/A')
                due = kev.get('dueDate', 'N/A')
                ransomware = kev.get('knownRansomwareCampaignUse', 'N/A')
                nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id != 'N/A' else ""
                description_lines.append(
                   f"**{i}. [{cve_id}]({nvd_link})**\n"
                   f"   *Name:* {name}\n"
                   f"   *Added:* {added} | *Due:* {due} | *Ransomware:* {ransomware}"
                )
                if i >= 5 and len(results_to_show) > 5: # Stop adding details after 5 if many results
                     description_lines.append(f"\n*... and {len(results_to_show) - 5} more*")
                     break

            embed.description = "\n".join(description_lines)
            embed.set_footer(text=f"Found {len(recent_kevs)} entries matching criteria. Showing top {len(results_to_show)}.")
            embed.timestamp = discord.utils.utcnow()

            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            logger.error(f"Error handling /kev latest command: {e}", exc_info=True)
            if interaction.response.is_done():
                await interaction.followup.send("❌ An unexpected error occurred while fetching latest KEV entries.", ephemeral=True)
            # else: interaction should have been deferred

    # --- Error Handler --- 
    async def cog_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        if isinstance(error, app_commands.MissingPermissions):
            await interaction.response.send_message("You need the 'Manage Server' permission to use this command.", ephemeral=True)
        # Handle Range errors for count/days
        elif isinstance(error, app_commands.errors.RangeError): 
             param_name = error.argument.name
             await interaction.response.send_message(f"Parameter `{param_name}` must be between {error.minimum} and {error.maximum}.", ephemeral=True)
        else:
            logger.error(f"Unhandled error in KEVCog command: {error}", exc_info=True)
            if not interaction.response.is_done():
                 await interaction.response.send_message("An unexpected error occurred.", ephemeral=True)

async def setup(bot: 'SecurityBot'):
    await bot.add_cog(KEVCog(bot))
    logger.info("KEVCog loaded.")