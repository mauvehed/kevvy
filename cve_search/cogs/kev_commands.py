import discord
from discord import app_commands
from discord.ext import commands
import logging

from ..db_utils import KEVConfigDB
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..bot import SecurityBot

logger = logging.getLogger(__name__)

class KEVCog(commands.Cog):
    """Cog containing slash commands for CISA KEV configuration."""

    kev_group = app_commands.Group(name="kev", description="Manage CISA KEV monitoring for this server.", guild_only=True)

    def __init__(self, bot: 'SecurityBot'):
        self.bot = bot
        self.db: KEVConfigDB | None = self.bot.db

    @kev_group.command(name="enable", description="Enable KEV alerts in the specified channel.")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def kev_enable_command(self, interaction: discord.Interaction, channel: discord.TextChannel):
        """Enable CISA KEV monitoring alerts in the specified channel for this server."""
        if not self.db:
            await interaction.response.send_message("Database is not available. Cannot enable KEV monitoring.", ephemeral=True)
            return
        if not isinstance(interaction.user, discord.Member) or not interaction.user.guild_permissions.manage_guild:
             await interaction.response.send_message("You need the 'Manage Server' permission to use this command.", ephemeral=True)
             return

        try:
            if interaction.guild_id is None:
                 await interaction.response.send_message("Could not determine server ID.", ephemeral=True)
                 return
            self.db.set_kev_config(interaction.guild_id, channel.id)
            await interaction.response.send_message(f"✅ CISA KEV monitoring enabled for this server. Alerts will be sent to {channel.mention}.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error enabling KEV for guild {interaction.guild_id}: {e}", exc_info=True)
            if not interaction.response.is_done():
                 await interaction.response.send_message("An error occurred while enabling KEV monitoring.", ephemeral=True)

    @kev_group.command(name="disable", description="Disable KEV alerts for this server.")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def kev_disable_command(self, interaction: discord.Interaction):
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
            await interaction.response.send_message("❌ CISA KEV monitoring disabled for this server.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error disabling KEV for guild {interaction.guild_id}: {e}", exc_info=True)
            if not interaction.response.is_done():
                 await interaction.response.send_message("An error occurred while disabling KEV monitoring.", ephemeral=True)

    @kev_group.command(name="status", description="Check KEV alert status for this server.")
    async def kev_status_command(self, interaction: discord.Interaction):
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

            await interaction.response.send_message(f"🟢 CISA KEV monitoring is **enabled** for this server.\nAlerts are sent to: {channel_mention}", ephemeral=True)
        else:
            await interaction.response.send_message("⚪ CISA KEV monitoring is **disabled** for this server.", ephemeral=True)

    async def cog_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        if isinstance(error, app_commands.MissingPermissions):
            await interaction.response.send_message("You need the 'Manage Server' permission to use this command.", ephemeral=True)
        else:
            logger.error(f"Unhandled error in KEVCog command: {error}", exc_info=True)
            if not interaction.response.is_done():
                 await interaction.response.send_message("An unexpected error occurred.", ephemeral=True)

async def setup(bot: 'SecurityBot'):
    await bot.add_cog(KEVCog(bot))
    logger.info("KEVCog loaded.")