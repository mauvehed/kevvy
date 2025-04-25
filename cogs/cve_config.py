import discord
from discord.ext import commands
from discord import app_commands
import logging
from typing import Optional

# Use absolute import assuming 'kevvy' is the top-level package
from kevvy.bot import SecurityBot

logger = logging.getLogger(__name__)

@app_commands.guild_only() # Ensure commands only appear in guilds
@app_commands.default_permissions(manage_guild=True) # Require Manage Guild permission
class CveConfigCog(commands.Cog, name="CVE Configuration"):
    """Commands to configure CVE auto-response behavior."""

    # Use the specific bot type hint here
    def __init__(self, bot: SecurityBot):
        self.bot = bot
        # The check `hasattr(bot, 'db')` is still useful for runtime safety,
        # but the type hint now matches.
        if not hasattr(bot, 'db') or bot.db is None:
             logger.error("CVE Config Cog loaded but bot.db is not available!")
             # Consider raising commands.ExtensionFailed here to prevent loading
             # raise commands.ExtensionFailed("CVE Config Cog requires bot.db")


    # Define the command group
    cve_channel_group = app_commands.Group(
        name="cve-channel",
        description="Configure where the bot automatically responds to CVE IDs."
    )

    @cve_channel_group.command(name="set", description="Set a specific channel for CVE auto-responses.")
    @app_commands.describe(channel="The text channel where the bot should respond.")
    async def set_channel(self, interaction: discord.Interaction, channel: discord.TextChannel):
        """Sets the bot to respond to CVEs only in the specified channel."""
        if not interaction.guild_id:
            await interaction.response.send_message("This command can only be used in a server.", ephemeral=True)
            return

        # Type hint for self.bot is now SecurityBot, so self.bot.db is recognized
        if not self.bot.db:
            logger.error(f"Database unavailable during /cve-channel set command (Guild: {interaction.guild_id})")
            await interaction.response.send_message("Error: Database connection is not available.", ephemeral=True)
            return

        try:
            # Accessing self.bot.db is now type-safe
            self.bot.db.set_cve_response_mode(interaction.guild_id, str(channel.id))
            logger.info(f"User {interaction.user} set CVE response channel for guild {interaction.guild_id} to #{channel.name} ({channel.id})")
            await interaction.response.send_message(
                f"✅ Okay, I will now only respond to CVE IDs mentioned in {channel.mention}.",
                ephemeral=True,
                allowed_mentions=discord.AllowedMentions.none() # Prevent pinging the channel
            )
        except Exception as e:
            logger.error(f"Failed to set CVE response channel for guild {interaction.guild_id}: {e}", exc_info=True)
            await interaction.response.send_message("An error occurred while setting the CVE response channel.", ephemeral=True)


    @cve_channel_group.command(name="set-all", description="Allow CVE auto-responses in all channels.")
    async def set_all_channels(self, interaction: discord.Interaction):
        """Sets the bot to respond to CVEs in any channel it can access."""
        if not interaction.guild_id:
            await interaction.response.send_message("This command can only be used in a server.", ephemeral=True)
            return

        if not self.bot.db:
            logger.error(f"Database unavailable during /cve-channel set-all command (Guild: {interaction.guild_id})")
            await interaction.response.send_message("Error: Database connection is not available.", ephemeral=True)
            return

        try:
            self.bot.db.set_cve_response_mode(interaction.guild_id, "all")
            logger.info(f"User {interaction.user} set CVE response mode for guild {interaction.guild_id} to 'all'.")
            await interaction.response.send_message(
                f"✅ Okay, I will now respond to CVE IDs mentioned in *any channel* I have access to.",
                ephemeral=True
            )
        except Exception as e:
            logger.error(f"Failed to set CVE response mode to 'all' for guild {interaction.guild_id}: {e}", exc_info=True)
            await interaction.response.send_message("An error occurred while updating the setting.", ephemeral=True)


    @cve_channel_group.command(name="disable", description="Disable CVE auto-responses entirely in this server.")
    async def disable_responses(self, interaction: discord.Interaction):
        """Disables the bot's automatic responses to CVEs in messages."""
        if not interaction.guild_id:
            await interaction.response.send_message("This command can only be used in a server.", ephemeral=True)
            return

        if not self.bot.db:
            logger.error(f"Database unavailable during /cve-channel disable command (Guild: {interaction.guild_id})")
            await interaction.response.send_message("Error: Database connection is not available.", ephemeral=True)
            return

        try:
            self.bot.db.set_cve_response_mode(interaction.guild_id, None) # None deletes the setting
            logger.info(f"User {interaction.user} disabled CVE auto-response for guild {interaction.guild_id}." )
            await interaction.response.send_message(
                f"❌ Okay, I will no longer automatically respond to CVE IDs mentioned in messages in this server.",
                ephemeral=True
            )
        except Exception as e:
            logger.error(f"Failed to disable CVE auto-response for guild {interaction.guild_id}: {e}", exc_info=True)
            await interaction.response.send_message("An error occurred while disabling CVE auto-responses.", ephemeral=True)

    @cve_channel_group.command(name="status", description="Show the current CVE auto-response setting for this server.")
    async def show_status(self, interaction: discord.Interaction):
        """Displays the current configuration for CVE auto-responses."""
        if not interaction.guild_id or not interaction.guild: # Need guild for channel lookup
            await interaction.response.send_message("This command can only be used in a server.", ephemeral=True)
            return

        if not self.bot.db:
            logger.error(f"Database unavailable during /cve-channel status command (Guild: {interaction.guild_id})")
            await interaction.response.send_message("Error: Database connection is not available.", ephemeral=True)
            return

        try:
            mode = self.bot.db.get_cve_response_mode(interaction.guild_id)
            status_message = ""
            if mode is None:
                status_message = "❌ CVE auto-responses are currently **disabled** in this server."
            elif mode == "all":
                status_message = "✅ CVE auto-responses are currently **enabled in all channels** I can access."
            elif mode.isdigit():
                channel_id = int(mode)
                channel = interaction.guild.get_channel(channel_id)
                if channel:
                    status_message = f"✅ CVE auto-responses are currently **enabled only in {channel.mention}**."
                else:
                     # Channel might have been deleted or bot lost access
                     status_message = f"⚠️ CVE auto-responses are set to channel ID `{channel_id}`, but I can no longer see that channel. Responses are effectively disabled."
                     logger.warning(f"CVE response channel {channel_id} for guild {interaction.guild_id} not found.")
            else:
                # Should not happen with current logic
                status_message = f"❓ Unknown CVE response setting found ('{mode}'). Please reconfigure using `/cve-channel set`, `/cve-channel set-all`, or `/cve-channel disable`."
                logger.error(f"Found unexpected CVE response mode '{mode}' for guild {interaction.guild_id} in DB.")

            await interaction.response.send_message(status_message, ephemeral=True, allowed_mentions=discord.AllowedMentions.none())

        except Exception as e:
            logger.error(f"Failed to get CVE auto-response status for guild {interaction.guild_id}: {e}", exc_info=True)
            await interaction.response.send_message("An error occurred while retrieving the current status.", ephemeral=True)

# Use the specific bot type hint for the setup function as well
async def setup(bot: SecurityBot):
    """Adds the CVE Configuration cog to the bot."""
    # Add check for db availability before adding cog?
    if not hasattr(bot, 'db') or bot.db is None:
         logger.critical("Failed to load CveConfigCog: Bot database connection (bot.db) not found.")
         # Optionally raise an error to prevent loading if DB is essential
         # raise commands.ExtensionFailed("CveConfigCog requires bot.db to be initialized.")
         return # Or just log and don't load

    await bot.add_cog(CveConfigCog(bot))
    logger.info("Successfully added CveConfigCog.")

# Add error handling for commands within the cog if needed,
# although the global error handler in the bot might suffice.
# Example:
# @set_channel.error
# async def set_channel_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
#     logger.error(f"Error in /cve-channel set: {error}")
#     # Handle specific errors or provide generic message
#     await interaction.response.send_message("An error occurred.", ephemeral=True) 