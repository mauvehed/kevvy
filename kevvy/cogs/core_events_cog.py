import discord
from discord.ext import commands
from discord import app_commands
import logging
import asyncio
import re  # For CVE_REGEX logic
import datetime  # For cache timing

# Assuming SecurityBot is in kevvy/bot.py, one level up from kevvy/cogs/
# This relative import should work if the script is run as part of the kevvy package.
from ..bot import SecurityBot
from ..nvd_client import NVDRateLimitError  # For specific error handling

# If MAX_EMBEDS_PER_MESSAGE is a true constant, it can be defined here or imported
# For now, let's assume it might become a configurable bot attribute accessed via self.bot
# Or, if it's in bot.py at module level, we might need to rethink access or duplicate it.
# Let's try to access it via self.bot assuming it's set there.
# If not, we can define it in this cog or import from a config module later.

logger = logging.getLogger(__name__)


class CoreEventsCog(commands.Cog, name="CoreEvents"):
    """Handles core Discord events for the bot."""

    def __init__(self, bot: SecurityBot):
        self.bot = bot
        # Define RECENT_CVE_CACHE_SECONDS here if it's specific to this cog's on_message logic
        # Or ensure it's an attribute on self.bot that we can access.
        # For now, let's make it a cog attribute if it was a bot attribute primarily for on_message.
        self.RECENT_CVE_CACHE_SECONDS = (
            20  # Default, can be adjusted or made configurable
        )
        # The recently_processed_cves cache should ideally live on the bot instance if other parts might use it
        # or if its lifetime should match the bot's. For now, assuming it was self.recently_processed_cves on bot.

    @commands.Cog.listener()
    async def on_connect(self):
        """Called when the bot successfully connects to the Discord Gateway."""
        # Access logger via self.bot.logger if it's an attribute of the bot instance
        # For now, using the cog's own logger.
        logger.info(
            f"Successfully connected to Discord Gateway. Shard ID: {self.bot.shard_id}"
        )

    @commands.Cog.listener()
    async def on_disconnect(self):
        """Called when the bot loses connection to the Discord Gateway."""
        logger.warning(
            f"Disconnected from Discord Gateway unexpectedly. Shard ID: {self.bot.shard_id}. Will attempt to reconnect."
        )

    @commands.Cog.listener()
    async def on_resumed(self):
        """Called when the bot successfully resumes a session after a disconnect."""
        logger.info(
            f"Successfully resumed Discord Gateway session. Shard ID: {self.bot.shard_id}"
        )

    @commands.Cog.listener()
    async def on_guild_join(self, guild: discord.Guild):
        """Called when the bot joins a new guild."""
        logger.info(
            f"Joined guild: {guild.name} ({guild.id}). Owner: {guild.owner} ({guild.owner_id}). Members: {guild.member_count}"
        )
        # Optional: Send a welcome message logic would go here, accessing self.bot if needed

    @commands.Cog.listener()
    async def on_guild_remove(self, guild: discord.Guild):
        """Called when the bot is removed from a guild."""
        logger.info(f"Removed from guild: {guild.name} ({guild.id}).")
        # Optional: Clean up any guild-specific configurations from the database via self.bot.db

    @commands.Cog.listener()
    async def on_ready(self):
        """Called when the bot is fully ready and internal cache is built."""
        # Access attributes from the bot instance via self.bot
        if not hasattr(self.bot, "start_time") or self.bot.start_time is None:
            # Fallback if start_time wasn't set on bot instance before on_ready
            # This typically should be set in the bot's __init__ or early setup_hook
            logger.warning("Bot start_time not pre-set, setting it now in on_ready.")
            # self.bot.start_time = datetime.datetime.now(datetime.timezone.utc) # If you need to set it here

        logger.info(f"Logged in as {self.bot.user.name} ({self.bot.user.id})")
        logger.info(f"Command prefix: {self.bot.command_prefix}")
        logger.info(f"Successfully fetched {len(self.bot.guilds)} guilds.")
        logger.info("Bot is ready! Listening for CVEs...")

        # Activate Discord logging handler if prepared on the bot instance
        if self.bot.discord_log_handler:
            root_logger = logging.getLogger()  # Get the root logger
            handler_exists = any(
                h is self.bot.discord_log_handler for h in root_logger.handlers
            )
            if not handler_exists:
                await asyncio.sleep(5)  # Add 5-second delay
                root_logger.addHandler(self.bot.discord_log_handler)
                logger.info(
                    f"Discord logging handler activated for channel ID {self.bot.discord_log_handler.channel_id}."
                )
            else:
                logger.debug("Discord logging handler already active.")
        else:
            logger.warning(
                "Discord log handler was not prepared (self.bot.discord_log_handler is None), cannot activate."
            )

    @commands.Cog.listener()
    async def on_app_command_error(
        self, interaction: discord.Interaction, error: app_commands.AppCommandError
    ):
        """Global error handler for application (slash) commands, now in CoreEventsCog."""
        command_name = (
            interaction.command.name if interaction.command else "Unknown Command"
        )
        user = interaction.user
        guild = interaction.guild
        channel = interaction.channel

        guild_name = guild.name if guild else "DM"
        guild_id = guild.id if guild else "N/A"
        channel_name = getattr(channel, "name", "DM/Unknown Channel")
        channel_id = channel.id if channel else "N/A"

        log_message = (
            f"App Command Error in command '{command_name}' "
            f"(User: {user} ({user.id}), Guild: {guild_name} ({guild_id}), "
            f"Channel: {channel_name} ({channel_id})): {error}"
        )

        if isinstance(error, app_commands.CommandNotFound):
            logger.warning(f"CommandNotFound error suppressed: {log_message}")
            return
        elif isinstance(error, app_commands.CommandOnCooldown):
            logger.warning(log_message)
            await interaction.response.send_message(
                f"⏳ This command is on cooldown. Please try again in {error.retry_after:.2f} seconds.",
                ephemeral=True,
            )
        elif isinstance(error, app_commands.MissingPermissions):
            logger.error(log_message)
            await interaction.response.send_message(
                f"🚫 You do not have the required permissions to use this command: {', '.join(error.missing_permissions)}",
                ephemeral=True,
            )
        elif isinstance(error, app_commands.BotMissingPermissions):
            logger.error(log_message)
            try:
                await interaction.response.send_message(
                    f"🚫 I lack the necessary permissions to run this command: {', '.join(error.missing_permissions)}."
                    f" Please ensure I have these permissions in this channel/server.",
                    ephemeral=True,
                )
            except discord.Forbidden:
                logger.error(
                    f"Cannot even send error message about BotMissingPermissions in channel {channel_id} (Guild: {guild_id})"
                )
        elif isinstance(error, app_commands.CheckFailure):
            logger.warning(f"CheckFailure: {log_message}")
            await interaction.response.send_message(
                "❌ You do not meet the requirements to use this command.",
                ephemeral=True,
            )
        else:
            logger.error(f"Unhandled App Command Error: {log_message}", exc_info=error)
            try:
                if interaction.response.is_done():
                    await interaction.followup.send(
                        "❌ An unexpected error occurred while processing your command.",
                        ephemeral=True,
                    )
                else:
                    await interaction.response.send_message(
                        "❌ An unexpected error occurred while processing your command.",
                        ephemeral=True,
                    )
            except Exception as e:
                logger.error(
                    f"Failed to send generic error message to user after unhandled App Command Error: {e}"
                )

        error_type_name = type(error).__name__
        # Use StatsManager method
        await self.bot.stats_manager.record_app_command_error(error_type_name)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.author.bot:
            return
        if not message.guild:
            return

        # Access bot attributes via self.bot
        if not self.bot.cve_monitor or not self.bot.db:
            logger.debug(
                "CVE Monitor or DB not initialized on bot, skipping on_message processing."
            )
            return

        # Increment message processed using StatsManager
        await self.bot.stats_manager.increment_messages_processed()

        # Use CVE_REGEX from the cve_monitor instance
        potential_cves = re.findall(self.bot.cve_monitor.CVE_REGEX, message.content)
        if not potential_cves:
            return

        guild_id = message.guild.id
        channel_id = message.channel.id

        guild_config = self.bot.db.get_cve_guild_config(guild_id)
        if not guild_config or not guild_config.get("enabled"):
            logger.debug(
                f"Global CVE monitoring disabled for guild {guild_id}. Skipping message {message.id}."
            )
            return

        channel_config = self.bot.db.get_cve_channel_config(guild_id, channel_id)
        if not channel_config or not channel_config.get("enabled"):
            logger.debug(
                f"CVE monitoring disabled for channel {channel_id} in guild {guild_id}. Skipping message {message.id}."
            )
            return

        logger.info(
            f"Detected {len(potential_cves)} potential CVE(s) in message {message.id} in G:{guild_id}/C:{channel_id}"
        )

        unique_cves = sorted(
            list(set(potential_cves)), key=lambda x: potential_cves.index(x)
        )
        processed_count = 0
        now = datetime.datetime.now(datetime.timezone.utc)

        # Use RECENT_CVE_CACHE_SECONDS from self (cog instance) or self.bot if it were defined there
        cache_expiry_time = now - datetime.timedelta(
            seconds=self.RECENT_CVE_CACHE_SECONDS
        )

        # Ensure recently_processed_cves is an attribute of the bot for shared state
        if not hasattr(self.bot, "recently_processed_cves"):
            logger.warning(
                "Bot attribute 'recently_processed_cves' not found. Initializing for CoreEventsCog."
            )
            self.bot.recently_processed_cves = {}  # Initialize if it wasn't on the bot

        expired_keys = [
            key
            for key, ts in self.bot.recently_processed_cves.items()
            if ts < cache_expiry_time
        ]
        for key in expired_keys:
            try:
                del self.bot.recently_processed_cves[key]
                logger.debug(f"Removed expired CVE cache entry: {key}")
            except KeyError:
                pass

        # MAX_EMBEDS_PER_MESSAGE should be accessible, e.g., from bot config or defined constant
        # Assuming it's an attribute of self.bot for now, or a globally imported constant
        # If it was a module-level constant in bot.py, it needs to be imported or moved to a config file.
        # For this example, let's assume it's self.bot.MAX_EMBEDS_PER_MESSAGE
        # If not, this will need adjustment.
        # A better way would be to make MAX_EMBEDS_PER_MESSAGE a config value or bot attribute.
        # For now, let's define it locally in the cog if it wasn't a bot attribute.
        MAX_EMBEDS_PER_MESSAGE = getattr(
            self.bot, "MAX_EMBEDS_PER_MESSAGE", 5
        )  # Default to 5 if not on bot

        for cve_id_raw in unique_cves:
            if processed_count >= MAX_EMBEDS_PER_MESSAGE:
                logger.warning(
                    f"Reached max embed limit ({MAX_EMBEDS_PER_MESSAGE}) for message {message.id}. Remaining CVEs: {unique_cves[processed_count:]}"
                )
                try:
                    await message.channel.send(
                        f"ℹ️ Found {len(unique_cves) - processed_count} more CVEs, but only showing the first {MAX_EMBEDS_PER_MESSAGE}. Use `/cve lookup` for details.",
                        delete_after=30,
                    )
                except (discord.Forbidden, discord.HTTPException) as e:
                    logger.error(
                        f"Failed to send max embed notice for message {message.id}: {e}"
                    )
                break

            try:
                cve_id = cve_id_raw.upper().replace(" ", "-")
                cache_key = (channel_id, cve_id)
                last_processed_time = self.bot.recently_processed_cves.get(cache_key)
                if last_processed_time and last_processed_time > cache_expiry_time:
                    logger.debug(
                        f"Skipping recently processed CVE {cve_id} in channel {channel_id} (Cached at {last_processed_time})."
                    )
                    continue

                # Increment CVE lookups using StatsManager
                await self.bot.stats_manager.increment_cve_lookups()

                cve_data = await self.bot.cve_monitor.get_cve_data(cve_id)
                if not cve_data:
                    logger.warning(
                        f"No data found for {cve_id} mentioned in message {message.id}."
                    )
                    continue
                else:
                    # Increment NVD success using StatsManager
                    await self.bot.stats_manager.increment_nvd_fallback_success()

                min_severity_str = guild_config.get("severity_threshold", "all")
                passes_threshold, cve_severity_str = (
                    self.bot.cve_monitor.check_severity_threshold(
                        cve_data, min_severity_str
                    )
                )
                if not passes_threshold:
                    logger.info(
                        f"CVE {cve_id} (Severity: {cve_severity_str}) does not meet threshold '{min_severity_str}' for guild {guild_id}. Skipping alert."
                    )
                    continue

                is_verbose = self.bot.db.get_effective_verbosity(guild_id, channel_id)
                logger.debug(
                    f"Effective verbosity for G:{guild_id}/C:{channel_id} = {is_verbose}"
                )

                cve_embed = self.bot.cve_monitor.create_cve_embed(
                    cve_data, verbose=is_verbose
                )
                await message.channel.send(embed=cve_embed)
                processed_count += 1
                logger.info(
                    f"Sent alert for {cve_id} (Severity: {cve_severity_str}, Verbose: {is_verbose}) from message {message.id}."
                )

                self.bot.recently_processed_cves[cache_key] = now
                await asyncio.sleep(1.0)

                kev_status = None
                try:
                    kev_status = await self.bot.cve_monitor.check_kev(cve_id)
                except Exception as kev_err:
                    logger.error(
                        f"Error checking KEV status for {cve_id}: {kev_err}",
                        exc_info=True,
                    )
                    # Record KEV API error using StatsManager
                    await self.bot.stats_manager.record_api_error("kev")

                if kev_status:
                    kev_embed = self.bot.cve_monitor.create_kev_status_embed(
                        cve_id, kev_status, verbose=is_verbose
                    )
                    await message.channel.send(embed=kev_embed)
                    logger.info(
                        f"Sent KEV status for {cve_id} (Verbose: {is_verbose}) from message {message.id}."
                    )
                    await asyncio.sleep(1.0)

            except discord.Forbidden:
                logger.error(
                    f"Missing permissions to send message/embed in channel {channel_id} (Guild: {guild_id}) for CVE {cve_id}."
                )
                break
            except discord.HTTPException as e:
                logger.error(
                    f"HTTP error sending embed for {cve_id} in channel {channel_id} (Guild: {guild_id}): {e}"
                )
            except NVDRateLimitError as e:
                logger.error(f"NVD rate limit hit processing {cve_id}: {e}")
                # Record NVD rate limit using StatsManager
                await self.bot.stats_manager.record_nvd_rate_limit_hit()
                continue
            except Exception as e:
                logger.error(
                    f"Unexpected error processing CVE {cve_id} from message {message.id}: {e}",
                    exc_info=True,
                )
                # Record generic NVD API error using StatsManager
                await self.bot.stats_manager.record_api_error("nvd")


async def setup(bot: SecurityBot):
    """Standard setup function to add the cog to the bot."""
    await bot.add_cog(CoreEventsCog(bot))
    logger.info("CoreEventsCog has been loaded.")
