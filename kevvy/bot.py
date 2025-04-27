import discord
from discord.ext import commands, tasks
from discord import app_commands
import aiohttp
from aiohttp import ClientTimeout
from .cve_monitor import CVEMonitor
from .nvd_client import NVDClient, NVDRateLimitError
from .vulncheck_client import VulnCheckClient
from .cisa_kev_client import CisaKevClient
from .db_utils import KEVConfigDB
import logging
import os
import asyncio
from typing import Dict, Any, List, Optional
from collections import defaultdict
from .discord_log_handler import DiscordLogHandler
import datetime
import signal
import platform

MAX_EMBEDS_PER_MESSAGE = 5

logger = logging.getLogger(__name__)

class SecurityBot(commands.Bot):
    def __init__(self, nvd_api_key: str | None, vulncheck_api_token: str | None):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        prefix = os.getenv('DISCORD_COMMAND_PREFIX', '!')
        super().__init__(command_prefix=prefix, intents=intents, enable_debug_events=True)

        self.http_session: aiohttp.ClientSession | None = None
        self.cisa_kev_client: CisaKevClient | None = None
        self.db: KEVConfigDB | None = None
        self.nvd_client: NVDClient | None = None
        self.cve_monitor: CVEMonitor | None = None
        self.start_time: datetime.datetime = datetime.datetime.now(datetime.timezone.utc)
        self.loaded_cogs: List[str] = []
        self.failed_cogs: List[str] = []
        self.timestamp_last_kev_check_success: Optional[datetime.datetime] = None
        self.timestamp_last_kev_alert_sent: Optional[datetime.datetime] = None

        # --- Statistics Counters ---
        self.stats_lock = asyncio.Lock()
        # Basic counters (already existed)
        self.stats_cve_lookups = 0
        self.stats_kev_alerts_sent = 0
        self.stats_messages_processed = 0
        # New counters
        self.stats_vulncheck_success = 0
        self.stats_nvd_fallback_success = 0
        self.stats_api_errors_vulncheck = 0
        self.stats_api_errors_nvd = 0
        self.stats_api_errors_cisa = 0
        self.stats_rate_limits_nvd = 0 # Specific counter for NVD rate limits
        # App command errors: defaultdict(int) to count errors by type name
        self.stats_app_command_errors: Dict[str, int] = defaultdict(int)
        # --- End Statistics Counters ---

        # VulnCheck doesn't need session, can init here
        self.vulncheck_client = VulnCheckClient(api_key=vulncheck_api_token)

        # --- Kevvy Web Reporting Config ---
        self.kevvy_web_url = os.getenv('KEVVY_WEB_URL')
        self.kevvy_web_api_key = os.getenv('KEVVY_WEB_API_KEY')
        if self.kevvy_web_url and not self.kevvy_web_api_key:
             logger.warning("KEVVY_WEB_URL is set, but KEVVY_WEB_API_KEY is missing. Web reporting disabled.")
             self.kevvy_web_url = None # Disable if key is missing
        elif self.kevvy_web_url:
             logger.info(f"Kevvy Web reporting enabled for URL: {self.kevvy_web_url}")
        else:
             logger.info("Kevvy Web reporting is disabled (KEVVY_WEB_URL not set).")
        # --- End Kevvy Web Reporting Config ---

    async def _handle_signal(self, sig: signal.Signals):
        """Handles received OS signals for graceful shutdown."""
        logger.warning(f"Received signal {sig.name}. Initiating graceful shutdown...")
        # Use create_task to ensure close() runs even if the handler is interrupted
        asyncio.create_task(self.close(), name=f'Signal-{sig.name}-Shutdown')

    def _setup_signal_handlers(self):
        """Sets up OS signal handlers for graceful shutdown."""
        try:
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(
                    sig, lambda s=sig: asyncio.create_task(self._handle_signal(s))
                )
            logger.info("Registered signal handlers for SIGINT and SIGTERM.")
        except NotImplementedError:
            logger.warning("Signal handlers are not supported on this platform (likely Windows). Graceful shutdown via signals is disabled.")
        except Exception as e:
            logger.error(f"Failed to set up signal handlers: {e}", exc_info=True)

    async def setup_hook(self):
        self.http_session = aiohttp.ClientSession()
        logger.info("Created aiohttp.ClientSession.")

        # Initialize NVD client now that we have a session
        self.nvd_client = NVDClient(session=self.http_session, api_key=os.getenv('NVD_API_KEY'))
        logger.info("Initialized NVDClient.")

        # Initialize Database utility
        try:
            self.db = KEVConfigDB()
            logger.info("Initialized KEV Configuration Database.")
        except Exception as e:
             logger.error(f"Failed to initialize KEV Configuration Database: {e}", exc_info=True)
             self.db = None

        # Initialize CISA client
        if self.db and self.http_session:
             self.cisa_kev_client = CisaKevClient(session=self.http_session, db=self.db)
             logger.info("Initialized CisaKevClient with DB persistence.")
        else:
            logger.error("Could not initialize CisaKevClient due to missing DB or HTTP session.")
            self.cisa_kev_client = None

        # Initialize CVEMonitor with NVDClient and potentially CisaKevClient
        if self.nvd_client:
            self.cve_monitor = CVEMonitor(self.nvd_client, kev_client=self.cisa_kev_client)
            logger.info(f"Initialized CVEMonitor (KEV support: {'enabled' if self.cisa_kev_client else 'disabled'}).")
        else:
            logger.error("Could not initialize CVEMonitor because NVDClient failed to initialize.")

        # Load Cogs
        initial_extensions = [
            'kevvy.cogs.kev_commands',
            'kevvy.cogs.cve_lookup'
            # Add other cogs here if needed
        ]
        self.loaded_cogs = [] # Reset on setup
        self.failed_cogs = [] # Reset on setup
        for extension in initial_extensions:
            try:
                await self.load_extension(extension)
                logger.info(f"Successfully loaded extension: {extension}")
                self.loaded_cogs.append(extension)
            except commands.ExtensionError as e:
                logger.error(f"Failed to load extension {extension}: {e}", exc_info=True)
                self.failed_cogs.append(f"{extension} (Load Error)")
            except Exception as e:
                 logger.error(f"An unexpected error occurred loading extension {extension}: {e}", exc_info=True)
                 self.failed_cogs.append(f"{extension} (Exception)")

        # Setup signal handlers before syncing commands or starting tasks
        self._setup_signal_handlers()

        # Sync the commands
        try:
            await self.tree.sync()
            logging.info("Synced application commands.")
        except Exception as e:
            logger.error(f"Failed to sync application commands: {e}", exc_info=True)
            # Consider adding this failure to failed_cogs or a separate status

        # Start background tasks
        self.check_cisa_kev_feed.start()
        if self.kevvy_web_url:
             self.report_status_task.start()

    async def close(self):
        logger.warning("Bot shutdown initiated...")
        if self.is_closed():
            logger.info("Bot close() called, but already closing/closed.")
            return

        logging.info("Closing bot resources...")
        if self.check_cisa_kev_feed.is_running():
            self.check_cisa_kev_feed.cancel()
            logging.info("Cancelled CISA KEV monitoring task.")

        if self.report_status_task.is_running():
            self.report_status_task.cancel()
            logging.info("Cancelled Kevvy Web reporting task.")

        if self.http_session:
            await self.http_session.close()
            logging.info("Closed aiohttp session.")

        if self.db:
            self.db.close()
            logging.info("Closed KEV Config Database connection.")

        await super().close()
        logger.warning("Bot shutdown complete.")

    @tasks.loop(hours=1)
    async def check_cisa_kev_feed(self):
        """Periodically checks the CISA KEV feed for new entries and sends to configured guilds."""
        if not self.cisa_kev_client or not self.db:
            logger.debug("CISA KEV client or DB not initialized, skipping check.")
            return

        task_start_time = datetime.datetime.now(datetime.timezone.utc)
        success = False
        try:
            logger.info("Running periodic CISA KEV check...")
            # Wrap client call to potentially track API errors
            new_entries = []
            try:
                new_entries = await self.cisa_kev_client.get_new_kev_entries()
                success = True # Mark success if call completes without CISA client exception
            except Exception as client_error:
                 logger.error(f"CISA KEV client error during fetch: {client_error}", exc_info=True)
                 async with self.stats_lock:
                     self.stats_api_errors_cisa += 1
                 # Allow loop to continue to update timestamp

            if not new_entries:
                logger.info("Completed periodic CISA KEV check. No new KEV entries found.")
                # No return needed here, let it reach the success update
            else:
                logger.info(f"Found {len(new_entries)} new KEV entries. Checking configured guilds...")
                if enabled_configs := self.db.get_enabled_kev_configs():
                    alerts_sent_this_run = 0
                    for config in enabled_configs:
                        guild_id = config['guild_id']
                        channel_id = config['channel_id']

                        guild = self.get_guild(guild_id)
                        if not guild:
                            logger.warning(f"Could not find guild {guild_id} from KEV config, skipping.")
                            continue

                        target_channel = self.get_channel(channel_id)
                        if not target_channel:
                            logger.error(f"Could not find CISA KEV target channel with ID: {channel_id} in guild {guild.name} ({guild_id})")
                            continue
                        if not isinstance(target_channel, discord.TextChannel):
                             logger.error(f"CISA KEV target channel {channel_id} in guild {guild.name} ({guild_id}) is not a TextChannel.")
                             continue

                        logger.info(f"Sending {len(new_entries)} new KEV entries to channel #{target_channel.name} in guild {guild.name}")
                        for entry in new_entries:
                            embed = self._create_kev_embed(entry)
                            try:
                                await target_channel.send(embed=embed)
                                alerts_sent_this_run += 1
                                self.timestamp_last_kev_alert_sent = datetime.datetime.now(datetime.timezone.utc) # Update timestamp
                                await asyncio.sleep(0.75)
                            except discord.Forbidden:
                                 logger.error(f"Missing permissions to send message in CISA KEV channel {channel_id} (Guild: {guild_id})")
                                 break
                            except discord.HTTPException as e:
                                 logger.error(f"Failed to send CISA KEV embed for {entry.get('cveID', 'Unknown CVE')} to channel {channel_id} (Guild: {guild_id}): {e}")
                            except Exception as e:
                                 logger.error(f"Unexpected error sending KEV embed for {entry.get('cveID', 'Unknown CVE')} (Guild: {guild_id}): {e}", exc_info=True)
                        await asyncio.sleep(2)
                    # Update global counter after processing all guilds for this run
                    if alerts_sent_this_run > 0:
                        async with self.stats_lock:
                            self.stats_kev_alerts_sent += alerts_sent_this_run

                else:
                    logger.info("No guilds have KEV monitoring enabled.")
            # Update success timestamp if the fetch didn't raise an exception
            if success:
                 self.timestamp_last_kev_check_success = task_start_time

        except Exception as e:
            # Catch errors in the loop logic itself (outside CISA client call)
            logger.error(f"Error during CISA KEV check loop logic: {e}", exc_info=True)
            # Optionally increment a different counter for loop errors vs API errors

    @check_cisa_kev_feed.before_loop
    async def before_kev_check(self):
        """Ensures the bot is ready before the loop starts."""
        await self.wait_until_ready()
        logger.info("Bot is ready, starting CISA KEV monitoring loop.")

    @tasks.loop(minutes=5)
    async def report_status_task(self):
        """Periodically sends status and detailed diagnostics to the kevvy-web server."""
        if not self.kevvy_web_url or not self.kevvy_web_api_key or not self.http_session:
            logger.debug("Web reporting skipped: URL, API key, or HTTP session not available.")
            return

        logger.debug("Preparing status & diagnostics report for kevvy-web...")
        now = datetime.datetime.now(datetime.timezone.utc)

        # --- Gather Basic Status (already existed) ---
        uptime_delta = now - self.start_time
        status_payload = {
            "timestamp": now.isoformat(),
            "bot_id": self.user.id if self.user else None,
            "bot_name": self.user.name if self.user else "Unknown",
            "guild_count": len(self.guilds),
            "latency_ms": round(self.latency * 1000, 2) if self.latency else None,
            "uptime_seconds": int(uptime_delta.total_seconds()),
            "shard_id": self.shard_id if self.shard_id is not None else 0,
            "shard_count": self.shard_count if self.shard_count is not None else 1,
            "is_ready": self.is_ready(),
            "is_closed": self.is_closed(),
        }

        # --- Gather Detailed Stats & Diagnostics ---
        # Make copies under lock to avoid holding lock during DB query/sending
        async with self.stats_lock:
            stats_payload = {
                "timestamp": now.isoformat(),
                "cve_lookups_since_last": self.stats_cve_lookups,
                "kev_alerts_sent_since_last": self.stats_kev_alerts_sent,
                "messages_processed_since_last": self.stats_messages_processed,
                "vulncheck_success_since_last": self.stats_vulncheck_success,
                "nvd_fallback_success_since_last": self.stats_nvd_fallback_success,
                "api_errors_vulncheck_since_last": self.stats_api_errors_vulncheck,
                "api_errors_nvd_since_last": self.stats_api_errors_nvd,
                "api_errors_cisa_since_last": self.stats_api_errors_cisa,
                "rate_limits_nvd_since_last": self.stats_rate_limits_nvd,
                "app_command_errors_since_last": dict(self.stats_app_command_errors) # Convert defaultdict
            }
            # Reset counters after reading
            self.stats_cve_lookups = 0
            self.stats_kev_alerts_sent = 0
            self.stats_messages_processed = 0
            self.stats_vulncheck_success = 0
            self.stats_nvd_fallback_success = 0
            self.stats_api_errors_vulncheck = 0
            self.stats_api_errors_nvd = 0
            self.stats_api_errors_cisa = 0
            self.stats_rate_limits_nvd = 0
            self.stats_app_command_errors.clear()

        # Gather non-counter diagnostics
        enabled_kev_guilds = self.db.count_enabled_guilds() if self.db else 0

        diagnostics_payload = {
            "timestamp": now.isoformat(),
            "loaded_cogs": self.loaded_cogs,
            "failed_cogs": self.failed_cogs,
            "kev_enabled_guilds": enabled_kev_guilds,
            "last_kev_check_success_ts": self.timestamp_last_kev_check_success.isoformat() if self.timestamp_last_kev_check_success else None,
            "last_kev_alert_sent_ts": self.timestamp_last_kev_alert_sent.isoformat() if self.timestamp_last_kev_alert_sent else None,
        }

        # --- Send Data --- 
        # Send basic status
        await self._send_to_web_portal("/api/v1/status", status_payload)

        # Gather and Send Stats Payload
        stats_payload = await self._get_current_stats()
        await self._send_to_web_portal("/api/v1/stats", stats_payload)

        # Gather and Send Diagnostics Payload
        diagnostics_payload = await self._get_current_diagnostics()
        await self._send_to_web_portal("/api/v1/diagnostics", diagnostics_payload)

        # Reset counters after attempting to send all payloads
        async with self.stats_lock:
            logger.debug("Resetting periodic statistics counters.")

    @report_status_task.before_loop
    async def before_report_status(self):
        """Ensures the bot is ready before the reporting loop starts."""
        await self.wait_until_ready()
        logger.info("Bot is ready, starting Kevvy Web reporting loop.")

    @report_status_task.after_loop
    async def after_report_status(self):
        if self.report_status_task.is_being_cancelled():
            logger.info("Kevvy Web reporting loop cancelled.")
        else:
            logger.error("Kevvy Web reporting loop stopped unexpectedly.")

    async def _send_to_web_portal(self, endpoint: str, data: Dict[str, Any]):
        """Sends data to a specified endpoint on the kevvy-web server."""
        if not self.kevvy_web_url or not self.kevvy_web_api_key or not self.http_session:
            logger.error("Cannot send to web portal: Configuration or session missing.")
            return

        target_url = self.kevvy_web_url.rstrip('/') + endpoint
        headers = {
            'Content-Type': 'application/json',
            'X-API-Key': self.kevvy_web_api_key
        }
        request_timeout = ClientTimeout(total=10)

        try:
            async with self.http_session.post(target_url, json=data, headers=headers, timeout=request_timeout) as response:
                if 200 <= response.status < 300:
                    logger.debug(f"Successfully sent data to kevvy-web endpoint {endpoint}. Status: {response.status}")
                else:
                    response_text = await response.text()
                    logger.error(f"Error sending data to kevvy-web endpoint {endpoint}. Status: {response.status}, Response: {response_text[:200]}") # Log first 200 chars
        except aiohttp.ClientConnectorError as e:
             logger.error(f"Connection error sending data to kevvy-web ({target_url}): {e}")
        except asyncio.TimeoutError:
            logger.error(f"Timeout error sending data to kevvy-web ({target_url})")
        except Exception as e:
            logger.error(f"Unexpected error sending data to kevvy-web endpoint {endpoint}: {e}", exc_info=True)

    def _create_kev_embed(self, kev_data: Dict[str, Any]) -> discord.Embed:
        """Creates a Discord embed for a CISA KEV entry."""
        cve_id = kev_data.get('cveID', 'N/A')
        nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id != 'N/A' else "Link unavailable"

        title = f"🚨 New CISA KEV Entry: {cve_id}"
        embed = discord.Embed(
            title=title,
            description=kev_data.get('shortDescription', 'No description available.'),
            url=nvd_link,
            color=discord.Color.dark_red()
        )

        embed.add_field(name="Vulnerability Name", value=kev_data.get('vulnerabilityName', 'N/A'), inline=False)
        embed.add_field(name="Vendor/Project", value=kev_data.get('vendorProject', 'N/A'), inline=True)
        embed.add_field(name="Product", value=kev_data.get('product', 'N/A'), inline=True)
        embed.add_field(name="Date Added", value=kev_data.get('dateAdded', 'N/A'), inline=True)
        embed.add_field(name="Required Action", value=kev_data.get('requiredAction', 'N/A'), inline=False)
        embed.add_field(name="Due Date", value=kev_data.get('dueDate', 'N/A'), inline=True)
        embed.add_field(name="Known Ransomware Use", value=kev_data.get('knownRansomwareCampaignUse', 'N/A'), inline=True)

        if notes := kev_data.get('notes', ''):
            notes_display = f'{notes[:1020]}...' if len(notes) > 1024 else notes
            embed.add_field(name="Notes", value=notes_display, inline=False)

        embed.set_footer(text="Source: CISA Known Exploited Vulnerabilities Catalog")
        embed.timestamp = discord.utils.utcnow()

        return embed

    async def on_connect(self):
        """Called when the bot successfully connects to the Discord Gateway."""
        logger.info(f"Successfully connected to Discord Gateway. Shard ID: {self.shard_id}")

    async def on_disconnect(self):
        """Called when the bot loses connection to the Discord Gateway."""
        logger.warning(f"Disconnected from Discord Gateway unexpectedly. Shard ID: {self.shard_id}. Will attempt to reconnect.")

    async def on_resumed(self):
        """Called when the bot successfully resumes a session after a disconnect."""
        logger.info(f"Successfully resumed Discord Gateway session. Shard ID: {self.shard_id}")

    async def on_ready(self):
        """Called when the bot is fully ready and internal cache is built."""
        if not hasattr(self, 'start_time'): # Prevent overwriting if on_ready is called multiple times (e.g., after resume)
            self.start_time = datetime.datetime.now(datetime.timezone.utc)
        logger.info(f'Logged in as {self.user.name} ({self.user.id})')
        logger.info(f'Command prefix: {self.command_prefix}')
        logger.info(f'Successfully fetched {len(self.guilds)} guilds.')
        logger.info('Bot is ready! Listening for CVEs...')
        await self._setup_discord_logging()

    async def on_guild_join(self, guild: discord.Guild):
        """Called when the bot joins a new guild."""
        logger.info(f"Joined guild: {guild.name} ({guild.id}). Owner: {guild.owner} ({guild.owner_id}). Members: {guild.member_count}")
        # Optional: Send a welcome message to the guild owner or a default channel

    async def on_guild_remove(self, guild: discord.Guild):
        """Called when the bot is removed from a guild."""
        logger.info(f"Removed from guild: {guild.name} ({guild.id}).")
        # Optional: Clean up any guild-specific configurations from the database

    async def on_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        """Global error handler for application (slash) commands."""
        command_name = interaction.command.name if interaction.command else "Unknown Command"
        user = interaction.user
        guild = interaction.guild
        channel = interaction.channel

        # Safely get guild/channel info for logging
        guild_name = guild.name if guild else "DM"
        guild_id = guild.id if guild else "N/A"
        # Use getattr for channel name as some types (like DMChannel) lack it
        channel_name = getattr(channel, 'name', 'DM/Unknown Channel')
        channel_id = channel.id if channel else "N/A"

        log_message = (
            f"App Command Error in command '{command_name}' "
            f"(User: {user} ({user.id}), Guild: {guild_name} ({guild_id}), "
            f"Channel: {channel_name} ({channel_id})): {error}"
        )

        if isinstance(error, app_commands.CommandNotFound):
            logger.warning(f"CommandNotFound error suppressed: {log_message}") # Usually not an issue unless commands aren't syncing
            # Don't need to inform user, Discord handles this
            return
        elif isinstance(error, app_commands.CommandOnCooldown):
            logger.warning(log_message)
            await interaction.response.send_message(
                f"⏳ This command is on cooldown. Please try again in {error.retry_after:.2f} seconds.",
                ephemeral=True
            )
        elif isinstance(error, app_commands.MissingPermissions):
            logger.error(log_message)
            await interaction.response.send_message(
                f"🚫 You do not have the required permissions to use this command: {', '.join(error.missing_permissions)}",
                ephemeral=True
            )
        elif isinstance(error, app_commands.BotMissingPermissions):
            logger.error(log_message)
            try:
                await interaction.response.send_message(
                    f"🚫 I lack the necessary permissions to run this command: {', '.join(error.missing_permissions)}."
                    f" Please ensure I have these permissions in this channel/server.",
                    ephemeral=True
                )
            except discord.Forbidden:
                 # Also safely access guild/channel id here
                 logger.error(f"Cannot even send error message about BotMissingPermissions in channel {channel_id} (Guild: {guild_id})")
        elif isinstance(error, app_commands.CheckFailure):
            # This covers custom checks failing (e.g., @app_commands.check decorators)
            logger.warning(f"CheckFailure: {log_message}")
            # Provide a generic message or tailor based on check type if needed
            await interaction.response.send_message(
                "❌ You do not meet the requirements to use this command.",
                ephemeral=True
            )
        else:
            # Log other/unexpected errors
            logger.error(f"Unhandled App Command Error: {log_message}", exc_info=error)
            try:
                # Send a generic error message if possible
                if interaction.response.is_done():
                    await interaction.followup.send("❌ An unexpected error occurred while processing your command.", ephemeral=True)
                else:
                    await interaction.response.send_message("❌ An unexpected error occurred while processing your command.", ephemeral=True)
            except Exception as e:
                 logger.error(f"Failed to send generic error message to user after unhandled App Command Error: {e}")

        # Increment error counter using the error type name
        error_type_name = type(error).__name__
        async with self.stats_lock:
            self.stats_app_command_errors[error_type_name] += 1

    async def _setup_discord_logging(self):
        """Sets up the DiscordLogHandler based on environment variables."""
        log_channel_id_str = os.getenv('LOGGING_CHANNEL_ID')
        disable_discord_logging = os.getenv('DISABLE_DISCORD_LOGGING', 'false').lower() == 'true'

        if disable_discord_logging:
            logging.info("Discord logging handler is disabled via DISABLE_DISCORD_LOGGING environment variable.")
            return # Exit setup early if disabled

        if log_channel_id_str:
            try:
                log_channel_id = int(log_channel_id_str)
                root_logger = logging.getLogger()

                # Check if the handler is already added to prevent duplicates during reconnects
                handler_exists = any(isinstance(h, DiscordLogHandler) and h.channel_id == log_channel_id for h in root_logger.handlers)
                if handler_exists:
                    logging.debug(f"DiscordLogHandler for channel {log_channel_id} already configured.")
                    return

                formatter = next(
                    (
                        handler.formatter
                        for handler in root_logger.handlers
                        if isinstance(handler, logging.StreamHandler)
                    ),
                    None,
                )
                discord_handler = DiscordLogHandler(bot=self, channel_id=log_channel_id)

                # Set formatter if found, otherwise use default
                if formatter:
                    discord_handler.setFormatter(formatter)
                else:
                    # Fallback basic formatter if no console handler found
                    fallback_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
                    discord_handler.setFormatter(fallback_formatter)

                root_logger.addHandler(discord_handler)
                logging.info(f"Successfully added Discord logging handler for channel ID {log_channel_id}")
            except ValueError:
                logging.error(f"Invalid LOGGING_CHANNEL_ID: '{log_channel_id_str}'. Must be an integer.")
            except Exception as e:
                logging.error(f"Failed to set up Discord logging handler: {e}", exc_info=True)
        else:
            logging.info("LOGGING_CHANNEL_ID not set, skipping Discord log handler setup.")

    async def on_message(self, message: discord.Message):
        if message.author == self.user:
            return

        # Increment message counter
        async with self.stats_lock:
            self.stats_messages_processed += 1

        if not self.cve_monitor:
             logger.debug("CVEMonitor not initialized, skipping CVE scan.")
             await self.process_commands(message)
             return

        cves_found = self.cve_monitor.find_cves(message.content)

        if not cves_found:
            await self.process_commands(message)
            return

        unique_cves = sorted(list(set(cves_found)), key=lambda x: cves_found.index(x))

        # --- Get Guild Verbose Setting --- 
        guild_verbose_setting = False # Default to non-verbose
        if message.guild and self.db:
            guild_config = self.db.get_cve_channel_config(message.guild.id)
            if guild_config and guild_config.get('enabled'): # Only apply if CVE monitoring is enabled
                guild_verbose_setting = guild_config.get('verbose_mode', False)
        # --- End Get Guild Verbose Setting ---

        embeds_to_send = []
        processed_count = 0
        for cve_original_case in unique_cves:
            # Normalize to uppercase for API lookups
            cve = cve_original_case.upper() # Added conversion

            if processed_count >= MAX_EMBEDS_PER_MESSAGE:
                logging.warning(f"Max embeds reached for message {message.id}. Found {len(unique_cves)} unique CVEs, processing first {MAX_EMBEDS_PER_MESSAGE}.")
                break

            cve_data = None
            source_used = None # Track which source succeeded
            try:
                # Increment lookup counter for each unique CVE attempted
                async with self.stats_lock:
                    self.stats_cve_lookups += 1

                if self.vulncheck_client.api_client:
                    logging.debug(f"Attempting VulnCheck fetch for {cve}") # Uses normalized cve
                    try:
                        cve_data = await self.vulncheck_client.get_cve_details(cve) # Pass normalized cve
                        if cve_data:
                            source_used = "VulnCheck"
                            async with self.stats_lock:
                                self.stats_vulncheck_success += 1 # Increment VulnCheck success
                    except Exception as e_vc:
                        logger.error(f"Error during VulnCheck API call for {cve}: {e_vc}", exc_info=True)
                        async with self.stats_lock:
                            self.stats_api_errors_vulncheck += 1
                        cve_data = None # Ensure cve_data is None if exception occurred
                else:
                    logging.debug("VulnCheck client not available (no API key?), skipping.")

                if not cve_data:
                    log_msg_prefix = f"VulnCheck failed for {cve}," if self.vulncheck_client.api_client else ""
                    logging.debug(f"{log_msg_prefix} Attempting NVD fetch for {cve} (VulnCheck unavailable or failed).") # Uses normalized cve

                    if self.nvd_client:
                        try:
                            cve_data = await self.nvd_client.get_cve_details(cve) # Pass normalized cve
                            if cve_data:
                                source_used = "NVD"
                                async with self.stats_lock:
                                    self.stats_nvd_fallback_success += 1 # Increment NVD fallback success
                        # Catch Rate Limit specifically
                        except NVDRateLimitError as e_rate_limit:
                            logger.warning(f"NVD rate limit encountered for {cve}: {e_rate_limit}")
                            async with self.stats_lock:
                                self.stats_rate_limits_nvd += 1
                            cve_data = None
                        # Catch other NVD client errors
                        except Exception as e_nvd:
                            logger.error(f"Error during NVD API call for {cve}: {e_nvd}", exc_info=True)
                            async with self.stats_lock:
                                self.stats_api_errors_nvd += 1
                            cve_data = None # Ensure cve_data is None if exception occurred
                    else:
                         logger.warning("NVD Client not available, skipping NVD lookup.")

                if cve_data:
                    # Add source info if not already present from client
                    if 'source' not in cve_data and source_used:
                         cve_data['source'] = source_used
                    
                    # --- Pass verbose setting to embed creation --- 
                    embeds = await self.cve_monitor.create_cve_embed(cve_data, verbose=guild_verbose_setting)
                    # --- End Pass verbose setting ---

                    embeds_to_send.extend(embeds)
                    processed_count += 1 # Increment based on primary CVE embed, not KEV
                else:
                    logging.warning(f"Could not retrieve details for {cve} from any source.") # Uses normalized cve

            except Exception as e:
                logging.error(f"Failed to process CVE {cve} after checking sources: {e}", exc_info=True) # Uses normalized cve

            await asyncio.sleep(0.2)

        if embeds_to_send:
            logging.info(f"Sending {len(embeds_to_send)} embeds for message {message.id}")
            # Ensure we don't exceed Discord embed limits per message batch (usually 10)
            # This logic sends one embed per message, which is safer but slower.
            # Consider batching embeds up to 10 per message if needed.
            for i, embed in enumerate(embeds_to_send):
                if i >= MAX_EMBEDS_PER_MESSAGE:
                    logging.warning(f"Stopping embed sending at {i} due to MAX_EMBEDS_PER_MESSAGE limit.")
                    break 
                try:
                     await message.channel.send(embed=embed)
                     if i < len(embeds_to_send) - 1:
                          await asyncio.sleep(0.5)
                except discord.Forbidden:
                     guild_id_str = message.guild.id if message.guild else 'DM'
                     logger.error(f"Missing permissions to send embed in channel {message.channel.id} (Guild: {guild_id_str})")
                     break 
                except discord.HTTPException as http_err:
                     logger.error(f"HTTP Error sending embed {i+1}/{len(embeds_to_send)} for message {message.id}: {http_err}")
                     await asyncio.sleep(1)
                except Exception as send_err:
                     logger.error(f"Unexpected error sending embed {i+1}/{len(embeds_to_send)}: {send_err}", exc_info=True)
                     await asyncio.sleep(1)

            if len(unique_cves) > MAX_EMBEDS_PER_MESSAGE:
                await message.channel.send(f"*Found {len(unique_cves)} unique CVEs, showing details for the first {MAX_EMBEDS_PER_MESSAGE}.*", allowed_mentions=discord.AllowedMentions.none())

        await self.process_commands(message)

    async def _get_current_stats(self) -> Dict[str, Any]:
        """Gathers current statistics counters under lock."""
        async with self.stats_lock:
            # Return a copy of the current stats
            return {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "bot_id": self.user.id if self.user else None,
                "cve_lookups_since_last": self.stats_cve_lookups,
                "kev_alerts_sent_since_last": self.stats_kev_alerts_sent,
                "messages_processed_since_last": self.stats_messages_processed,
                "vulncheck_success_since_last": self.stats_vulncheck_success,
                "nvd_fallback_success_since_last": self.stats_nvd_fallback_success,
                "api_errors_vulncheck_since_last": self.stats_api_errors_vulncheck,
                "api_errors_nvd_since_last": self.stats_api_errors_nvd,
                "api_errors_cisa_since_last": self.stats_api_errors_cisa,
                "rate_limits_nvd_since_last": self.stats_rate_limits_nvd,
                "app_command_errors_since_last": dict(self.stats_app_command_errors)
            }

    async def _get_current_diagnostics(self) -> Dict[str, Any]:
        """Gathers current diagnostic information."""
        enabled_kev_guilds = self.db.count_enabled_guilds() if self.db else 0

        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "bot_id": self.user.id if self.user else None,
            "loaded_cogs": self.loaded_cogs,
            "failed_cogs": self.failed_cogs,
            "kev_enabled_guilds": enabled_kev_guilds,
            "last_kev_check_success_ts": self.timestamp_last_kev_check_success.isoformat() if self.timestamp_last_kev_check_success else None,
            "last_kev_alert_sent_ts": self.timestamp_last_kev_alert_sent.isoformat() if self.timestamp_last_kev_alert_sent else None,
            # Add other relevant non-counter diagnostics here if needed
        }