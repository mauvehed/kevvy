import discord
from discord.ext import commands, tasks
import aiohttp
from .cve_monitor import CVEMonitor
from .nvd_client import NVDClient, NVDRateLimitError
from .vulncheck_client import VulnCheckClient
from .cisa_kev_client import CisaKevClient
from .db_utils import KEVConfigDB
import logging
import os
import asyncio
from typing import Dict, List, Optional, Tuple
from .discord_log_handler import DiscordLogHandler
import datetime
import signal
import importlib.metadata  # Added for dynamic versioning
from .stats_manager import StatsManager
from discord import app_commands

# Constants
MAX_EMBEDS_PER_MESSAGE = 5
WEBAPP_ENDPOINT_URL = os.getenv("KEVVY_WEB_URL", "")
WEBAPP_API_KEY = os.getenv("KEVVY_WEB_API_KEY", None)

logger = logging.getLogger(__name__)


class SecurityBot(commands.Bot):
    def __init__(self, nvd_api_key: str | None, vulncheck_api_token: str | None):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        prefix = os.getenv("DISCORD_COMMAND_PREFIX", "!")
        super().__init__(
            command_prefix=prefix, intents=intents, enable_debug_events=True
        )

        self.http_session: aiohttp.ClientSession | None = None
        self.cisa_kev_client: CisaKevClient | None = None
        self.db: KEVConfigDB | None = None
        self.nvd_client: NVDClient | None = None
        self.cve_monitor: CVEMonitor | None = None
        self.start_time: datetime.datetime = datetime.datetime.now(
            datetime.timezone.utc
        )
        self.loaded_cogs: List[str] = []
        self.failed_cogs: List[str] = []
        self.timestamp_last_kev_check_success: Optional[datetime.datetime] = None
        self.timestamp_last_kev_alert_sent: Optional[datetime.datetime] = None

        # --- Initialize StatsManager ---
        self.stats_manager = StatsManager()
        # --- End Initialize StatsManager ---

        self.version = "0.1.0-test"  # Add a version attribute
        # Read version dynamically from package metadata
        try:
            self.version = importlib.metadata.version("kevvy")
        except importlib.metadata.PackageNotFoundError:
            logger.error(
                "Could not determine package version for 'kevvy'. Using default."
            )
            self.version = "0.0.0-unknown"

        self.vulncheck_client = VulnCheckClient(api_key=vulncheck_api_token)
        self.last_stats_sent_time: Optional[datetime.datetime] = None
        # Add cache for recently processed CVEs in channels
        self.recently_processed_cves: Dict[Tuple[int, str], datetime.datetime] = {}
        self.RECENT_CVE_CACHE_SECONDS = 20  # Cache duration in seconds
        self.discord_log_handler: Optional[DiscordLogHandler] = None

        # Cache for KEVs recently alerted to a channel (either by on_message or check_cisa_kev_feed)
        self.recently_alerted_kevs: Dict[Tuple[int, str], datetime.datetime] = {}
        self.RECENT_KEV_ALERT_CACHE_HOURS = (
            1  # Cache KEV alerts for 1 hour to avoid duplicates
        )

    def get_uptime_string(self) -> str:
        """Returns a human-readable uptime string."""
        if not self.start_time:
            return "Unknown"

        now = datetime.datetime.now(datetime.timezone.utc)
        diff = now - self.start_time

        days = diff.days
        hours, remainder = divmod(diff.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0 or days > 0:
            parts.append(f"{hours}h")
        if minutes > 0 or hours > 0 or days > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")

        return " ".join(parts)

    async def _handle_signal(self, sig: signal.Signals):
        """Handles received OS signals for graceful shutdown."""
        logger.warning(f"Received signal {sig.name}. Initiating graceful shutdown...")
        # Use create_task to ensure close() runs even if the handler is interrupted
        asyncio.create_task(self.close(), name=f"Signal-{sig.name}-Shutdown")

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
            logger.warning(
                "Signal handlers are not supported on this platform (likely Windows). Graceful shutdown via signals is disabled."
            )
        except Exception as e:
            logger.error(f"Failed to set up signal handlers: {e}", exc_info=True)

    async def setup_hook(self):
        self.http_session = aiohttp.ClientSession()
        logger.info("Created aiohttp.ClientSession.")

        self.nvd_client = NVDClient(
            session=self.http_session, api_key=os.getenv("NVD_API_KEY")
        )
        logger.info("Initialized NVDClient.")

        try:
            self.db = KEVConfigDB()
            logger.info("Initialized KEV Configuration Database.")
        except Exception as e:
            logger.error(
                f"Failed to initialize KEV Configuration Database: {e}", exc_info=True
            )
            self.db = None

        if self.db and self.http_session:
            self.cisa_kev_client = CisaKevClient(session=self.http_session, db=self.db)
            logger.info("Initialized CisaKevClient with DB persistence.")
        else:
            logger.error(
                "Could not initialize CisaKevClient due to missing DB or HTTP session."
            )
            self.cisa_kev_client = None

        if self.nvd_client:
            self.cve_monitor = CVEMonitor(
                self.nvd_client,
                vulncheck_client=self.vulncheck_client,
                kev_client=self.cisa_kev_client,
                stats_manager=self.stats_manager,
            )
            logger.info(
                f"Initialized CVEMonitor (KEV support: {'enabled' if self.cisa_kev_client else 'disabled'}, VulnCheck: {'enabled' if self.vulncheck_client else 'disabled'})."
            )
        else:
            logger.error(
                "Could not initialize CVEMonitor because NVDClient failed to initialize."
            )

        # Load all cogs
        initial_extensions = [
            "kevvy.cogs.kev_commands",
            "kevvy.cogs.cve_lookup",
            "kevvy.cogs.utility_cog",
            "kevvy.cogs.core_events_cog",
            "kevvy.cogs.tasks_cog",
            "kevvy.cogs.diagnostics",
        ]
        self.loaded_cogs = []
        self.failed_cogs = []
        for i, extension in enumerate(initial_extensions):
            logger.debug(f"Attempting to load extension {i + 1}: {extension}")
            try:
                await self.load_extension(extension)
                logger.info(f"Successfully loaded extension: {extension}")
                self.loaded_cogs.append(extension)
            except commands.ExtensionError as e:
                logger.error(
                    f"Failed to load extension {extension}: {e}", exc_info=True
                )
                self.failed_cogs.append(f"{extension} (Load Error)")
            except asyncio.CancelledError:
                logger.error(
                    f"Extension loading loop cancelled during processing of extension: {extension}",
                    exc_info=True,
                )
                self.failed_cogs.append(f"{extension} (Cancelled during load)")
                raise
            except Exception as e:
                logger.error(
                    f"An unexpected error occurred loading extension {extension}: {e}",
                    exc_info=True,
                )
                self.failed_cogs.append(f"{extension} (Exception)")
            logger.debug(f"Finished processing extension {i + 1}: {extension}")

        self._setup_signal_handlers()
        logger.info(f"--- Initializing Kevvy Bot Version: {self.version} ---")

        # Read test guild ID from environment variable or use default
        test_guild_id_str = os.getenv("TEST_GUILD_ID", "")
        test_guild_id = int(test_guild_id_str) if test_guild_id_str else None

        if test_guild_id:
            guild_obj = discord.Object(id=test_guild_id)
            logger.info(
                f"Preparing to sync commands to specific guild: {test_guild_id}"
            )

            # Log which commands are being synced
            all_commands = self.tree.get_commands()
            command_names = [cmd.name for cmd in all_commands]
            logger.info(f"Commands being synced: {', '.join(command_names)}")

            # Check for specifically problematic commands
            for cmd in all_commands:
                if isinstance(cmd, app_commands.Group):
                    logger.info(
                        f"Group '{cmd.name}' has subcommands: {[subcmd.name for subcmd in cmd.commands]}"
                    )

            await self.tree.sync(guild=guild_obj)
            logger.info(f"Application commands synced to guild {test_guild_id}.")
        else:
            logger.info("Syncing global application commands...")
            await self.tree.sync()
            logger.info("Global application commands synced.")

        await self._setup_discord_logging()

    async def close(self):
        logger.warning("Bot shutdown initiated...")
        if self.is_closed():
            logger.info("Bot close() called, but already closing/closed.")
            return
        logging.info("Closing bot resources...")

        if self.http_session:
            await self.http_session.close()
            logging.info("Closed aiohttp session.")
        if self.db:
            self.db.close()
            logging.info("Closed KEV Config Database connection.")
        await super().close()
        logger.warning("Bot shutdown complete.")

    async def _setup_discord_logging(self):
        """Sets up the DiscordLogHandler based on environment variables."""
        log_channel_id_str = os.getenv("LOGGING_CHANNEL_ID")
        disable_discord_logging = (
            os.getenv("DISABLE_DISCORD_LOGGING", "false").lower() == "true"
        )

        if disable_discord_logging:
            logging.info(
                "Discord logging handler is disabled via DISABLE_DISCORD_LOGGING environment variable."
            )
            return  # Exit setup early if disabled

        if log_channel_id_str:
            try:
                log_channel_id = int(log_channel_id_str)
                root_logger = logging.getLogger()

                # Check if the handler is already added to prevent duplicates during reconnects
                handler_exists = any(
                    isinstance(h, DiscordLogHandler) and h.channel_id == log_channel_id
                    for h in root_logger.handlers
                )
                if handler_exists:
                    logging.debug(
                        f"DiscordLogHandler for channel {log_channel_id} already configured."
                    )
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
                    fallback_formatter = logging.Formatter(
                        "%(asctime)s - %(levelname)s - %(name)s - %(message)s"
                    )
                    discord_handler.setFormatter(fallback_formatter)

                root_logger.addHandler(discord_handler)
                logging.info(
                    f"Successfully added Discord logging handler for channel ID {log_channel_id}"
                )
            except ValueError:
                logging.error(
                    f"Invalid LOGGING_CHANNEL_ID: '{log_channel_id_str}'. Must be an integer."
                )
            except Exception as e:
                logging.error(
                    f"Failed to set up Discord logging handler: {e}", exc_info=True
                )
        else:
            logging.info(
                "LOGGING_CHANNEL_ID not set, skipping Discord log handler setup."
            )

        # Add final log regardless of success/failure in preparing
        log_status = "SET" if self.discord_log_handler else "NOT SET"
        logging.debug(
            f"_setup_discord_logging finished. self.discord_log_handler is {log_status}."
        )

    # @tasks.loop(minutes=5) # Commented out to prevent duplicate status sending
    async def send_stats_to_webapp(self):
        """Periodically sends bot statistics to the web application dashboard."""
        if not self.http_session:
            logger.debug("HTTP session not available, skipping web app stats send.")
            return

        # Skip if URL is not configured
        base_url = WEBAPP_ENDPOINT_URL
        if not base_url or base_url == "YOUR_WEBAPP_ENDPOINT_URL_HERE":
            logger.debug(
                "Web app endpoint URL not properly configured, skipping stats send."
            )
            return

        # Construct the full URL
        full_url = f"{base_url.rstrip('/')}/api/bot-status"

        headers = {
            "Content-Type": "application/json",
        }
        if WEBAPP_API_KEY:
            headers["Authorization"] = f"Bearer {WEBAPP_API_KEY}"

        try:
            # Ensure we correctly await the async method
            current_stats = await self.stats_manager.get_stats_dict()
            current_time = datetime.datetime.now(datetime.timezone.utc)
            uptime_delta = current_time - self.start_time
            uptime_seconds = int(uptime_delta.total_seconds())

            # Ensure kev_enabled_count is defined before constructing the payload
            kev_enabled_count = 0
            if self.db:
                try:
                    kev_enabled_count = self.db.count_enabled_guilds()
                except Exception as db_err:
                    logger.error(
                        f"Error fetching KEV enabled guild count: {db_err}",
                        exc_info=True,
                    )

            # Map only the required stats fields to the exact names expected by the backend
            mapped_stats = {
                "cve_lookups": current_stats.get("cve_lookups", 0),
                "kev_alerts": current_stats.get("kev_alerts_sent", 0),
                "messages_processed": current_stats.get("messages_processed", 0),
                "vulncheck_success": current_stats.get("vulncheck_success", 0),
                "nvd_fallback_success": current_stats.get("nvd_fallback_success", 0),
                "api_errors_vulncheck": current_stats.get("api_errors_vulncheck", 0),
                "nvd_api_errors": current_stats.get("api_errors_nvd", 0),
                "api_errors_cisa": current_stats.get("api_errors_cisa", 0),
                "kev_api_errors": current_stats.get("api_errors_kev", 0),
                "rate_limits_nvd": current_stats.get("rate_limits_hit_nvd", 0),
                "app_command_errors": current_stats.get("app_command_errors", {}),
            }

            # Construct the payload
            payload = {
                "bot_id": self.user.id if self.user else None,
                "bot_name": str(self.user) if self.user else "Unknown",
                "guild_count": len(self.guilds),
                "latency_ms": round(self.latency * 1000, 2),
                "uptime": self.get_uptime_string(),
                "shard_id": self.shard_id if self.shard_id is not None else 0,
                "shard_count": self.shard_count if self.shard_count is not None else 1,
                "start_time": self.start_time.isoformat(),
                "uptime_seconds": uptime_seconds,
                "is_ready": self.is_ready(),
                "timestamp": current_time.isoformat(),
                "last_stats_sent_time": (
                    self.last_stats_sent_time.isoformat()
                    if self.last_stats_sent_time
                    else None
                ),
                # Only include mapped stats fields at the top level
                **mapped_stats,
                # Ensure these are always present at top level
                "loaded_cogs": self.loaded_cogs,
                "failed_cogs": self.failed_cogs,
                "last_kev_check_success": (
                    self.timestamp_last_kev_check_success.isoformat()
                    if self.timestamp_last_kev_check_success
                    else None
                ),
                "last_kev_alert_sent": (
                    self.timestamp_last_kev_alert_sent.isoformat()
                    if self.timestamp_last_kev_alert_sent
                    else None
                ),
                "kev_enabled_guilds": kev_enabled_count,
                "version": self.version,
                # Also include stats in the nested structure for backward compatibility
                "stats": {
                    **current_stats,
                    "loaded_cogs": self.loaded_cogs,
                    "failed_cogs": self.failed_cogs,
                    "last_kev_check_success": (
                        self.timestamp_last_kev_check_success.isoformat()
                        if self.timestamp_last_kev_check_success
                        else None
                    ),
                    "last_kev_alert_sent": (
                        self.timestamp_last_kev_alert_sent.isoformat()
                        if self.timestamp_last_kev_alert_sent
                        else None
                    ),
                    "kev_enabled_guilds": kev_enabled_count,
                },
            }

            logger.info(f"Sending stats payload to {full_url}")

            status_code, response_text = await self._post_stats(
                full_url, payload, headers
            )

            if 200 <= status_code < 300:
                logger.info(
                    f"Successfully sent stats to web app (Status: {status_code})"
                )
                self.last_stats_sent_time = datetime.datetime.now(datetime.timezone.utc)
            else:
                logger.error(
                    f"Failed to send stats to web app. Status: {status_code}. Response: {response_text[:500]}"
                )
        except aiohttp.ClientError as e:
            logger.error(
                f"Connection error while sending stats to web app {full_url}: {e}"
            )
        except Exception as e:
            logger.error(
                f"An unexpected error occurred sending stats to web app: {e}",
                exc_info=True,
            )

    async def on_message(self, message: discord.Message):
        """Process incoming messages for CVEs and respond with info embeds."""
        # Handle commands first before any other processing
        # Check if the message invoked a command
        ctx = await self.get_context(message)
        if ctx.command:
            # If a command was found, process it and then stop further on_message processing
            # for this message to prevent duplicate responses or unintended CVE lookups on command text.
            # In this specific method, returning here primarily prevents the redundant self.process_commands
            # call below IF the CVE logic were still present in this on_message.
            # Since CVE logic is being moved/confirmed to be in CoreEventsCog,
            # this early return's main job is to ensure commands are processed once.
            await self.process_commands(message)
            return

        # If no command was invoked by this message, then self.process_commands below won't do anything
        # specific for commands (as there isn't one).
        # We still call it as per discord.py best practices when overriding on_message,
        # as it might handle other message-related tasks or ensure the event dispatch flow is complete.
        # Cog-based on_message listeners will still fire independently.
        await self.process_commands(message)

        # All CVE-specific processing, including incrementing messages_processed,
        # fetching CVE data, checking KEV status, sending embeds, and caching,
        # is now handled by the on_message listener in CoreEventsCog.
        # This bot-level on_message is now solely for ensuring commands are processed
        # when on_message is overridden at the bot level.

    async def on_connect(self):  # This is a new addition if not present
        logger.info(f"Bot connected to Discord. Shard ID: {self.shard_id}")

    async def on_resumed(self):  # This is a new addition if not present
        logger.info(f"Bot resumed connection. Shard ID: {self.shard_id}")

    async def on_disconnect(self):  # This is a new addition if not present
        logger.warning(
            f"Bot disconnected from Discord. Shard ID: {self.shard_id}. Attempting to reconnect."
        )


# If the main function or entry point is here, it would be at the end of the file.
# Example:
# async def main():
#     # ... setup and run bot
#
# if __name__ == "__main__":
#     asyncio.run(main())
