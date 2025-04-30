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
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
from .discord_log_handler import DiscordLogHandler
import datetime
import signal
import re
import importlib.metadata


class IgnoreHttpRateLimitFilter(logging.Filter):
    def filter(self, record):
        # Reject logs from 'discord.http' logger to prevent feedback loops
        # during rate limiting.
        return not record.name.startswith("discord.http")


MAX_EMBEDS_PER_MESSAGE = 5
WEBAPP_ENDPOINT_URL = os.getenv("KEVVY_WEB_URL", "YOUR_WEBAPP_ENDPOINT_URL_HERE")
WEBAPP_API_KEY = os.getenv("KEVVY_WEB_API_KEY", None)

logger = logging.getLogger(__name__)

try:
    bot_version = importlib.metadata.version("kevvy")  # Assumes package name is 'kevvy'
except importlib.metadata.PackageNotFoundError:
    bot_version = "unknown"
    logger.warning("Could not determine bot version. Package 'kevvy' not found.")


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

        # --- Statistics Counters ---
        self.stats_lock = asyncio.Lock()
        self.stats_cve_lookups = 0
        self.stats_kev_alerts_sent = 0
        self.stats_messages_processed = 0
        self.stats_vulncheck_success = 0
        self.stats_nvd_fallback_success = 0
        self.stats_api_errors_vulncheck = 0
        self.stats_api_errors_nvd = 0
        self.stats_api_errors_cisa = 0
        self.stats_api_errors_kev = 0
        self.stats_rate_limits_nvd = 0
        self.stats_rate_limits_hit_nvd = 0
        self.stats_app_command_errors: Dict[str, int] = defaultdict(int)
        # --- End Statistics Counters ---

        # Assign the version determined at module level
        self.version = bot_version  # Use the already determined version

        self.vulncheck_client = VulnCheckClient(api_key=vulncheck_api_token)
        self.last_stats_sent_time: Optional[datetime.datetime] = None
        # Add cache for recently processed CVEs in channels
        self.recently_processed_cves: Dict[Tuple[int, str], datetime.datetime] = {}
        self.RECENT_CVE_CACHE_SECONDS = 20  # Cache duration in seconds

        # Flag for KEV check initial run
        self.kev_check_first_run = True
        # Placeholder for the Discord log handler
        self.discord_log_handler: Optional[DiscordLogHandler] = None

    def get_uptime(self) -> str:
        """Calculates the bot's uptime."""
        now = datetime.datetime.now(datetime.timezone.utc)
        delta = now - self.start_time

        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        days, hours = divmod(hours, 24)

        if days > 0:
            return f"{days}d {hours}h {minutes}m {seconds}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"

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

        # Initialize NVD client now that we have a session
        self.nvd_client = NVDClient(
            session=self.http_session, api_key=os.getenv("NVD_API_KEY")
        )
        logger.info("Initialized NVDClient.")

        # Initialize Database utility
        try:
            self.db = KEVConfigDB()
            logger.info("Initialized KEV Configuration Database.")
        except Exception as e:
            logger.error(
                f"Failed to initialize KEV Configuration Database: {e}", exc_info=True
            )
            self.db = None

        # Initialize CISA client
        if self.db and self.http_session:
            self.cisa_kev_client = CisaKevClient(session=self.http_session, db=self.db)
            logger.info("Initialized CisaKevClient with DB persistence.")
        else:
            logger.error(
                "Could not initialize CisaKevClient due to missing DB or HTTP session."
            )
            self.cisa_kev_client = None

        # Initialize CVEMonitor with NVDClient and potentially CisaKevClient
        if self.nvd_client:
            self.cve_monitor = CVEMonitor(
                self.nvd_client, kev_client=self.cisa_kev_client
            )
            logger.info(
                f"Initialized CVEMonitor (KEV support: {'enabled' if self.cisa_kev_client else 'disabled'})."
            )
        else:
            logger.error(
                "Could not initialize CVEMonitor because NVDClient failed to initialize."
            )

        # Load Cogs
        initial_extensions = [
            "kevvy.cogs.kev_commands",
            "kevvy.cogs.cve_lookup",
            # 'kevvy.cogs.diagnostics' # Removed as requested
        ]
        self.loaded_cogs = []  # Reset on setup
        self.failed_cogs = []  # Reset on setup
        for extension in initial_extensions:
            try:
                await self.load_extension(extension)
                logger.info(f"Successfully loaded extension: {extension}")
                self.loaded_cogs.append(extension)
            except commands.ExtensionError as e:
                logger.error(
                    f"Failed to load extension {extension}: {e}", exc_info=True
                )
                self.failed_cogs.append(f"{extension} (Load Error)")
            except Exception as e:
                logger.error(
                    f"An unexpected error occurred loading extension {extension}: {e}",
                    exc_info=True,
                )
                self.failed_cogs.append(f"{extension} (Exception)")

        # Setup signal handlers before syncing commands or starting tasks
        self._setup_signal_handlers()

        logger.info(f"--- Initializing Kevvy Bot Version: {self.version} ---")

        # Sync the commands
        try:
            await self.tree.sync()
            logging.info("Synced application commands.")
        except Exception as e:
            logger.error(f"Failed to sync application commands: {e}", exc_info=True)
            # Consider adding this failure to failed_cogs or a separate status

        # Start background tasks
        self.check_cisa_kev_feed.start()
        self.send_stats_to_webapp.start()

        # Setup Discord logging handler (it will be activated in on_ready)
        await self._setup_discord_logging()

    async def _post_stats(
        self, url: str, payload: dict, headers: dict
    ) -> Tuple[int, str]:
        """Helper method to perform the actual POST request for stats.

        Returns:
            Tuple[int, str]: Status code and response text.
        Raises:
            aiohttp.ClientConnectorError: If a connection error occurs.
            asyncio.TimeoutError: If the request times out.
            Exception: For other unexpected errors during the request.
        """
        timeout = ClientTimeout(total=10)  # 10-second timeout
        if not self.http_session:
            logger.error("HTTP session is not initialized, cannot send stats.")
            raise RuntimeError("HTTP Session not available")  # Or handle appropriately

        logger.debug(f"Executing POST to {url}")
        try:
            async with self.http_session.post(
                url, json=payload, headers=headers, timeout=timeout
            ) as response:
                response_text = await response.text()
                logger.debug(
                    f"Received response from {url}: Status {response.status}, Body: {response_text[:100]}"
                )  # Log truncated response
                return response.status, response_text
        except aiohttp.ClientConnectorError as e:
            logger.error(f"Connection error during stats POST to {url}: {e}")
            raise  # Re-raise for the caller to handle
        except asyncio.TimeoutError:
            logger.error(f"Timeout during stats POST to {url}")
            raise  # Re-raise for the caller to handle
        except Exception as e:
            logger.error(
                f"Unexpected error during stats POST to {url}: {e}", exc_info=True
            )
            raise  # Re-raise unexpected errors

    async def close(self):
        logger.warning("Bot shutdown initiated...")
        if self.is_closed():
            logger.info("Bot close() called, but already closing/closed.")
            return

        logging.info("Closing bot resources...")
        if self.check_cisa_kev_feed.is_running():
            self.check_cisa_kev_feed.cancel()
            logging.info("Cancelled CISA KEV monitoring task.")

        if self.send_stats_to_webapp.is_running():
            self.send_stats_to_webapp.cancel()
            logging.info("Cancelled Web App Stats sending task.")

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
                success = (
                    True  # Mark success if call completes without CISA client exception
                )
            except Exception as client_error:
                logger.error(
                    f"CISA KEV client error during fetch: {client_error}", exc_info=True
                )
                async with self.stats_lock:
                    self.stats_api_errors_cisa += 1
                # Allow loop to continue to update timestamp

            if not new_entries:
                logger.info(
                    "Completed periodic CISA KEV check. No new KEV entries found."
                )
                # No processing needed if no new entries
            else:
                # --- Start: Block moved inside this 'else' ---
                logger.info(
                    f"Found {len(new_entries)} new KEV entries. Checking configured guilds..."
                )
                # Initialize here, only if there are entries to process
                alerts_sent_this_run = 0
                enabled_configs = self.db.get_enabled_kev_configs()

                # Limit entries on the very first run after startup
                max_initial_entries = 3
                if self.kev_check_first_run and len(new_entries) > max_initial_entries:
                    logger.warning(
                        f"First KEV check run found {len(new_entries)} entries. Processing only the first {max_initial_entries} to avoid rate limits."
                    )
                    new_entries_to_process = new_entries[:max_initial_entries]
                    self.kev_check_first_run = False  # Set flag so next run is full
                else:
                    new_entries_to_process = new_entries
                    if self.kev_check_first_run:
                        self.kev_check_first_run = False  # Set flag even if fewer than max were found initially

                if enabled_configs:
                    for config in enabled_configs:
                        guild_id = config["guild_id"]
                        channel_id = config["channel_id"]

                        guild = self.get_guild(guild_id)
                        if not guild:
                            logger.warning(
                                f"Could not find guild {guild_id} from KEV config, skipping."
                            )
                            continue

                        target_channel = self.get_channel(channel_id)
                        if not target_channel:
                            logger.error(
                                f"Could not find CISA KEV target channel with ID: {channel_id} in guild {guild.name} ({guild_id})"
                            )
                            continue
                        if not isinstance(target_channel, discord.TextChannel):
                            logger.error(
                                f"CISA KEV target channel {channel_id} in guild {guild.name} ({guild_id}) is not a TextChannel."
                            )
                            continue

                        logger.info(
                            f"Sending {len(new_entries_to_process)} new KEV entries to channel #{target_channel.name} in guild {guild.name}"
                        )
                        # Track alerts sent to *this specific* channel for logging/delay purposes maybe?
                        # alerts_sent_to_this_channel = 0
                        for entry in new_entries_to_process:
                            embed = self._create_kev_embed(entry)
                            try:
                                await target_channel.send(embed=embed)
                                alerts_sent_this_run += 1  # Increment total sent count
                                # alerts_sent_to_this_channel += 1
                                self.timestamp_last_kev_alert_sent = (
                                    datetime.datetime.now(datetime.timezone.utc)
                                )  # Update timestamp
                                await asyncio.sleep(1.5)  # Increase sleep duration
                            except discord.Forbidden:
                                logger.error(
                                    f"Missing permissions to send message in CISA KEV channel {channel_id} (Guild: {guild_id})"
                                )
                                break  # Stop sending to this channel if permission lost
                            except discord.HTTPException as e:
                                logger.error(
                                    f"Failed to send CISA KEV embed for {entry.get('cveID', 'Unknown CVE')} to channel {channel_id} (Guild: {guild_id}): {e}"
                                )
                            except Exception as e:
                                logger.error(
                                    f"Unexpected error sending KEV embed for {entry.get('cveID', 'Unknown CVE')} (Guild: {guild_id}): {e}",
                                    exc_info=True,
                                )
                        # Consider moving sleep outside inner loop if rate limits are per channel
                        await asyncio.sleep(
                            2
                        )  # Sleep AFTER processing all entries for ONE channel

                    # --- Moved Stat Update Outside Config Loop ---
                    if alerts_sent_this_run > 0:
                        async with self.stats_lock:
                            self.stats_kev_alerts_sent += alerts_sent_this_run
                        logger.info(
                            f"Finished sending KEV alerts. Total sent this run: {alerts_sent_this_run}"
                        )
                    # --- End Moved Stat Update ---

                else:
                    logger.info("No guilds have KEV monitoring enabled.")
                # --- End: Block moved inside this 'else' ---

            # Update success timestamp if the fetch didn't raise an exception
            # This should be outside the main try/except for the KEV check logic
            # to ensure it runs even if there are errors processing entries,
            # as long as the initial fetch succeeded.
            if success:
                self.timestamp_last_kev_check_success = task_start_time
                logger.debug(
                    f"Updated last KEV check success timestamp to {task_start_time}"
                )

        except Exception as e:
            # Catch errors in the loop logic itself (outside CISA client call)
            logger.error(f"Error during CISA KEV check loop logic: {e}", exc_info=True)
            # Optionally increment a different counter for loop errors vs API errors

    @check_cisa_kev_feed.before_loop
    async def before_kev_check(self):
        """Ensures the bot is ready before the loop starts."""
        await self.wait_until_ready()
        logger.info("Bot is ready, starting CISA KEV monitoring loop.")

    # --- Background Task: Send Stats to Web App ---
    @tasks.loop(minutes=5)
    async def send_stats_to_webapp(self):
        """Periodically sends bot statistics to the web application dashboard."""
        if not self.http_session:
            logger.debug("HTTP session not available, skipping web app stats send.")
            return

        base_url = WEBAPP_ENDPOINT_URL  # Keep the base URL from env var
        if base_url == "YOUR_WEBAPP_ENDPOINT_URL_HERE":
            logger.debug(
                "Web app endpoint base URL not configured (KEVVY_WEB_URL), skipping stats send."
            )
            return

        # Construct the full URL by appending the specific path
        # Use rstrip to handle potential trailing slash in env var
        full_url = f"{base_url.rstrip('/')}/api/bot-status"

        current_time = datetime.datetime.now(datetime.timezone.utc)
        stats_payload = {}

        # Safely gather stats under lock
        async with self.stats_lock:
            stats_payload = {
                "bot_id": self.user.id if self.user else None,
                "bot_name": str(self.user) if self.user else "Unknown",
                "guild_count": len(self.guilds),
                "latency_ms": round(self.latency * 1000, 2),
                "start_time": self.start_time.isoformat(),
                "timestamp": current_time.isoformat(),
                "last_stats_sent_time": (
                    self.last_stats_sent_time.isoformat()
                    if self.last_stats_sent_time
                    else None
                ),
                "stats": {
                    "cve_lookups": self.stats_cve_lookups,
                    "kev_alerts_sent": self.stats_kev_alerts_sent,
                    "messages_processed": self.stats_messages_processed,
                    "vulncheck_success": self.stats_vulncheck_success,
                    "nvd_fallback_success": self.stats_nvd_fallback_success,
                    "api_errors_vulncheck": self.stats_api_errors_vulncheck,
                    "api_errors_nvd": self.stats_api_errors_nvd,
                    "api_errors_cisa": self.stats_api_errors_cisa,
                    "api_errors_kev": self.stats_api_errors_kev,
                    "rate_limits_nvd": self.stats_rate_limits_nvd,
                    "rate_limits_hit_nvd": self.stats_rate_limits_hit_nvd,
                    "app_command_errors": dict(
                        self.stats_app_command_errors
                    ),  # Convert defaultdict
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
                    # Add other relevant stats like uptime if needed
                },
            }

        headers = {"Content-Type": "application/json"}
        if WEBAPP_API_KEY:
            headers["Authorization"] = (
                f"Bearer {WEBAPP_API_KEY}"  # Or adjust scheme if needed
            )

        ClientTimeout(total=10)

        try:
            # Add the missing log statement back
            logger.info(f"Sending stats payload to {full_url}")
            # Call the new helper method
            status_code, response_text = await self._post_stats(
                full_url, stats_payload, headers
            )

            # Process response based on status code
            if 200 <= status_code < 300:
                logger.info(
                    f"Successfully sent stats to web app (Status: {status_code})"
                )
                self.last_stats_sent_time = datetime.datetime.now(datetime.timezone.utc)
            else:
                # Log HTTP errors from the web app
                logger.error(
                    f"Failed to send stats to web app. Status: {status_code}. "
                    f"Response: {response_text[:200]}"  # Log truncated response
                )

        except aiohttp.ClientConnectorError as e:
            # Log connection errors specifically
            logger.error(
                f"Connection error sending stats to web app {full_url}: {type(e).__name__} - {e}"
            )
        except asyncio.TimeoutError:
            logger.error(f"Timeout sending stats to web app {full_url}")
        except RuntimeError as e:  # Catch session not ready error from helper
            logger.error(f"Cannot send stats: {e}")
        except Exception as e:
            # Catch-all for other unexpected errors during the process
            logger.error(
                f"An unexpected error occurred sending stats to web app: {e}",
                exc_info=True,
            )

    @send_stats_to_webapp.before_loop
    async def before_send_stats(self):
        """Ensures the bot is ready before the stats loop starts."""
        await self.wait_until_ready()
        logger.info("Starting Web App Stats sending loop...")

    # --- End Background Task: Send Stats to Web App ---

    def _create_kev_embed(self, kev_data: Dict[str, Any]) -> discord.Embed:
        """Creates a standardized embed for a KEV entry."""
        cve_id = kev_data.get("cveID", "N/A")
        nvd_link = (
            f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            if cve_id != "N/A"
            else "Link unavailable"
        )

        title = f"🚨 New CISA KEV Entry: {cve_id}"
        embed = discord.Embed(
            title=title,
            description=kev_data.get("shortDescription", "No description available."),
            url=nvd_link,
            color=discord.Color.dark_red(),
        )

        embed.add_field(
            name="Vulnerability Name",
            value=kev_data.get("vulnerabilityName", "N/A"),
            inline=False,
        )
        embed.add_field(
            name="Vendor/Project",
            value=kev_data.get("vendorProject", "N/A"),
            inline=True,
        )
        embed.add_field(
            name="Product", value=kev_data.get("product", "N/A"), inline=True
        )
        embed.add_field(
            name="Date Added", value=kev_data.get("dateAdded", "N/A"), inline=True
        )
        embed.add_field(
            name="Required Action",
            value=kev_data.get("requiredAction", "N/A"),
            inline=False,
        )
        embed.add_field(
            name="Due Date", value=kev_data.get("dueDate", "N/A"), inline=True
        )
        embed.add_field(
            name="Known Ransomware Use",
            value=kev_data.get("knownRansomwareCampaignUse", "N/A"),
            inline=True,
        )

        if notes := kev_data.get("notes", ""):
            notes_display = f"{notes[:1020]}..." if len(notes) > 1024 else notes
            embed.add_field(name="Notes", value=notes_display, inline=False)

        embed.set_footer(text="Source: CISA Known Exploited Vulnerabilities Catalog")
        embed.timestamp = discord.utils.utcnow()

        return embed

    async def on_connect(self):
        """Called when the bot successfully connects to the Discord Gateway."""
        logger.info(
            f"Successfully connected to Discord Gateway. Shard ID: {self.shard_id}"
        )

    async def on_disconnect(self):
        """Called when the bot loses connection to the Discord Gateway."""
        logger.warning(
            f"Disconnected from Discord Gateway unexpectedly. Shard ID: {self.shard_id}. Will attempt to reconnect."
        )

    async def on_resumed(self):
        """Called when the bot successfully resumes a session after a disconnect."""
        logger.info(
            f"Successfully resumed Discord Gateway session. Shard ID: {self.shard_id}"
        )

    async def on_ready(self):
        """Called when the bot is fully ready and internal cache is built."""
        if not hasattr(
            self, "start_time"
        ):  # Prevent overwriting if on_ready is called multiple times (e.g., after resume)
            self.start_time = datetime.datetime.now(datetime.timezone.utc)
        logger.info(f"Logged in as {self.user.name} ({self.user.id})")
        logger.info(f"Command prefix: {self.command_prefix}")
        logger.info(f"Successfully fetched {len(self.guilds)} guilds.")
        logger.info("Bot is ready! Listening for CVEs...")

        # Activate Discord logging handler if prepared
        if self.discord_log_handler:
            root_logger = logging.getLogger()
            # Check if handler already exists
            handler_exists = any(
                h is self.discord_log_handler for h in root_logger.handlers
            )
            if not handler_exists:
                # Add a small delay before activating to potentially space out initial logs
                await asyncio.sleep(5)  # Add 5-second delay
                root_logger.addHandler(self.discord_log_handler)
                logger.info(
                    f"Discord logging handler activated for channel ID {self.discord_log_handler.channel_id}."
                )
            else:
                logger.debug("Discord logging handler already active.")
        else:
            logger.warning(
                "Discord log handler was not prepared (self.discord_log_handler is None), cannot activate."
            )

    async def on_guild_join(self, guild: discord.Guild):
        """Called when the bot joins a new guild."""
        logger.info(
            f"Joined guild: {guild.name} ({guild.id}). Owner: {guild.owner} ({guild.owner_id}). Members: {guild.member_count}"
        )
        # Optional: Send a welcome message to the guild owner or a default channel

    async def on_guild_remove(self, guild: discord.Guild):
        """Called when the bot is removed from a guild."""
        logger.info(f"Removed from guild: {guild.name} ({guild.id}).")
        # Optional: Clean up any guild-specific configurations from the database

    async def on_message(self, message: discord.Message):
        """Process messages to detect and report CVEs based on configuration."""
        if message.author.bot:
            return  # Ignore bots

        if not message.guild:
            return  # Ignore DMs

        if not self.cve_monitor or not self.db:
            logger.debug(
                "CVE Monitor or DB not initialized, skipping on_message processing."
            )
            return  # Bot components not ready

        # Increment message processing stat
        async with self.stats_lock:
            self.stats_messages_processed += 1

        # Find potential CVEs
        potential_cves = re.findall(CVEMonitor.CVE_REGEX, message.content)
        if not potential_cves:
            return  # No CVEs found

        guild_id = message.guild.id
        channel_id = message.channel.id

        # --- Check Configuration ---
        guild_config = self.db.get_cve_guild_config(guild_id)
        if not guild_config or not guild_config.get("enabled"):
            logger.debug(
                f"Global CVE monitoring disabled for guild {guild_id}. Skipping message {message.id}."
            )
            return  # Global monitoring disabled for this guild

        channel_config = self.db.get_cve_channel_config(guild_id, channel_id)
        if not channel_config or not channel_config.get("enabled"):
            logger.debug(
                f"CVE monitoring disabled for channel {channel_id} in guild {guild_id}. Skipping message {message.id}."
            )
            return  # Channel-specific monitoring disabled
        # --- End Configuration Check ---

        logger.info(
            f"Detected {len(potential_cves)} potential CVE(s) in message {message.id} in G:{guild_id}/C:{channel_id}"
        )

        # Process unique CVEs found
        unique_cves = sorted(
            list(set(potential_cves)), key=lambda x: potential_cves.index(x)
        )
        processed_count = 0
        now = datetime.datetime.now(datetime.timezone.utc)
        cache_expiry_time = now - datetime.timedelta(
            seconds=self.RECENT_CVE_CACHE_SECONDS
        )

        # Opportunistic Cache Cleanup (Remove expired entries)
        # Doing this less frequently might be better, but simple for now
        expired_keys = [
            key
            for key, ts in self.recently_processed_cves.items()
            if ts < cache_expiry_time
        ]
        for key in expired_keys:
            try:
                del self.recently_processed_cves[key]
                logger.debug(f"Removed expired CVE cache entry: {key}")
            except KeyError:
                pass  # Ignore if already deleted by concurrent process

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
                break  # Stop processing this message

            try:
                # --- Normalize CVE ID --- #
                # Ensure uppercase and hyphens for API calls and caching
                cve_id = cve_id_raw.upper().replace(" ", "-")
                # --- End Normalization ---

                cache_key = (channel_id, cve_id)

                # --- Cache Check ---
                last_processed_time = self.recently_processed_cves.get(cache_key)
                if last_processed_time and last_processed_time > cache_expiry_time:
                    logger.debug(
                        f"Skipping recently processed CVE {cve_id} in channel {channel_id} (Cached at {last_processed_time})."
                    )
                    continue  # Skip this CVE, already processed recently
                # --- End Cache Check ---

                # Increment lookup count AFTER cache check passes
                async with self.stats_lock:
                    self.stats_cve_lookups += 1

                # Fetch CVE data (this handles VulnCheck/NVD)
                cve_data = await self.cve_monitor.get_cve_data(cve_id)
                if not cve_data:
                    logger.warning(
                        f"No data found for {cve_id} mentioned in message {message.id}."
                    )
                    # Maybe increment an error/not_found counter here?
                    continue  # Skip this CVE
                else:
                    # Assume NVD success if data is found (simplification)
                    async with self.stats_lock:
                        self.stats_nvd_fallback_success += 1

                # --- Check Severity Threshold ---
                min_severity_str = guild_config.get("severity_threshold", "all")
                passes_threshold, cve_severity_str = (
                    self.cve_monitor.check_severity_threshold(
                        cve_data, min_severity_str
                    )
                )
                if not passes_threshold:
                    logger.info(
                        f"CVE {cve_id} (Severity: {cve_severity_str}) does not meet threshold '{min_severity_str}' for guild {guild_id}. Skipping alert."
                    )
                    continue
                # --- End Severity Check ---

                # Determine verbosity
                is_verbose = self.db.get_effective_verbosity(guild_id, channel_id)
                logger.debug(
                    f"Effective verbosity for G:{guild_id}/C:{channel_id} = {is_verbose}"
                )

                # Create and send CVE embed
                cve_embed = self.cve_monitor.create_cve_embed(
                    cve_data, verbose=is_verbose
                )
                await message.channel.send(embed=cve_embed)
                processed_count += 1
                logger.info(
                    f"Sent alert for {cve_id} (Severity: {cve_severity_str}, Verbose: {is_verbose}) from message {message.id}."
                )

                # --- Update Cache on Success ---
                self.recently_processed_cves[cache_key] = now
                # --- End Update Cache ---

                await asyncio.sleep(1.0)  # Sleep AFTER sending CVE embed

                # Check KEV status
                kev_status = None  # Initialize kev_status
                try:
                    kev_status = await self.cve_monitor.check_kev(cve_id)
                except Exception as kev_err:
                    logger.error(
                        f"Error checking KEV status for {cve_id}: {kev_err}",
                        exc_info=True,
                    )
                    async with self.stats_lock:
                        self.stats_api_errors_kev += 1

                if kev_status:
                    kev_embed = self.cve_monitor.create_kev_status_embed(
                        cve_id, kev_status, verbose=is_verbose
                    )
                    await message.channel.send(embed=kev_embed)
                    logger.info(
                        f"Sent KEV status for {cve_id} (Verbose: {is_verbose}) from message {message.id}."
                    )
                    # No need to update cache again here, CVE embed send was enough
                    await asyncio.sleep(1.0)  # Sleep AFTER sending KEV embed

            except discord.Forbidden:
                logger.error(
                    f"Missing permissions to send message/embed in channel {channel_id} (Guild: {guild_id}) for CVE {cve_id}."
                )
                break  # Stop processing this message if permissions fail
            except discord.HTTPException as e:
                logger.error(
                    f"HTTP error sending embed for {cve_id} in channel {channel_id} (Guild: {guild_id}): {e}"
                )
                # Could increment a generic discord error stat here if needed
                # Continue to next CVE potentially
            except NVDRateLimitError as e:
                logger.error(f"NVD rate limit hit processing {cve_id}: {e}")
                async with self.stats_lock:
                    self.stats_rate_limits_hit_nvd += (
                        1  # Use the specific rate limit counter
                    )
                    self.stats_api_errors_nvd += (
                        1  # Also count as a general NVD API error
                    )
                continue  # Allow processing of other CVEs if possible
            except Exception as e:
                logger.error(
                    f"Unexpected error processing CVE {cve_id} from message {message.id}: {e}",
                    exc_info=True,
                )
                # Increment a generic error counter? Need more specific API error counters maybe.
                # For now, let's assume this might be an NVD error if it wasn't caught above
                async with self.stats_lock:
                    self.stats_api_errors_nvd += 1
                # Continue to next CVE potentially

    async def on_app_command_error(
        self, interaction: discord.Interaction, error: app_commands.AppCommandError
    ):
        """Global error handler for application (slash) commands."""
        command_name = (
            interaction.command.name if interaction.command else "Unknown Command"
        )
        user = interaction.user
        guild = interaction.guild
        channel = interaction.channel

        # Safely get guild/channel info for logging
        guild_name = guild.name if guild else "DM"
        guild_id = guild.id if guild else "N/A"
        # Use getattr for channel name as some types (like DMChannel) lack it
        channel_name = getattr(channel, "name", "DM/Unknown Channel")
        channel_id = channel.id if channel else "N/A"

        log_message = (
            f"App Command Error in command '{command_name}' "
            f"(User: {user} ({user.id}), Guild: {guild_name} ({guild_id}), "
            f"Channel: {channel_name} ({channel_id})): {error}"
        )

        if isinstance(error, app_commands.CommandNotFound):
            logger.warning(
                f"CommandNotFound error suppressed: {log_message}"
            )  # Usually not an issue unless commands aren't syncing
            # Don't need to inform user, Discord handles this
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
                # Also safely access guild/channel id here
                logger.error(
                    f"Cannot even send error message about BotMissingPermissions in channel {channel_id} (Guild: {guild_id})"
                )
        elif isinstance(error, app_commands.CheckFailure):
            # This covers custom checks failing (e.g., @app_commands.check decorators)
            logger.warning(f"CheckFailure: {log_message}")
            # Provide a generic message or tailor based on check type if needed
            await interaction.response.send_message(
                "❌ You do not meet the requirements to use this command.",
                ephemeral=True,
            )
        else:
            # Log other/unexpected errors
            logger.error(f"Unhandled App Command Error: {log_message}", exc_info=error)
            try:
                # Send a generic error message if possible
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

        # Increment error counter using the error type name
        error_type_name = type(error).__name__
        async with self.stats_lock:
            self.stats_app_command_errors[error_type_name] += 1

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

                # Set the logging level for this handler
                discord_handler.setLevel(
                    logging.INFO
                )  # Only send INFO and above to Discord

                # Add the custom filter to prevent discord.http logs from being sent to Discord
                ignore_filter = IgnoreHttpRateLimitFilter()
                discord_handler.addFilter(ignore_filter)

                # Store the handler but don't add it yet
                self.discord_log_handler = discord_handler
                # root_logger.addHandler(discord_handler)
                logging.info(
                    # f"Successfully added Discord logging handler for channel ID {log_channel_id}"
                    f"Discord logging handler prepared for channel ID {log_channel_id}. Will activate on_ready."
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
