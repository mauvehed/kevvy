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
                self.nvd_client, kev_client=self.cisa_kev_client
            )
            logger.info(
                f"Initialized CVEMonitor (KEV support: {'enabled' if self.cisa_kev_client else 'disabled'})."
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
            logger.debug(f"Attempting to load extension {i+1}: {extension}")
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
            logger.debug(f"Finished processing extension {i+1}: {extension}")

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

    @tasks.loop(minutes=5)
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
                # Keep these at top level for backward compatibility
                "loaded_cogs": self.loaded_cogs,
                "failed_cogs": self.failed_cogs,
                "timestamp_last_kev_check_success": (
                    self.timestamp_last_kev_check_success.isoformat()
                    if self.timestamp_last_kev_check_success
                    else None
                ),
                "timestamp_last_kev_alert_sent": (
                    self.timestamp_last_kev_alert_sent.isoformat()
                    if self.timestamp_last_kev_alert_sent
                    else None
                ),
                "version": self.version,
                # Also include stats in the nested structure like tasks_cog.py does
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

    @tasks.loop(hours=1)
    async def check_cisa_kev_feed(self):
        """Periodically checks CISA KEV feed for new entries and notifies configured channels."""
        if not self.cisa_kev_client or not self.db:
            logger.debug(
                "CISA KEV Client or DB not initialized, skipping KEV feed check."
            )
            return

        logger.info("Checking CISA KEV feed for new entries...")
        try:
            new_entries = await self.cisa_kev_client.get_new_kev_entries()
            # Update timestamp only after a successful fetch
            self.timestamp_last_kev_check_success = datetime.datetime.now(
                datetime.timezone.utc
            )

        except Exception as e:
            logger.error(f"CISA KEV client error during fetch: {e}", exc_info=True)
            # Record the API error using StatsManager
            await self.stats_manager.record_api_error(service="cisa", count=1)
            return  # Stop processing if fetch failed

        if not new_entries:
            logger.info("No new CISA KEV entries found.")
            return

        logger.info(f"Found {len(new_entries)} new CISA KEV entries. Processing...")
        configs = self.db.get_enabled_kev_configs()
        if not configs:
            logger.info("No guilds/channels configured for KEV alerts.")
            return

        alerts_sent_count = 0
        for entry in new_entries:
            logger.debug(f"Processing KEV entry: {entry.get('cveID')}")
            try:
                embed = self._create_kev_embed(entry)
            except Exception as e:
                logger.error(
                    f"Failed to create embed for KEV entry {entry.get('cveID')}: {e}",
                    exc_info=True,
                )
                continue  # Skip this entry if embed creation fails

            for config in configs:
                guild_id = config["guild_id"]
                channel_id = config["channel_id"]

                guild = self.get_guild(guild_id)
                if not guild:
                    logger.warning(
                        f"Could not find guild {guild_id} from KEV config, skipping."
                    )
                    continue

                channel = self.get_channel(channel_id)
                if not channel:
                    # Attempt to fetch if get_channel failed (might be due to cache)
                    try:
                        channel = await self.fetch_channel(channel_id)
                    except discord.NotFound:
                        logger.error(
                            f"Could not find CISA KEV target channel with ID: {channel_id} in guild {guild.name} ({guild_id}) even after fetch."
                        )
                        channel = None
                    except discord.Forbidden:
                        logger.error(
                            f"Missing permissions to fetch CISA KEV target channel with ID: {channel_id} in guild {guild.name} ({guild_id})."
                        )
                        channel = None
                    except Exception as e:
                        logger.error(
                            f"Error fetching CISA KEV target channel {channel_id}: {e}",
                            exc_info=True,
                        )
                        channel = None

                if channel and isinstance(channel, discord.TextChannel):
                    try:
                        await channel.send(embed=embed)
                        logger.debug(
                            f"Sent KEV alert for {entry.get('cveID')} to #{channel.name} ({channel_id}) in {guild.name} ({guild_id})"
                        )
                        # Increment alerts sent stat using StatsManager
                        await self.stats_manager.increment_kev_alerts_sent(count=1)
                        alerts_sent_count += 1
                    except discord.Forbidden:
                        logger.error(
                            f"Missing permissions to send message in CISA KEV channel {channel_id} (Guild: {guild_id})"
                        )
                    except discord.HTTPException as e:
                        logger.error(
                            f"HTTP error sending KEV alert to channel {channel_id}: {e}",
                            exc_info=True,
                        )
                    except Exception as e:
                        logger.error(
                            f"Unexpected error sending KEV alert to {channel_id}: {e}",
                            exc_info=True,
                        )
                elif not channel:
                    # Error already logged above if channel fetch failed
                    pass
                else:
                    logger.warning(
                        f"Configured CISA KEV target channel {channel_id} in guild {guild.name} ({guild_id}) is not a TextChannel."
                    )

        if alerts_sent_count > 0:
            logger.info(f"Sent {alerts_sent_count} KEV alerts.")
            self.timestamp_last_kev_alert_sent = datetime.datetime.now(
                datetime.timezone.utc
            )

    async def _post_stats(self, url, data, headers):
        """Helper method to POST stats payload to web app. Returns (status_code, response_text)."""
        async with self.http_session.post(url, json=data, headers=headers) as resp:
            resp_text = await resp.text()
            return resp.status, resp_text

    def get_uptime_string(self):
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

    def _create_kev_embed(self, kev_entry):
        """Creates a Discord embed for a KEV entry."""
        cve_id = kev_entry.get("cveID", "Unknown CVE")
        title = f"🚨 NEW CISA KEV ALERT: {cve_id}"

        # Build embed
        embed = discord.Embed(
            title=title,
            description="A new vulnerability has been added to the CISA Known Exploited Vulnerabilities (KEV) catalog.",
            color=discord.Color.red(),
        )

        # Add fields for KEV metadata
        embed.add_field(
            name="Description",
            value=kev_entry.get("shortDescription", "No description available."),
            inline=False,
        )
        embed.add_field(
            name="Vulnerability Name",
            value=kev_entry.get("vulnerabilityName", "Unknown"),
            inline=True,
        )
        embed.add_field(
            name="Vendor Product",
            value=kev_entry.get("vendorProject", "Unknown"),
            inline=True,
        )
        embed.add_field(
            name="Product", value=kev_entry.get("product", "Unknown"), inline=True
        )

        # Add dates
        added_date = kev_entry.get("dateAdded", "Unknown")
        due_date = kev_entry.get("dueDate", "Unknown")
        embed.add_field(name="Added to KEV", value=added_date, inline=True)
        embed.add_field(
            name="Remediation Due Date",
            value=due_date,
            inline=True,
        )

        # Add reference links
        cisa_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        embed.add_field(
            name="References",
            value=f"[CISA KEV Catalog]({cisa_url})\n[NVD Entry]({nvd_url})",
            inline=False,
        )

        # Set footer with timestamp
        embed.set_footer(text=f"CISA KEV Alert • {cve_id}")
        embed.timestamp = datetime.datetime.now(datetime.timezone.utc)

        return embed

    async def on_message(self, message: discord.Message):
        """Process incoming messages for CVEs and respond with info embeds."""
        # Handle commands first before any other processing
        await self.process_commands(message)

        # Skip processing if conditions not met
        if (
            message.author.bot
            or not isinstance(message.channel, discord.TextChannel)
            or not message.guild
            or not self.cve_monitor
            or not self.db
        ):
            return

        # Read necessary info for processing
        guild_id = message.guild.id
        channel_id = message.channel.id
        content = message.content

        # Count this message regardless of whether we find a CVE
        await self.stats_manager.increment_messages_processed()

        # Find CVEs in the message
        cve_matches = self.cve_monitor.find_cves(content)
        if not cve_matches:
            return  # No CVEs found

        # Check monitoring config
        try:
            guild_config = self.db.get_cve_guild_config(guild_id)
            if not guild_config or not guild_config.get("enabled", True):
                return  # Guild has monitoring disabled

            channel_config = self.db.get_cve_channel_config(guild_id, channel_id)
            if not channel_config or not channel_config.get("enabled", True):
                return  # Channel has monitoring disabled

            verbose = self.db.get_effective_verbosity(guild_id, channel_id)
            guild_severity_threshold = guild_config.get("severity_threshold", "all")
        except Exception as e:
            logger.error(f"Error checking CVE monitoring config: {e}", exc_info=True)
            return

        # Process unique CVEs
        embed_count = 0
        processed_cves = set()

        for cve_id in cve_matches:
            # Skip if already processed or hit embed limit
            if cve_id in processed_cves or embed_count >= MAX_EMBEDS_PER_MESSAGE:
                continue

            processed_cves.add(cve_id)

            # Skip if recently processed (rate limiting)
            cache_key = (channel_id, cve_id)
            now = datetime.datetime.now(datetime.timezone.utc)

            if cache_key in self.recently_processed_cves:
                cache_time = self.recently_processed_cves[cache_key]
                if (now - cache_time).total_seconds() < self.RECENT_CVE_CACHE_SECONDS:
                    logger.debug(
                        f"Skipping {cve_id} - processed recently in channel {channel_id}"
                    )
                    continue

            try:
                # Get and validate CVE data
                cve_data = await self.cve_monitor.get_cve_data(cve_id)
                if not cve_data:
                    continue

                # Check severity threshold with the correct parameter name (min_threshold_str)
                try:
                    passes_threshold, severity = (
                        self.cve_monitor.check_severity_threshold(
                            cve_data, min_threshold_str=guild_severity_threshold
                        )
                    )
                except Exception as e:
                    logger.warning(f"Error checking severity for {cve_id}: {str(e)}")
                    # Default to passing threshold if we can't check
                    passes_threshold, severity = True, "Unknown"

                if not passes_threshold:
                    logger.debug(
                        f"CVE {cve_id} with {severity} severity below threshold {guild_severity_threshold}"
                    )
                    continue

                # Check KEV status
                kev_data = None
                try:
                    kev_data = await self.cve_monitor.check_kev(cve_id)
                except Exception as e:
                    logger.warning(f"Error checking KEV status for {cve_id}: {str(e)}")
                    await self.stats_manager.record_api_error(service="kev")

                # Create embed - the correct signature only has cve_data and verbose parameters
                embed = self.cve_monitor.create_cve_embed(cve_data, verbose=verbose)

                await message.channel.send(embed=embed)
                self.recently_processed_cves[cache_key] = now
                embed_count += 1

                # If we found KEV data, send a separate KEV embed if the method exists
                if kev_data and hasattr(self.cve_monitor, "create_kev_status_embed"):
                    try:
                        kev_embed = self.cve_monitor.create_kev_status_embed(
                            cve_id, kev_data, verbose=verbose
                        )
                        await message.channel.send(embed=kev_embed)
                    except Exception as e:
                        logger.warning(
                            f"Failed to send KEV info for {cve_id}: {str(e)}"
                        )

            except discord.Forbidden:
                logger.error(
                    f"Missing permissions in channel {channel_id} (Guild: {guild_id})"
                )
                break  # Stop trying if we don't have permissions

            except discord.HTTPException as e:
                logger.error(f"Discord HTTP error for {cve_id}: {str(e)}")
                continue

            except NVDRateLimitError as e:
                logger.error(f"NVD API rate limit hit: {str(e)}")
                await self.stats_manager.record_nvd_rate_limit_hit()

                # Try to notify users about rate limit
                try:
                    warning_embed = discord.Embed(
                        title="⚠️ NVD API Rate Limit Reached",
                        description="The National Vulnerability Database (NVD) API rate limit has been reached. Please try again later.",
                        color=discord.Color.gold(),
                    )
                    await message.channel.send(embed=warning_embed)
                except Exception as e:
                    logger.warning(f"Failed to send rate limit warning: {str(e)}")
                break

            except Exception as e:
                logger.error(f"Error processing {cve_id}: {str(e)}", exc_info=True)
                continue
