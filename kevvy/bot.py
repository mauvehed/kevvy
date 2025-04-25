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
from typing import Dict, Any
from .discord_log_handler import DiscordLogHandler
import datetime

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
        self.start_time: datetime.datetime = datetime.datetime.utcnow()

        # --- Statistics Counters --- Added Section
        self.stats_lock = asyncio.Lock() # Lock for thread-safe counter updates
        self.stats_cve_lookups = 0
        self.stats_kev_alerts_sent = 0
        self.stats_messages_processed = 0
        self.stats_vulncheck_success = 0
        self.stats_api_errors_vulncheck = 0
        self.stats_nvd_fallback_success = 0
        self.stats_rate_limits_nvd = 0
        self.stats_api_errors_nvd = 0
        # --- End Statistics Counters --- Added Section

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
            'kevvy.cogs.cve_lookup',
            'kevvy.cogs.cve_config',
            # Add other cogs here if needed
        ]
        self.loaded_cogs = [] # Reset on setup
        for extension in initial_extensions:
            try:
                await self.load_extension(extension)
                logger.info(f"Successfully loaded extension: {extension}")
                self.loaded_cogs.append(extension)
            except commands.ExtensionError as e:
                logger.error(f"Failed to load extension {extension}: {e}", exc_info=True)
            except Exception as e:
                 logger.error(f"An unexpected error occurred loading extension {extension}: {e}", exc_info=True)

        # Sync the commands
        await self.tree.sync()
        logging.info(f"Synced application commands.")

        # Start background tasks
        self.check_cisa_kev_feed.start()
        if self.kevvy_web_url:
             self.report_status_task.start()

    async def close(self):
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
        logging.info("Bot closed.")

    @tasks.loop(hours=1)
    async def check_cisa_kev_feed(self):
        """Periodically checks the CISA KEV feed for new entries and sends to configured guilds."""
        if not self.cisa_kev_client or not self.db:
            logger.debug("CISA KEV client or DB not initialized, skipping check.")
            return

        try:
            logger.info("Running periodic CISA KEV check...")
            new_entries = await self.cisa_kev_client.get_new_kev_entries()

            if not new_entries:
                logger.info("No new KEV entries found.")
                return

            logger.info(f"Found {len(new_entries)} new KEV entries. Checking configured guilds...")
            enabled_configs = self.db.get_enabled_kev_configs()

            if not enabled_configs:
                logger.info("No guilds have KEV monitoring enabled.")
                return

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
                        # Increment stats counter after successful send
                        async with self.stats_lock:
                            self.stats_kev_alerts_sent += 1
                        await asyncio.sleep(0.75)
                    except discord.Forbidden:
                         logger.error(f"Missing permissions to send message in CISA KEV channel {channel_id} (Guild: {guild_id})")
                         break
                    except discord.HTTPException as e:
                         logger.error(f"Failed to send CISA KEV embed for {entry.get('cveID', 'Unknown CVE')} to channel {channel_id} (Guild: {guild_id}): {e}")
                    except Exception as e:
                         logger.error(f"Unexpected error sending KEV embed for {entry.get('cveID', 'Unknown CVE')} (Guild: {guild_id}): {e}", exc_info=True)
                await asyncio.sleep(2)

        except Exception as e:
            logger.error(f"Error during CISA KEV check loop: {e}", exc_info=True)

    @check_cisa_kev_feed.before_loop
    async def before_kev_check(self):
        """Ensures the bot is ready before the loop starts."""
        await self.wait_until_ready()
        logger.info("Bot is ready, starting CISA KEV monitoring loop.")

    @tasks.loop(minutes=5)
    async def report_status_task(self):
        """Periodically sends status and basic stats to the kevvy-web server."""
        if not self.kevvy_web_url or not self.kevvy_web_api_key or not self.http_session:
            logger.debug("Web reporting skipped: URL, API key, or HTTP session not available.")
            return

        logger.debug("Preparing status report for kevvy-web...")

        # Calculate uptime
        now = datetime.datetime.utcnow()
        uptime_delta = now - self.start_time
        uptime_seconds = int(uptime_delta.total_seconds())

        # Prepare status data
        status_data = {
            "timestamp": now.isoformat(),
            "bot_id": self.user.id if self.user else None,
            "bot_name": self.user.name if self.user else "Unknown",
            "guild_count": len(self.guilds),
            "latency_ms": round(self.latency * 1000, 2) if self.latency else None,
            "uptime_seconds": uptime_seconds,
            "shard_id": self.shard_id if self.shard_id is not None else 0,
            "shard_count": self.shard_count if self.shard_count is not None else 1,
            "is_ready": self.is_ready(),
            "is_closed": self.is_closed()
        }

        # Prepare stats data (Read current counters)
        async with self.stats_lock:
            cve_lookups = self.stats_cve_lookups
            kev_alerts = self.stats_kev_alerts_sent
            messages_processed = self.stats_messages_processed
            vulncheck_success = self.stats_vulncheck_success
            api_errors_vulncheck = self.stats_api_errors_vulncheck
            nvd_fallback_success = self.stats_nvd_fallback_success
            rate_limits_nvd = self.stats_rate_limits_nvd
            api_errors_nvd = self.stats_api_errors_nvd
            # Reset counters after reading
            self.stats_cve_lookups = 0
            self.stats_kev_alerts_sent = 0
            self.stats_messages_processed = 0
            self.stats_vulncheck_success = 0
            self.stats_api_errors_vulncheck = 0
            self.stats_nvd_fallback_success = 0
            self.stats_rate_limits_nvd = 0
            self.stats_api_errors_nvd = 0

        stats_data = {
            "timestamp": now.isoformat(),
            "cve_lookups_since_last": cve_lookups,
            "kev_alerts_sent_since_last": kev_alerts,
            "messages_processed_since_last": messages_processed,
            "vulncheck_success_since_last": vulncheck_success,
            "api_errors_vulncheck_since_last": api_errors_vulncheck,
            "nvd_fallback_success_since_last": nvd_fallback_success,
            "rate_limits_nvd_since_last": rate_limits_nvd,
            "api_errors_nvd_since_last": api_errors_nvd
        }

        # Send status
        await self._send_to_web_portal("/api/v1/status", status_data)

        # Send stats (optional, maybe less frequently in future)
        await self._send_to_web_portal("/api/v1/stats", stats_data)

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

        # Use ClientTimeout object
        request_timeout = ClientTimeout(total=10)

        try:
            # Pass the ClientTimeout object
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
            notes_display = notes[:1020] + '...' if len(notes) > 1024 else notes
            embed.add_field(name="Notes", value=notes_display, inline=False)

        embed.set_footer(text="Source: CISA Known Exploited Vulnerabilities Catalog")
        embed.timestamp = discord.utils.utcnow()

        return embed

    async def on_ready(self):
        self.start_time = datetime.datetime.utcnow()
        logging.info(f'Logged in as {self.user.name} ({self.user.id})')
        logging.info(f'Command prefix: {self.command_prefix}')
        logging.info(f'Ready! Listening for CVEs...')

        await self._setup_discord_logging()

        logging.info('------')

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

                # Find existing console handler to copy its formatter
                formatter = None
                for handler in root_logger.handlers:
                    if isinstance(handler, logging.StreamHandler):
                        formatter = handler.formatter
                        break

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

        # Ignore messages not in guilds for CVE auto-response check
        if not message.guild:
            await self.process_commands(message)
            return

        if not self.cve_monitor:
             logger.debug("CVEMonitor not initialized, skipping CVE scan.")
             await self.process_commands(message)
             return

        # --- Check Guild Configuration for CVE Auto-Response ---
        if not self.db:
             logger.error(f"Database unavailable during on_message for guild {message.guild.id}. Skipping CVE response check.")
             # Fallback: Should we process commands or just return?
             # Let's process commands but skip the auto-response part.
        else:
            try:
                response_mode = self.db.get_cve_response_mode(message.guild.id)

                if response_mode is None:
                    logger.debug(f"CVE auto-response disabled for guild {message.guild.id}. Skipping response.")
                    await self.process_commands(message)
                    return # Don't process CVEs in this message for auto-response

                elif response_mode == "all":
                    logger.debug(f"CVE auto-response enabled for all channels in guild {message.guild.id}.")
                    # Proceed to CVE detection

                elif response_mode.isdigit():
                    allowed_channel_id = int(response_mode)
                    if message.channel.id != allowed_channel_id:
                        logger.debug(f"CVE {message.id} found in channel {message.channel.id}, but response only allowed in {allowed_channel_id} for guild {message.guild.id}. Skipping response.")
                        await self.process_commands(message)
                        return # Don't process CVEs in this message for auto-response
                    else:
                         logger.debug(f"CVE auto-response permitted in channel {message.channel.id} for guild {message.guild.id}.")
                         # Proceed to CVE detection
                else:
                    logger.warning(f"Invalid CVE response mode '{response_mode}' found for guild {message.guild.id}. Skipping response.")
                    await self.process_commands(message)
                    return # Don't process CVEs

            except Exception as db_err:
                 logger.error(f"Error checking CVE response mode for guild {message.guild.id}: {db_err}", exc_info=True)
                 # Decide fallback behavior: maybe skip response to be safe?
                 await self.process_commands(message)
                 return

        # --- CVE Detection and Processing (only runs if checks above pass) ---
        cves_found = self.cve_monitor.find_cves(message.content)

        if not cves_found:
            await self.process_commands(message)
            return

        # Normalize CVEs to uppercase for consistent lookup
        unique_cves_upper = sorted(list(set(cve.upper() for cve in cves_found)), key=lambda x: cves_found.index(next(c for c in cves_found if c.upper() == x)))
        # Keep original case list for logging/display if needed, but use upper for processing
        original_unique_cves = sorted(list(set(cves_found)), key=lambda x: cves_found.index(x))

        guild_name = message.guild.name if message.guild else "DM"
        guild_id = message.guild.id if message.guild else "N/A"
        # Use getattr for safer access to channel name in log message
        channel_name = getattr(message.channel, 'name', f'ID:{message.channel.id}')
        channel_id = message.channel.id if message.channel else "N/A"

        logger.info(f"Found {len(unique_cves_upper)} unique CVE mentions in message {message.id} from {message.author} in {message.guild.name}/{channel_name}: {original_unique_cves}")

        embeds_to_send = []
        processed_count = 0
        # Use the uppercase list for processing
        for cve_id in unique_cves_upper:
            if processed_count >= MAX_EMBEDS_PER_MESSAGE:
                logging.warning(f"Max embeds reached for message {message.id}. Found {len(unique_cves_upper)} unique CVEs, processing first {MAX_EMBEDS_PER_MESSAGE}.")
                break

            cve_data = None
            source_used = None # Track which source succeeded
            try:
                # Increment lookup counter for each unique CVE attempted
                async with self.stats_lock:
                    self.stats_cve_lookups += 1

                if self.vulncheck_client and self.vulncheck_client.api_client:
                    logging.debug(f"Attempting VulnCheck fetch for {cve_id}")
                    try:
                        cve_data = await self.vulncheck_client.get_cve_details(cve_id)
                        if cve_data:
                            source_used = "VulnCheck"
                            async with self.stats_lock:
                                self.stats_vulncheck_success += 1 # Increment VulnCheck success
                    except Exception as e_vc:
                        logger.error(f"Error during VulnCheck API call for {cve_id}: {e_vc}", exc_info=True)
                        async with self.stats_lock:
                            self.stats_api_errors_vulncheck += 1
                        cve_data = None # Ensure cve_data is None if exception occurred
                else:
                    logging.debug("VulnCheck client not available (no API key?), skipping.")

                if not cve_data:
                    log_msg_prefix = f"VulnCheck failed for {cve_id}," if self.vulncheck_client and self.vulncheck_client.api_client else ""
                    logging.debug(f"{log_msg_prefix} Attempting NVD fetch for {cve_id} (VulnCheck unavailable or failed).")

                    if self.nvd_client:
                        try:
                            cve_data = await self.nvd_client.get_cve_details(cve_id)
                            if cve_data:
                                source_used = "NVD"
                                async with self.stats_lock:
                                    self.stats_nvd_fallback_success += 1 # Increment NVD fallback success
                        # Catch Rate Limit specifically
                        except NVDRateLimitError as e_rate_limit:
                            logger.warning(f"NVD rate limit encountered for {cve_id}: {e_rate_limit}")
                            async with self.stats_lock:
                                self.stats_rate_limits_nvd += 1
                            cve_data = None
                        # Catch other NVD client errors
                        except Exception as e_nvd:
                            logger.error(f"Error during NVD API call for {cve_id}: {e_nvd}", exc_info=True)
                            async with self.stats_lock:
                                self.stats_api_errors_nvd += 1
                            cve_data = None # Ensure cve_data is None if exception occurred
                    else:
                         logger.warning("NVD Client not available, skipping NVD lookup.")

                if cve_data:
                    # Add source info if not already present from client
                    if 'source' not in cve_data and source_used:
                         cve_data['source'] = source_used
                    embeds = await self.cve_monitor.create_cve_embed(cve_data)
                    embeds_to_send.extend(embeds)
                    processed_count += 1
                else:
                    logging.warning(f"Could not retrieve details for {cve_id} from any source.")

            except Exception as e:
                logging.error(f"Failed to process CVE {cve_id} after checking sources: {e}", exc_info=True)

            await asyncio.sleep(0.2)

        if embeds_to_send:
            logging.info(f"Sending {len(embeds_to_send)} embeds for message {message.id}")
            try:
                for i, embed in enumerate(embeds_to_send):
                    await message.channel.send(embed=embed)
                    if i < len(embeds_to_send) - 1:
                        await asyncio.sleep(0.5)

                if len(unique_cves_upper) > MAX_EMBEDS_PER_MESSAGE:
                    await message.channel.send(f"*Found {len(unique_cves_upper)} unique CVEs, showing details for the first {MAX_EMBEDS_PER_MESSAGE}.*", allowed_mentions=discord.AllowedMentions.none())
            except discord.Forbidden:
                 # Use getattr for safer access to channel name in log message
                 log_channel_name_error = getattr(message.channel, 'name', f'ID:{message.channel.id}')
                 logger.error(f"Missing permissions to send CVE response in channel {message.channel.id} ({log_channel_name_error}) in guild {message.guild.id} ({message.guild.name})")
            except discord.HTTPException as e:
                 logger.error(f"Failed to send CVE embeds for message {message.id} to channel {message.channel.id}: {e}")
            except Exception as e:
                 logger.error(f"Unexpected error sending CVE embeds for message {message.id}: {e}", exc_info=True)

        # Ensure commands are processed regardless of CVE processing result
        await self.process_commands(message)