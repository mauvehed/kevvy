import discord
from discord.ext import commands, tasks
from discord import app_commands
import aiohttp
from .cve_monitor import CVEMonitor
from .nvd_client import NVDClient
from .vulncheck_client import VulnCheckClient
from .cisa_kev_client import CisaKevClient
from .db_utils import KEVConfigDB
import logging
import os
import asyncio
from typing import Dict, Any
from .discord_log_handler import DiscordLogHandler

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

        # VulnCheck doesn't need session, can init here
        self.vulncheck_client = VulnCheckClient(api_key=vulncheck_api_token)

    async def setup_hook(self):
        self.http_session = aiohttp.ClientSession()
        logger.info("Created aiohttp.ClientSession.")

        # Initialize NVD client now that we have a session
        self.nvd_client = NVDClient(session=self.http_session, api_key=os.getenv('NVD_API_KEY'))
        logger.info("Initialized NVDClient.")

        # Initialize monitor components now that NVDClient exists
        if self.nvd_client:
            self.cve_monitor = CVEMonitor(self.nvd_client)
            logger.info("Initialized CVEMonitor.")
        else:
            logger.error("Could not initialize CVEMonitor because NVDClient failed to initialize.")

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

        # Initialize monitor components now that NVDClient exists
        if self.nvd_client:
            self.cve_monitor = CVEMonitor(self.nvd_client, kev_client=self.cisa_kev_client)
            logger.info("Initialized CVEMonitor with KEV support.")
        else:
            logger.error("Could not initialize CVEMonitor because NVDClient failed to initialize.")

        # Load Cogs
        initial_extensions = [
            'kevvy.cogs.kev_commands'
            # Add other cogs here if needed
        ]
        for extension in initial_extensions:
            try:
                await self.load_extension(extension)
                logger.info(f"Successfully loaded extension: {extension}")
            except commands.ExtensionError as e:
                logger.error(f"Failed to load extension {extension}: {e}", exc_info=True)
            except Exception as e:
                 logger.error(f"An unexpected error occurred loading extension {extension}: {e}", exc_info=True)

        # Sync the commands
        await self.tree.sync()
        logging.info(f"Synced application commands.")

        # Start background tasks
        self.check_cisa_kev_feed.start()

    async def close(self):
        logging.info("Closing bot resources...")
        if self.check_cisa_kev_feed.is_running():
            self.check_cisa_kev_feed.cancel()
            logging.info("Cancelled CISA KEV monitoring task.")

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
        logging.info(f'Logged in as {self.user.name} ({self.user.id})')
        logging.info(f'Command prefix: {self.command_prefix}')
        logging.info(f'Ready! Listening for CVEs...')

        # --- Setup Discord Logging Handler ---
        log_channel_id_str = os.getenv('LOGGING_CHANNEL_ID')
        if log_channel_id_str:
            try:
                log_channel_id = int(log_channel_id_str)
                root_logger = logging.getLogger()
                
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

                # Set level (optional, default is NOTSET, inheriting root logger level)
                # discord_handler.setLevel(logging.INFO) 
                
                root_logger.addHandler(discord_handler)
                logging.info(f"Successfully added Discord logging handler for channel ID {log_channel_id}")
            except ValueError:
                logging.error(f"Invalid LOGGING_CHANNEL_ID: '{log_channel_id_str}'. Must be an integer.")
            except Exception as e:
                logging.error(f"Failed to set up Discord logging handler: {e}", exc_info=True)
        else:
            logging.info("LOGGING_CHANNEL_ID not set, skipping Discord log handler setup.")
        
        logging.info('------')

    async def on_message(self, message: discord.Message):
        if message.author == self.user:
            return

        if not self.cve_monitor:
             logger.debug("CVEMonitor not initialized, skipping CVE scan.")
             await self.process_commands(message)
             return

        cves_found = self.cve_monitor.find_cves(message.content)

        if not cves_found:
            await self.process_commands(message)
            return

        unique_cves = sorted(list(set(cves_found)), key=lambda x: cves_found.index(x))

        embeds_to_send = []
        processed_count = 0
        for cve in unique_cves:
            if processed_count >= MAX_EMBEDS_PER_MESSAGE:
                logging.warning(f"Max embeds reached for message {message.id}. Found {len(unique_cves)} unique CVEs, processing first {MAX_EMBEDS_PER_MESSAGE}.")
                break

            cve_data = None
            try:
                if self.vulncheck_client.api_client:
                    logging.debug(f"Attempting VulnCheck fetch for {cve}")
                    cve_data = await self.vulncheck_client.get_cve_details(cve)
                else:
                    logging.debug("VulnCheck client not available (no API key?), skipping.")

                if not cve_data:
                    if self.vulncheck_client.api_client:
                        logging.debug(f"VulnCheck failed for {cve}, attempting NVD fallback.")
                    else:
                        logging.debug(f"Attempting NVD fetch for {cve} (VulnCheck unavailable).")

                    if self.nvd_client:
                        cve_data = await self.nvd_client.get_cve_details(cve)
                    else:
                         logger.warning("NVD Client not available, skipping NVD lookup.")

                if cve_data:
                    embeds = await self.cve_monitor.create_cve_embed(cve_data)
                    embeds_to_send.extend(embeds)
                    processed_count += 1
                else:
                    logging.warning(f"Could not retrieve details for {cve} from any source.")

            except Exception as e:
                logging.error(f"Failed to process CVE {cve} after checking sources: {e}", exc_info=True)

            await asyncio.sleep(0.2)

        if embeds_to_send:
            logging.info(f"Sending {len(embeds_to_send)} embeds for message {message.id}")
            for i, embed in enumerate(embeds_to_send):
                await message.channel.send(embed=embed)
                if i < len(embeds_to_send) - 1:
                    await asyncio.sleep(0.5)

            if len(unique_cves) > MAX_EMBEDS_PER_MESSAGE:
                await message.channel.send(f"*Found {len(unique_cves)} unique CVEs, showing details for the first {MAX_EMBEDS_PER_MESSAGE}.*", allowed_mentions=discord.AllowedMentions.none())

        await self.process_commands(message)