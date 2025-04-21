import discord
from discord.ext import commands, tasks # Import tasks
from discord import app_commands # Import app_commands
from .cve_monitor import CVEMonitor
from .nvd_client import NVDClient
from .vulncheck_client import VulnCheckClient # Import VulnCheckClient
from .cisa_kev_client import CisaKevClient # Import CisaKevClient
from .db_utils import KEVConfigDB # Import DB utility
import logging
import os
import asyncio # Import asyncio for sleep
import aiohttp # Import aiohttp
from typing import Dict, Any # Import Dict, Any

# Limit the number of embeds sent for a single message
MAX_EMBEDS_PER_MESSAGE = 5
# Default polling interval for CISA KEV feed (1 hour)
DEFAULT_CISA_KEV_INTERVAL = 3600 

logger = logging.getLogger(__name__) # Define logger at module level

class SecurityBot(commands.Bot):
    def __init__(self, nvd_api_key: str | None, vulncheck_api_token: str | None):
        intents = discord.Intents.default()
        intents.message_content = True # Needed for message content access
        intents.guilds = True # Needed for guild information access
        prefix = os.getenv('DISCORD_COMMAND_PREFIX', '!')
        super().__init__(command_prefix=prefix, intents=intents, enable_debug_events=True)
        
        # Declare session & clients, initialize later
        self.http_session: aiohttp.ClientSession | None = None
        self.cisa_kev_client: CisaKevClient | None = None
        self.db: KEVConfigDB | None = None # DB Util instance

        # Initialize other data source clients 
        self.nvd_client = NVDClient(session=self.http_session, api_key=nvd_api_key)
        self.vulncheck_client = VulnCheckClient(api_key=vulncheck_api_token)
        
        # Initialize monitor components
        self.cve_monitor = CVEMonitor(self.nvd_client)
        
        # --- CISA KEV Monitoring Configuration --- REMOVED ENV VAR LOGIC
        # Configuration is now handled per-guild via slash commands and DB
        # -----------------------------------------
        
        # Create the main command group - REMOVED (Moved to Cog)
        # self.kev_group = app_commands.Group(name="kev", description="Manage CISA KEV monitoring for this server.")

    async def setup_hook(self):
        # Create the HTTP session 
        self.http_session = aiohttp.ClientSession()
        logger.info("Created aiohttp.ClientSession.")

        # Initialize CISA client
        # Pass the DB instance for persistence
        if self.db and self.http_session: # Ensure both DB and session are ready
             self.cisa_kev_client = CisaKevClient(session=self.http_session, db=self.db)
             logger.info("Initialized CisaKevClient with DB persistence.")
        else:
            logger.error("Could not initialize CisaKevClient due to missing DB or HTTP session.")
            self.cisa_kev_client = None # Ensure it's None if init fails
        
        # Initialize Database utility
        try:
            self.db = KEVConfigDB() # Use default path
            logger.info("Initialized KEV Configuration Database.")
        except Exception as e:
             logger.error(f"Failed to initialize KEV Configuration Database: {e}", exc_info=True)
             # Bot can continue, but KEV features won't work
             self.db = None

        # Register KEV commands to the group - REMOVED (Handled by Cog loading)
        # self.kev_group.add_command(self.kev_enable_command)
        # self.kev_group.add_command(self.kev_disable_command)
        # self.kev_group.add_command(self.kev_status_command)
        
        # Add the command group to the bot's tree - REMOVED (Handled by Cog loading)
        # self.tree.add_command(self.kev_group)

        # Load Cogs
        initial_extensions = [
            'cve_search.cogs.kev_commands' # Path to the new cog file
        ]
        for extension in initial_extensions:
            try:
                await self.load_extension(extension)
                logger.info(f"Successfully loaded extension: {extension}")
            except commands.ExtensionError as e:
                logger.error(f"Failed to load extension {extension}: {e}", exc_info=True)
            except Exception as e:
                 logger.error(f"An unexpected error occurred loading extension {extension}: {e}", exc_info=True)

        # Sync the commands (syncs commands from loaded cogs too)
        await self.tree.sync() 
        logging.info(f"Synced application commands.")
        
        # Start background tasks
        # Start CISA KEV task unconditionally; it will check DB internally
        self.check_cisa_kev_feed.start()
        # if self.cisa_kev_channel_id: # OLD LOGIC
        #     self.check_cisa_kev_feed.change_interval(seconds=self.cisa_kev_interval) 
        #     self.check_cisa_kev_feed.start()
        # else:
        #     logger.info("CISA KEV monitoring task not started due to missing/invalid channel ID.")

    async def close(self):
        """Ensure cleanup happens correctly."""
        logging.info("Closing bot resources...")
        if self.check_cisa_kev_feed.is_running():
            self.check_cisa_kev_feed.cancel()
            logging.info("Cancelled CISA KEV monitoring task.")
        
        if self.http_session:
            await self.http_session.close() # Close the aiohttp session
            logging.info("Closed aiohttp session.")
        
        if self.db:
            self.db.close() # Close the database connection
            logging.info("Closed KEV Config Database connection.")
        
        await super().close() # Call the parent class's close method
        logging.info("Bot closed.")

    # --- KEV Slash Commands --- REMOVED (Moved to Cog) 
    # @app_commands.checks.has_permissions(manage_guild=True)
    # @kev_group.command(name="enable", description="Enable KEV alerts in the specified channel.")
    # async def kev_enable_command(self, interaction: discord.Interaction, channel: discord.TextChannel):
    # ... (rest of command methods removed) ...
    # --- End KEV Slash Commands ---

    @tasks.loop(hours=1) # Check hourly by default
    async def check_cisa_kev_feed(self):
        """Periodically checks the CISA KEV feed for new entries and sends to configured guilds."""
        if not self.cisa_kev_client or not self.db:
            logger.debug("CISA KEV client or DB not initialized, skipping check.")
            return
            
        try:
            logger.info("Running periodic CISA KEV check...") # Changed level to INFO
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
                    continue # Skip this guild, maybe log to disable it?
                if not isinstance(target_channel, discord.TextChannel):
                     logger.error(f"CISA KEV target channel {channel_id} in guild {guild.name} ({guild_id}) is not a TextChannel.")
                     continue

                logger.info(f"Sending {len(new_entries)} new KEV entries to channel #{target_channel.name} in guild {guild.name}")
                for entry in new_entries:
                    embed = self._create_kev_embed(entry)
                    try:
                        await target_channel.send(embed=embed)
                        await asyncio.sleep(0.75) # Slightly longer delay when sending to potentially multiple channels
                    except discord.Forbidden:
                         logger.error(f"Missing permissions to send message in CISA KEV channel {channel_id} (Guild: {guild_id})")
                         # Should we disable config for this guild after repeated failures?
                         break # Stop trying for this channel on permissions error
                    except discord.HTTPException as e:
                         logger.error(f"Failed to send CISA KEV embed for {entry.get('cveID', 'Unknown CVE')} to channel {channel_id} (Guild: {guild_id}): {e}")
                    except Exception as e:
                         logger.error(f"Unexpected error sending KEV embed for {entry.get('cveID', 'Unknown CVE')} (Guild: {guild_id}): {e}", exc_info=True)
                await asyncio.sleep(2) # Small delay before processing the next guild

        except Exception as e:
            logger.error(f"Error during CISA KEV check loop: {e}", exc_info=True)

    @check_cisa_kev_feed.before_loop
    async def before_kev_check(self):
        """Ensures the bot is ready before the loop starts."""
        await self.wait_until_ready()
        logger.info("Bot is ready, starting CISA KEV monitoring loop.")
        # Perform initial population without sending messages - REMOVED
        # Initial population is now handled by CisaKevClient.__init__ loading from DB
        # Ensure client is initialized before initial population
        # if not self.cisa_kev_client:
        #     # This check might be less critical now as task starts after setup_hook
        #     # where client is initialized, but doesn't hurt.
        #     logger.error("CISA KEV client not initialized, skipping initial population.")
        #     return
            
        # try:
        #     logger.info("Performing initial population of CISA KEV seen list...")
        #     await self.cisa_kev_client.get_new_kev_entries() # REMOVED CALL
        #     logger.info("Initial CISA KEV population complete.")
        # except Exception as e:
        #     logger.error(f"Error during initial CISA KEV population: {e}", exc_info=True)

    def _create_kev_embed(self, kev_data: Dict[str, Any]) -> discord.Embed:
        """Creates a Discord embed for a CISA KEV entry."""
        cve_id = kev_data.get('cveID', 'N/A')
        nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id != 'N/A' else "Link unavailable"
        
        title = f"🚨 New CISA KEV Entry: {cve_id}"
        embed = discord.Embed(
            title=title,
            description=kev_data.get('shortDescription', 'No description available.'),
            url=nvd_link, # Link title to NVD page
            color=discord.Color.dark_red() 
        )

        embed.add_field(name="Vulnerability Name", value=kev_data.get('vulnerabilityName', 'N/A'), inline=False)
        embed.add_field(name="Vendor/Project", value=kev_data.get('vendorProject', 'N/A'), inline=True)
        embed.add_field(name="Product", value=kev_data.get('product', 'N/A'), inline=True)
        embed.add_field(name="Date Added", value=kev_data.get('dateAdded', 'N/A'), inline=True)
        embed.add_field(name="Required Action", value=kev_data.get('requiredAction', 'N/A'), inline=False)
        embed.add_field(name="Due Date", value=kev_data.get('dueDate', 'N/A'), inline=True)
        embed.add_field(name="Known Ransomware Use", value=kev_data.get('knownRansomwareCampaignUse', 'N/A'), inline=True)
        
        notes = kev_data.get('notes', '')
        if notes:
            # Limit notes length
            notes = notes[:1020] + '...' if len(notes) > 1024 else notes
            embed.add_field(name="Notes", value=notes, inline=False)

        embed.set_footer(text="Source: CISA Known Exploited Vulnerabilities Catalog")
        embed.timestamp = discord.utils.utcnow() # Add timestamp

        return embed

    async def on_ready(self):
        logging.info(f'Logged in as {self.user.name} ({self.user.id})')
        
        logging.info(f'Command prefix: {self.command_prefix}')
        logging.info(f'Ready! Listening for CVEs...')
        logging.info('------')

    async def on_message(self, message: discord.Message):
        # Don't respond to our own messages
        if message.author == self.user:
            return

        # Look for CVEs in the message
        cves_found = self.cve_monitor.find_cves(message.content)
        
        if not cves_found:
            await self.process_commands(message) # Process traditional commands if no CVEs found
            return

        # Use a set to avoid processing the same CVE ID multiple times if it appears repeatedly
        unique_cves = sorted(list(set(cves_found)), key=lambda x: cves_found.index(x))
        
        embeds_to_send = []
        processed_count = 0
        # If CVEs are found, look up and generate embeds
        for cve in unique_cves:
            # Limit processing if too many unique CVEs are found in one message
            if processed_count >= MAX_EMBEDS_PER_MESSAGE:
                logging.warning(f"Max embeds reached for message {message.id}. Found {len(unique_cves)} unique CVEs, processing first {MAX_EMBEDS_PER_MESSAGE}.")
                break 
            
            cve_data = None
            try:
                # --- Try VulnCheck first (if client is available) --- 
                if self.vulncheck_client.api_client:
                    logging.debug(f"Attempting VulnCheck fetch for {cve}")
                    cve_data = await self.vulncheck_client.get_cve_details(cve)
                else:
                    logging.debug("VulnCheck client not available (no API key?), skipping.")
                
                # --- Fallback to NVD if VulnCheck fails or returns no data --- 
                if not cve_data:
                    if self.vulncheck_client.api_client:
                        logging.debug(f"VulnCheck failed for {cve}, attempting NVD fallback.")
                    else:
                        # If VulnCheck wasn't even tried, log that we're going straight to NVD
                        logging.debug(f"Attempting NVD fetch for {cve} (VulnCheck unavailable).")
                        
                    # await asyncio.sleep(0.1) # No longer needed as await below yields control
                    cve_data = await self.nvd_client.get_cve_details(cve)
                
                # --- Process data if found from either source --- 
                if cve_data:
                    embed = self.cve_monitor.create_cve_embed(cve_data)
                    embeds_to_send.append(embed)
                    processed_count += 1
                else:
                    logging.warning(f"Could not retrieve details for {cve} from any source.")

            except Exception as e:
                logging.error(f"Failed to process CVE {cve} after checking sources: {e}", exc_info=True)
            
            # Delay before processing next CVE ID in the message
            await asyncio.sleep(0.2) # Slightly longer delay between different CVE lookups

        # Send the collected embeds
        if embeds_to_send:
            logging.info(f"Sending {len(embeds_to_send)} embeds for message {message.id}")
            for i, embed in enumerate(embeds_to_send):
                await message.channel.send(embed=embed)
                if i < len(embeds_to_send) - 1:
                    await asyncio.sleep(0.5) # Delay between message sends
            
            if len(unique_cves) > MAX_EMBEDS_PER_MESSAGE:
                await message.channel.send(f"*Found {len(unique_cves)} unique CVEs, showing details for the first {MAX_EMBEDS_PER_MESSAGE}.*", allowed_mentions=discord.AllowedMentions.none())

        # Process traditional commands after handling CVEs
        await self.process_commands(message) 