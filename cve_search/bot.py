import discord
from discord.ext import commands, tasks # Import tasks
from discord import app_commands # Import app_commands
from .cve_monitor import CVEMonitor
from .nvd_client import NVDClient
from .vulncheck_client import VulnCheckClient # Import VulnCheckClient
from .cisa_kev_client import CisaKevClient # Import CisaKevClient
import logging
import os
import asyncio # Import asyncio for sleep
import importlib.metadata # Import for version reading
import aiohttp # Import aiohttp
from typing import Dict, Any # Import Dict, Any

# Limit the number of embeds sent for a single message
MAX_EMBEDS_PER_MESSAGE = 5
# Default polling interval for CISA KEV feed (1 hour)
DEFAULT_CISA_KEV_INTERVAL = 3600 

logger = logging.getLogger(__name__) # Define logger at module level

# Define the slash command function globally or as a static method
@app_commands.command(name="version", description="Displays the current version of the bot.")
async def version_command(interaction: discord.Interaction):
    try:
        # Use the package name defined in pyproject.toml
        version = importlib.metadata.version('cve-search')
        await interaction.response.send_message(f"cve-search version: `{version}`")
    except importlib.metadata.PackageNotFoundError:
        logging.error("Could not find package metadata for 'cve-search'. Is it installed correctly?")
        await interaction.response.send_message("Error: Could not determine application version.", ephemeral=True)
    except Exception as e:
        logging.error(f"Error retrieving version: {e}", exc_info=True)
        await interaction.response.send_message("An unexpected error occurred while retrieving the version.", ephemeral=True)

class SecurityBot(commands.Bot):
    def __init__(self, nvd_api_key: str | None, vulncheck_api_token: str | None):
        intents = discord.Intents.default()
        intents.message_content = True
        prefix = os.getenv('DISCORD_COMMAND_PREFIX', '!')
        # Initialize the bot with the command tree capability
        super().__init__(command_prefix=prefix, intents=intents, enable_debug_events=True) # Add enable_debug_events=True
        
        # Initialize HTTP client session (used by CISA KEV client)
        self.http_session: aiohttp.ClientSession = aiohttp.ClientSession()

        # Initialize data source clients
        self.nvd_client = NVDClient(api_key=nvd_api_key)
        self.vulncheck_client = VulnCheckClient(api_key=vulncheck_api_token) # Initialize VulnCheck client
        self.cisa_kev_client = CisaKevClient(session=self.http_session) # Initialize CisaKevClient
        
        # Initialize monitor components
        self.cve_monitor = CVEMonitor(self.nvd_client)
        
        # --- CISA KEV Monitoring Configuration ---
        self.cisa_kev_channel_id_str = os.getenv('CISA_KEV_CHANNEL_ID')
        self.cisa_kev_channel_id = None
        if self.cisa_kev_channel_id_str:
            try:
                self.cisa_kev_channel_id = int(self.cisa_kev_channel_id_str)
                logger.info(f"CISA KEV monitoring enabled. Target channel ID: {self.cisa_kev_channel_id}")
            except ValueError:
                logger.error(f"Invalid CISA_KEV_CHANNEL_ID: '{self.cisa_kev_channel_id_str}'. Must be an integer. KEV monitoring disabled.")
                self.cisa_kev_channel_id = None # Disable if ID is invalid
        else:
            logger.warning("CISA_KEV_CHANNEL_ID not set in environment. CISA KEV monitoring will be disabled.")

        try:
            interval_str = os.getenv('CISA_KEV_INTERVAL_SECONDS', str(DEFAULT_CISA_KEV_INTERVAL))
            self.cisa_kev_interval = int(interval_str)
            if self.cisa_kev_interval <= 0:
                 logger.warning(f"Invalid CISA_KEV_INTERVAL_SECONDS: {self.cisa_kev_interval}. Using default: {DEFAULT_CISA_KEV_INTERVAL} seconds.")
                 self.cisa_kev_interval = DEFAULT_CISA_KEV_INTERVAL
            else:
                 logger.info(f"CISA KEV polling interval set to {self.cisa_kev_interval} seconds.")
        except ValueError:
             logger.error(f"Invalid CISA_KEV_INTERVAL_SECONDS: '{interval_str}'. Using default: {DEFAULT_CISA_KEV_INTERVAL} seconds.")
             self.cisa_kev_interval = DEFAULT_CISA_KEV_INTERVAL
        # -----------------------------------------

    async def setup_hook(self):
        # Add the globally defined command to the bot's command tree
        self.tree.add_command(version_command)
        # Sync the commands (globally in this case)
        # Consider syncing to specific guilds for faster updates during development
        # await self.tree.sync(guild=discord.Object(id=YOUR_GUILD_ID))
        await self.tree.sync() 
        logging.info(f"Synced application commands.")
        # Start background tasks
        if self.cisa_kev_channel_id:
            self.check_cisa_kev_feed.change_interval(seconds=self.cisa_kev_interval) # Set interval dynamically
            self.check_cisa_kev_feed.start()
        else:
            logger.info("CISA KEV monitoring task not started due to missing/invalid channel ID.")

    async def close(self):
        """Ensure cleanup happens correctly."""
        logging.info("Closing bot resources...")
        if self.check_cisa_kev_feed.is_running():
            self.check_cisa_kev_feed.cancel()
            logging.info("Cancelled CISA KEV monitoring task.")
        
        await self.http_session.close() # Close the aiohttp session
        logging.info("Closed aiohttp session.")
        
        if self.vulncheck_client:
            self.vulncheck_client.close() # Close VulnCheck client if initialized
            logging.info("Closed VulnCheck client.")
        
        await super().close() # Call the parent class's close method
        logging.info("Bot closed.")

    @tasks.loop() # Default interval will be overridden in setup_hook
    async def check_cisa_kev_feed(self):
        """Periodically checks the CISA KEV feed for new entries."""
        try:
            logger.debug("Running periodic CISA KEV check...")
            new_entries = await self.cisa_kev_client.get_new_kev_entries()

            if new_entries and self.cisa_kev_channel_id:
                target_channel = self.get_channel(self.cisa_kev_channel_id)
                if not target_channel:
                    logger.error(f"Could not find CISA KEV target channel with ID: {self.cisa_kev_channel_id}")
                    return
                if not isinstance(target_channel, discord.TextChannel):
                     logger.error(f"CISA KEV target channel {self.cisa_kev_channel_id} is not a TextChannel.")
                     return

                logger.info(f"Sending {len(new_entries)} new CISA KEV entries to channel {target_channel.name} ({target_channel.id})")
                for entry in new_entries:
                    embed = self._create_kev_embed(entry)
                    try:
                        await target_channel.send(embed=embed)
                        await asyncio.sleep(0.5) # Prevent rate limiting
                    except discord.Forbidden:
                         logger.error(f"Missing permissions to send message in CISA KEV channel {target_channel.id}")
                         break # Stop trying if permissions error occurs
                    except discord.HTTPException as e:
                         logger.error(f"Failed to send CISA KEV embed for {entry.get('cveID', 'Unknown CVE')} to channel {target_channel.id}: {e}")
                    except Exception as e:
                         logger.error(f"Unexpected error sending CISA KEV embed for {entry.get('cveID', 'Unknown CVE')}: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Error during CISA KEV check loop: {e}", exc_info=True)

    @check_cisa_kev_feed.before_loop
    async def before_kev_check(self):
        """Ensures the bot is ready before the loop starts."""
        await self.wait_until_ready()
        logger.info("Bot is ready, starting CISA KEV monitoring loop.")
        # Perform initial population without sending messages
        try:
            logger.info("Performing initial population of CISA KEV seen list...")
            await self.cisa_kev_client.get_new_kev_entries()
            logger.info("Initial CISA KEV population complete.")
        except Exception as e:
            logger.error(f"Error during initial CISA KEV population: {e}", exc_info=True)

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
                    cve_data = self.vulncheck_client.get_cve_details(cve)
                else:
                    logging.debug("VulnCheck client not available (no API key?), skipping.")
                
                # --- Fallback to NVD if VulnCheck fails or returns no data --- 
                if not cve_data:
                    if self.vulncheck_client.api_client:
                        logging.debug(f"VulnCheck failed for {cve}, attempting NVD fallback.")
                    else:
                        # If VulnCheck wasn't even tried, log that we're going straight to NVD
                        logging.debug(f"Attempting NVD fetch for {cve} (VulnCheck unavailable).")
                        
                    await asyncio.sleep(0.1) # Small delay before trying next source
                    cve_data = self.nvd_client.get_cve_details(cve)
                
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