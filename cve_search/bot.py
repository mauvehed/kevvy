import discord
from discord.ext import commands
from discord import app_commands # Import app_commands
from .cve_monitor import CVEMonitor
from .nvd_client import NVDClient
import logging
import os
import asyncio # Import asyncio for sleep
import importlib.metadata # Import for version reading

# Limit the number of embeds sent for a single message
MAX_EMBEDS_PER_MESSAGE = 5

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
    def __init__(self, nvd_api_key: str | None):
        intents = discord.Intents.default()
        intents.message_content = True
        prefix = os.getenv('DISCORD_COMMAND_PREFIX', '!')
        # Initialize the bot with the command tree capability
        super().__init__(command_prefix=prefix, intents=intents)
        
        self.nvd_client = NVDClient(api_key=nvd_api_key)
        self.cve_monitor = CVEMonitor(self.nvd_client)

    async def setup_hook(self):
        # Add the globally defined command to the bot's command tree
        self.tree.add_command(version_command)
        # Sync the commands (globally in this case)
        # Consider syncing to specific guilds for faster updates during development
        # await self.tree.sync(guild=discord.Object(id=YOUR_GUILD_ID))
        await self.tree.sync() 
        logging.info(f"Synced application commands.")

    async def on_ready(self):
        logging.info(f'Logged in as {self.user.name} ({self.user.id})')
        
        # Log Bot Version on startup
        try:
            version = importlib.metadata.version('cve-search')
            logging.info(f"cve-search version: {version}")
        except importlib.metadata.PackageNotFoundError:
            logging.warning("Could not determine application version. Package metadata not found.")
        except Exception as e:
             logging.warning(f"Could not determine application version: {e}")

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
            try:
                cve_data = self.nvd_client.get_cve_details(cve)
                if cve_data:
                    embed = self.cve_monitor.create_cve_embed(cve_data)
                    embeds_to_send.append(embed)
                    processed_count += 1
            except Exception as e:
                logging.error(f"Failed to process CVE {cve}: {e}", exc_info=True)
            await asyncio.sleep(0.1) # Delay between API calls

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