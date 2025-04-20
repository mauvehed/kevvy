import discord
from discord.ext import commands
from .cve_monitor import CVEMonitor
from .nvd_client import NVDClient
import logging
import os
import asyncio # Import asyncio for sleep

# Limit the number of embeds sent for a single message
MAX_EMBEDS_PER_MESSAGE = 5

class SecurityBot(commands.Bot):
    def __init__(self, nvd_api_key: str | None):
        intents = discord.Intents.default()
        intents.message_content = True
        
        prefix = os.getenv('DISCORD_COMMAND_PREFIX', '!')
        super().__init__(command_prefix=prefix, intents=intents)
        
        self.nvd_client = NVDClient(api_key=nvd_api_key)
        self.cve_monitor = CVEMonitor(self.nvd_client)

    async def setup_hook(self):
        # Add any additional setup here
        pass

    async def on_ready(self):
        logging.info(f'Logged in as {self.user.name} ({self.user.id})')
        logging.info('------')

    async def on_message(self, message: discord.Message):
        # Don't respond to our own messages
        if message.author == self.user:
            return

        # Always process commands if applicable (e.g., for help command)
        # We will process commands *after* handling potential CVEs
        # await self.process_commands(message) # Moved this call lower

        # Look for CVEs in the message
        cves_found = self.cve_monitor.find_cves(message.content)
        
        if not cves_found:
            await self.process_commands(message) # Process commands if no CVEs found
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
            # Add a small delay between API calls if processing multiple CVEs
            # This helps stay within potential rate limits even with retries
            await asyncio.sleep(0.1) # 100ms delay

        # Send the collected embeds
        if embeds_to_send:
            logging.info(f"Sending {len(embeds_to_send)} embeds for message {message.id}")
            # Send embeds one by one
            for i, embed in enumerate(embeds_to_send):
                await message.channel.send(embed=embed)
                # Small delay between sending messages to avoid Discord rate limits
                if i < len(embeds_to_send) - 1:
                    await asyncio.sleep(0.5) 
            
            # If more CVEs were found than processed, add a note
            if len(unique_cves) > MAX_EMBEDS_PER_MESSAGE:
                await message.channel.send(f"*Found {len(unique_cves)} unique CVEs, showing details for the first {MAX_EMBEDS_PER_MESSAGE}.*", allowed_mentions=discord.AllowedMentions.none())

        # Process commands after handling CVEs
        await self.process_commands(message) 