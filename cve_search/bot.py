import discord
from discord.ext import commands
from .cve_monitor import CVEMonitor
from .vulners_client import VulnersClient
import logging
import os

class SecurityBot(commands.Bot):
    def __init__(self, vulners_api_key: str):
        intents = discord.Intents.default()
        intents.message_content = True
        
        prefix = os.getenv('DISCORD_COMMAND_PREFIX', '!')
        super().__init__(command_prefix=prefix, intents=intents)
        
        self.vulners_client = VulnersClient(vulners_api_key)
        self.cve_monitor = CVEMonitor(self.vulners_client)

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

        # Look for CVEs in the message
        cves = self.cve_monitor.find_cves(message.content)
        
        # If CVEs are found, look up and send details
        for cve in cves:
            try:
                cve_data = self.vulners_client.get_cve_details(cve)
                if cve_data:
                    embed = self.cve_monitor.create_cve_embed(cve_data)
                    await message.channel.send(embed=embed)
            except Exception as e:
                logging.error(f"Failed to process CVE {cve}: {e}", exc_info=True)

        await self.process_commands(message) 