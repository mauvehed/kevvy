import discord
from discord.ext import commands, tasks
import logging
import datetime
import aiohttp
import os
import platform
import time
from typing import TYPE_CHECKING, Optional, Dict, Any
import asyncio

# Attempt to get version from __init__
try:
    from .. import __version__ as BOT_VERSION
except ImportError:
    BOT_VERSION = 'unknown'

if TYPE_CHECKING:
    from ..bot import SecurityBot

logger = logging.getLogger(__name__)

class DiagnosticsCog(commands.Cog):
    """Cog for sending diagnostic information to a web endpoint."""

    def __init__(self, bot: 'SecurityBot'):
        self.bot = bot
        self.session: aiohttp.ClientSession = bot.http_session # Use bot's session
        # Use correct env var names
        self.api_endpoint = os.getenv('KEVVY_WEB_URL') 
        self.api_secret = os.getenv('KEVVY_WEB_API_KEY') # Use KEVVY_WEB_API_KEY
        self.start_time = time.time() 

        if not self.api_endpoint or not self.api_secret:
            # Use correct env var names in warning
            logger.warning("KEVVY_WEB_URL or KEVVY_WEB_API_KEY not set. Web status updates disabled.")
        else:
            self.update_web_status.start()

    def cog_unload(self):
        self.update_web_status.cancel()

    @tasks.loop(minutes=1.0) # Send status every minute
    async def update_web_status(self):
        if not self.api_endpoint or not self.api_secret:
            return # Silently return if config is missing

        logger.debug("Preparing to send bot status to web API.")

        # --- Gather Stats --- 
        stats_data: Dict[str, Any] = {}
        try:
            # Basic Bot Info
            stats_data['timestamp'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            stats_data['bot_version'] = BOT_VERSION
            stats_data['discord_py_version'] = discord.__version__
            stats_data['python_version'] = platform.python_version()
            stats_data['uptime_seconds'] = int(time.time() - self.start_time)
            stats_data['latency_ms'] = round(self.bot.latency * 1000, 2) if self.bot.latency else None
            stats_data['guild_count'] = len(self.bot.guilds)
            stats_data['loaded_cogs'] = list(self.bot.cogs.keys())

            # API/Task Status (Use getattr with default 0 for stats)
            stats_data['nvd_api_errors'] = getattr(self.bot, 'stats_api_errors_nvd', 0)
            # TODO: Add stats_api_errors_kev counter to bot if needed
            stats_data['kev_api_errors'] = getattr(self.bot, 'stats_api_errors_kev', 0)
            stats_data['last_kev_check_success_ts'] = self.bot.timestamp_last_kev_check_success.isoformat() if self.bot.timestamp_last_kev_check_success else None
            stats_data['last_kev_alert_sent_ts'] = self.bot.timestamp_last_kev_alert_sent.isoformat() if self.bot.timestamp_last_kev_alert_sent else None
            # TODO: Add CVE monitor timestamps if needed

            # Feature Usage/Config
            stats_data['cve_lookups'] = getattr(self.bot, 'stats_cve_lookups', 0)
            if self.bot.db:
                stats_data['kev_enabled_guilds'] = self.bot.db.count_enabled_guilds()
                stats_data['cve_globally_enabled_guilds'] = self.bot.db.count_globally_enabled_cve_guilds()
                stats_data['cve_active_channels'] = self.bot.db.count_active_cve_channels()
            else:
                stats_data['kev_enabled_guilds'] = None
                stats_data['cve_globally_enabled_guilds'] = None
                stats_data['cve_active_channels'] = None

            logger.debug(f"Gathered stats: {stats_data}")

            # --- Send to API --- 
            headers = {
                # Use correct secret var for Bearer token
                'Authorization': f'Bearer {self.api_secret}', 
                'Content-Type': 'application/json'
            }
            
            # Use a shorter timeout for status updates
            request_timeout = aiohttp.ClientTimeout(total=10)
            
            async with self.session.post(self.api_endpoint, json=stats_data, headers=headers, timeout=request_timeout) as response:
                if response.status == 200:
                    logger.info(f"Successfully sent bot status to web API ({self.api_endpoint}).")
                else:
                    logger.warning(f"Failed to send bot status to web API. Status: {response.status}, Reason: {response.reason}")
                    # Optionally log response body on error for debugging
                    # error_text = await response.text()
                    # logger.warning(f"Web API Response Body: {error_text[:500]}") # Limit length
        
        except aiohttp.ClientError as e:
            logger.error(f"HTTP Error sending status to web API: {e}")
        except asyncio.TimeoutError:
            logger.error(f"Timeout sending status to web API ({self.api_endpoint}).")
        except Exception as e:
            logger.error(f"Unexpected error in update_web_status task: {e}", exc_info=True)

    @update_web_status.before_loop
    async def before_update_web_status(self):
        await self.bot.wait_until_ready() # Wait until the bot is connected

async def setup(bot: 'SecurityBot'):
    # Ensure the bot has an aiohttp session
    if not hasattr(bot, 'http_session') or not bot.http_session:
        logger.error("Bot is missing http_session. DiagnosticsCog requires a shared aiohttp session.")
        return
    await bot.add_cog(DiagnosticsCog(bot))
    logger.info("Diagnostics Cog loaded.") 