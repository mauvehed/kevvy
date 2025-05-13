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
    BOT_VERSION = "unknown"

if TYPE_CHECKING:
    from ..bot import SecurityBot

logger = logging.getLogger(__name__)


class DiagnosticsCog(commands.Cog):
    """Cog for sending diagnostic information to a web endpoint."""

    def __init__(self, bot: "SecurityBot"):
        self.bot = bot
        # Adjust type hint to Optional, although setup ensures it exists
        self.session: Optional[aiohttp.ClientSession] = bot.http_session
        # Use correct env var names
        self.api_endpoint = os.getenv("KEVVY_WEB_URL")
        self.api_secret = os.getenv("KEVVY_WEB_API_KEY")  # Use KEVVY_WEB_API_KEY
        self.start_time = time.time()
        # Add a flag to track whether we've sent the cogs list
        self.cogs_list_sent = False

        if not self.api_endpoint or not self.api_secret:
            # Use correct env var names in warning
            logger.warning(
                "KEVVY_WEB_URL or KEVVY_WEB_API_KEY not set. Web status updates disabled."
            )
        else:
            # Add an assertion here to satisfy type checker, since setup ensures session exists if we reach here
            assert (
                self.session is not None
            ), "HTTP session must be initialized if API endpoint/secret are set"
            self.update_web_status.start()

    def cog_unload(self):
        """Cleanly stops the background task when the cog is unloaded."""
        self.update_web_status.cancel()
        logger.info("Stopped web status update task.")

    @tasks.loop(minutes=1.0)  # Send status every minute
    async def update_web_status(self):
        # Add check for self.session just in case, though it should always be available if task runs
        if not self.api_endpoint or not self.api_secret or not self.session:
            logger.warning(
                "Diagnostics task running without endpoint, secret, or session. Skipping update."
            )
            return  # Silently return if config or session is missing

        # Construct the full URL by appending the specific path
        full_api_url = f"{self.api_endpoint.rstrip('/')}/api/bot-status"

        logger.debug(f"Preparing to send bot status to web API at {full_api_url}.")

        # --- Gather Stats ---
        stats_data: Dict[str, Any] = {}
        try:
            # Basic Bot Info
            stats_data["timestamp"] = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()
            stats_data["bot_version"] = BOT_VERSION
            stats_data["discord_py_version"] = discord.__version__
            stats_data["python_version"] = platform.python_version()
            stats_data["uptime_seconds"] = int(time.time() - self.start_time)
            stats_data["latency_ms"] = (
                round(self.bot.latency * 1000, 2) if self.bot.latency else None
            )
            stats_data["guild_count"] = len(self.bot.guilds)

            # Get stats from StatsManager
            current_bot_stats: Dict[str, Any] = {}
            if self.bot.stats_manager:
                current_bot_stats = await self.bot.stats_manager.get_stats_dict()
            else:
                logger.error(
                    "StatsManager not found on bot in DiagnosticsCog. Detailed stats will be zero."
                )

            # Only send cog list on first update after startup
            if not self.cogs_list_sent:
                cog_names = list(self.bot.cogs.keys())
                logger.info(
                    f"First status update - sending {len(cog_names)} loaded cogs: {cog_names}"
                )
                stats_data["loaded_cogs"] = cog_names
                self.cogs_list_sent = True

            # API/Task Status - Mapped keys
            stats_data["nvd_api_errors"] = current_bot_stats.get("api_errors_nvd", 0)
            stats_data["kev_api_errors"] = current_bot_stats.get("api_errors_kev", 0)
            stats_data["last_kev_check_success_ts"] = (
                self.bot.timestamp_last_kev_check_success.isoformat()
                if self.bot.timestamp_last_kev_check_success
                else None
            )
            stats_data["last_kev_alert_sent_ts"] = (
                self.bot.timestamp_last_kev_alert_sent.isoformat()
                if self.bot.timestamp_last_kev_alert_sent
                else None
            )
            stats_data["api_errors_vulncheck"] = current_bot_stats.get(
                "api_errors_vulncheck", 0
            )
            stats_data["api_errors_cisa"] = current_bot_stats.get("api_errors_cisa", 0)
            stats_data["rate_limits_nvd"] = current_bot_stats.get(
                "rate_limits_hit_nvd", 0
            )

            # Feature Usage/Config - Mapped keys
            stats_data["cve_lookups"] = current_bot_stats.get("cve_lookups", 0)
            stats_data["kev_alerts"] = current_bot_stats.get("kev_alerts_sent", 0)
            stats_data["messages_processed"] = current_bot_stats.get(
                "messages_processed", 0
            )
            stats_data["vulncheck_success"] = current_bot_stats.get(
                "vulncheck_success", 0
            )
            stats_data["nvd_fallback_success"] = current_bot_stats.get(
                "nvd_fallback_success", 0
            )

            # Database dependent stats
            if self.bot.db:
                stats_data["kev_enabled_guilds"] = self.bot.db.count_enabled_guilds()
                stats_data["cve_globally_enabled_guilds"] = (
                    self.bot.db.count_globally_enabled_cve_guilds()
                )
                stats_data["cve_active_channels"] = (
                    self.bot.db.count_active_cve_channels()
                )
            else:
                stats_data["kev_enabled_guilds"] = None
                stats_data["cve_globally_enabled_guilds"] = None
                stats_data["cve_active_channels"] = None

            logger.debug(f"Gathered stats: {stats_data}")

            # --- Send to API ---
            headers = {
                # Use correct secret var for Bearer token
                "Authorization": f"Bearer {self.api_secret}",
                "Content-Type": "application/json",
            }

            # Use a shorter timeout for status updates
            request_timeout = aiohttp.ClientTimeout(total=10)

            # Use the full URL constructed above
            # Ensure session is not None before using it
            if self.session:
                async with self.session.post(
                    full_api_url,
                    json=stats_data,
                    headers=headers,
                    timeout=request_timeout,
                ) as response:
                    if response.status == 200:
                        logger.info(
                            f"Successfully sent bot status to web API ({full_api_url})."
                        )
                    else:
                        logger.warning(
                            f"Failed to send bot status to web API. Status: {response.status}, Reason: {response.reason}"
                        )
                        # Optionally log response body on error for debugging
                        try:
                            error_text = await response.text()
                            logger.warning(
                                f"Web API Response Body (Truncated): {error_text[:500]}"
                            )  # Limit length
                        except Exception as read_err:
                            logger.warning(
                                f"Could not read response body after API error: {read_err}"
                            )
            else:
                logger.error("HTTP session is not available for sending status update.")

        except aiohttp.ClientError as e:
            logger.error(f"HTTP Error sending status to web API ({full_api_url}): {e}")
        except asyncio.TimeoutError:
            logger.error(f"Timeout sending status to web API ({full_api_url}).")
        except Exception as e:
            logger.error(
                f"Unexpected error in update_web_status task: {e}", exc_info=True
            )

    @update_web_status.before_loop
    async def before_update_web_status(self):
        """Ensures the bot is ready before the loop starts."""
        await self.bot.wait_until_ready()
        logger.info("Bot ready, starting web status update loop.")


async def setup(bot: "SecurityBot"):
    """Sets up the Diagnostics Cog."""
    # Ensure the bot has an aiohttp session
    if not hasattr(bot, "http_session") or not bot.http_session:
        logger.error(
            "Bot is missing http_session. DiagnosticsCog requires a shared aiohttp session."
        )
        return  # Don't load cog if session isn't ready
    await bot.add_cog(DiagnosticsCog(bot))
    logger.info("Diagnostics Cog loaded.")
