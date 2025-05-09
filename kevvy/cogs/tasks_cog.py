import discord
from discord.ext import commands, tasks
import logging
import asyncio
import datetime
from typing import Dict, Any, Tuple
import os
import aiohttp
from aiohttp import ClientTimeout

# Assuming SecurityBot is in kevvy/bot.py, one level up from kevvy/cogs/
from ..bot import SecurityBot  # For type hinting self.bot

logger = logging.getLogger(__name__)

# Access env vars directly in the cog for now
WEBAPP_ENDPOINT_URL = os.getenv("KEVVY_WEB_URL", "YOUR_WEBAPP_ENDPOINT_URL_HERE")
WEBAPP_API_KEY = os.getenv("KEVVY_WEB_API_KEY", None)


class TasksCog(commands.Cog, name="BackgroundTasks"):
    """Handles background tasks like CISA KEV feed checking and stats reporting."""

    def __init__(self, bot: SecurityBot):
        self.bot = bot
        self.kev_check_first_run = True  # Flag for KEV check initial run for this cog

    def cog_unload(self):
        """Called when the cog is unloaded. Ensures tasks are cancelled."""
        logger.info("Cancelled background tasks due to cog unload.")

    def _create_kev_embed(self, kev_data: Dict[str, Any]) -> discord.Embed:
        """Creates a standardized embed for a KEV entry."""
        cve_id = kev_data.get("cveID", "N/A")
        nvd_link = (
            f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            if cve_id != "N/A"
            else "Link unavailable"
        )
        title = f"🚨 New CISA KEV Entry: {cve_id}"
        embed = discord.Embed(
            title=title,
            description=kev_data.get("shortDescription", "No description available."),
            url=nvd_link,
            color=discord.Color.dark_red(),
        )
        embed.add_field(
            name="Vulnerability Name",
            value=kev_data.get("vulnerabilityName", "N/A"),
            inline=False,
        )
        embed.add_field(
            name="Vendor/Project",
            value=kev_data.get("vendorProject", "N/A"),
            inline=True,
        )
        embed.add_field(
            name="Product", value=kev_data.get("product", "N/A"), inline=True
        )
        embed.add_field(
            name="Date Added", value=kev_data.get("dateAdded", "N/A"), inline=True
        )
        embed.add_field(
            name="Required Action",
            value=kev_data.get("requiredAction", "N/A"),
            inline=False,
        )
        embed.add_field(
            name="Due Date", value=kev_data.get("dueDate", "N/A"), inline=True
        )
        embed.add_field(
            name="Known Ransomware Use",
            value=kev_data.get("knownRansomwareCampaignUse", "N/A"),
            inline=True,
        )
        if notes := kev_data.get("notes", ""):
            notes_display = f"{notes[:1020]}..." if len(notes) > 1024 else notes
            embed.add_field(name="Notes", value=notes_display, inline=False)
        embed.set_footer(text="Source: CISA Known Exploited Vulnerabilities Catalog")
        embed.timestamp = discord.utils.utcnow()
        return embed

    @tasks.loop(hours=1)
    async def check_cisa_kev_feed(self):
        """Periodically checks the CISA KEV feed for new entries and sends to configured guilds."""
        if not self.bot.cisa_kev_client or not self.bot.db:
            logger.debug(
                "CISA KEV client or DB not initialized on bot, skipping KEV check in TasksCog."
            )
            return

        task_start_time = datetime.datetime.now(datetime.timezone.utc)
        success = False
        try:
            logger.info("Running periodic CISA KEV check from TasksCog...")
            new_entries = []
            try:
                new_entries = await self.bot.cisa_kev_client.get_new_kev_entries()
                success = True
            except Exception as client_error:
                logger.error(
                    f"CISA KEV client error during fetch (TasksCog): {client_error}",
                    exc_info=True,
                )
                await self.bot.stats_manager.record_api_error("cisa")

            if not new_entries:
                logger.info(
                    "Completed periodic CISA KEV check (TasksCog). No new KEV entries found."
                )
            else:
                logger.info(
                    f"Found {len(new_entries)} new KEV entries (TasksCog). Checking configured guilds..."
                )
                alerts_sent_this_run = 0
                enabled_configs = self.bot.db.get_enabled_kev_configs()

                max_initial_entries = 3
                if self.kev_check_first_run and len(new_entries) > max_initial_entries:
                    logger.warning(
                        f"First KEV check run (TasksCog) found {len(new_entries)} entries. Processing only the first {max_initial_entries}."
                    )
                    new_entries_to_process = new_entries[:max_initial_entries]
                    self.kev_check_first_run = False
                else:
                    new_entries_to_process = new_entries
                    if self.kev_check_first_run:
                        self.kev_check_first_run = False

                if enabled_configs:
                    for config in enabled_configs:
                        guild_id = config["guild_id"]
                        channel_id = config["channel_id"]
                        guild = self.bot.get_guild(guild_id)
                        if not guild:
                            logger.warning(
                                f"Could not find guild {guild_id} from KEV config (TasksCog), skipping."
                            )
                            continue
                        target_channel = self.bot.get_channel(channel_id)
                        if not target_channel or not isinstance(
                            target_channel, discord.TextChannel
                        ):
                            logger.error(
                                f"Invalid CISA KEV target channel {channel_id} in guild {guild.name} (TasksCog)."
                            )
                            continue
                        logger.info(
                            f"Sending {len(new_entries_to_process)} new KEV entries to #{target_channel.name} in {guild.name} (TasksCog)..."
                        )
                        for entry in new_entries_to_process:
                            embed = self._create_kev_embed(entry)
                            try:
                                await target_channel.send(embed=embed)
                                alerts_sent_this_run += 1
                                self.bot.timestamp_last_kev_alert_sent = (
                                    datetime.datetime.now(datetime.timezone.utc)
                                )
                                await asyncio.sleep(1.5)
                            except discord.Forbidden:
                                logger.error(
                                    f"Missing permissions for KEV alert in G:{guild_id}/C:{channel_id} (TasksCog)."
                                )
                                break
                            except discord.HTTPException as e:
                                logger.error(
                                    f"HTTP error for KEV alert {entry.get('cveID', 'N/A')} in G:{guild_id}/C:{channel_id} (TasksCog): {e}"
                                )
                                pass
                            except Exception as e:
                                logger.error(
                                    f"Unexpected error for KEV alert {entry.get('cveID', 'N/A')} G:{guild_id}/C:{channel_id} (TasksCog): {e}",
                                    exc_info=True,
                                )
                                pass
                        await asyncio.sleep(2)
                    if alerts_sent_this_run > 0:
                        await self.bot.stats_manager.increment_kev_alerts_sent(
                            alerts_sent_this_run
                        )
                        logger.info(
                            f"Finished KEV alerts (TasksCog). Total sent: {alerts_sent_this_run}"
                        )
                else:
                    logger.info("No guilds have KEV monitoring enabled (TasksCog).")
            if success:
                self.bot.timestamp_last_kev_check_success = task_start_time
                logger.debug(
                    f"Updated last KEV check success timestamp to {task_start_time} (TasksCog)."
                )
        except Exception as e:
            logger.error(
                f"Error during CISA KEV check loop logic (TasksCog): {e}", exc_info=True
            )

    @check_cisa_kev_feed.before_loop
    async def before_kev_check(self):
        """Ensures the bot is ready before the loop starts."""
        await self.bot.wait_until_ready()
        logger.info("Bot is ready, starting CISA KEV monitoring loop from TasksCog.")

    # --- Stats Reporting Task ---
    async def _post_stats(
        self, url: str, payload: dict, headers: dict
    ) -> Tuple[int, str]:
        """Helper method to perform the actual POST request for stats."""
        timeout = ClientTimeout(total=10)
        if not self.bot.http_session:
            logger.error("HTTP session is not initialized on bot, cannot send stats.")
            raise RuntimeError("HTTP Session not available")

        logger.debug(f"Executing POST to {url} from TasksCog")
        try:
            async with self.bot.http_session.post(
                url, json=payload, headers=headers, timeout=timeout
            ) as response:
                response_text = await response.text()
                logger.debug(
                    f"Received response from {url} (TasksCog): Status {response.status}, Body: {response_text[:100]}"
                )
                return response.status, response_text
        except aiohttp.ClientConnectorError as e:
            logger.error(f"Connection error during stats POST to {url} (TasksCog): {e}")
            raise
        except asyncio.TimeoutError:
            logger.error(f"Timeout during stats POST to {url} (TasksCog)")
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error during stats POST to {url} (TasksCog): {e}",
                exc_info=True,
            )
            raise

    @tasks.loop(minutes=5)
    async def send_stats_to_webapp(self):
        """Periodically sends bot statistics to the web application dashboard."""
        if not self.bot.http_session:
            logger.debug(
                "HTTP session not available on bot, skipping web app stats send (TasksCog)."
            )
            return

        base_url = WEBAPP_ENDPOINT_URL
        if base_url == "YOUR_WEBAPP_ENDPOINT_URL_HERE":
            logger.debug(
                "Web app endpoint base URL not configured (TasksCog), skipping stats send."
            )
            return

        full_url = f"{base_url.rstrip('/')}/api/bot-status"
        current_time = datetime.datetime.now(datetime.timezone.utc)

        # Get stats dictionary from StatsManager
        core_stats_dict = await self.bot.stats_manager.get_stats_dict()

        # Get other stats directly from bot
        kev_enabled_count = 0
        if self.bot.db:
            try:
                kev_enabled_count = self.bot.db.count_enabled_guilds()
            except Exception as db_err:
                logger.error(
                    f"Error fetching KEV enabled guild count (TasksCog): {db_err}",
                    exc_info=True,
                )

        uptime_delta = current_time - self.bot.start_time
        uptime_seconds = int(uptime_delta.total_seconds())

        # Construct the final payload, merging bot info and the stats dict
        stats_payload = {
            "bot_id": self.bot.user.id if self.bot.user else None,
            "bot_name": str(self.bot.user) if self.bot.user else "Unknown",
            "guild_count": len(self.bot.guilds),
            "latency_ms": round(self.bot.latency * 1000, 2),
            "shard_id": self.bot.shard_id if self.bot.shard_id is not None else 0,
            "shard_count": (
                self.bot.shard_count if self.bot.shard_count is not None else 1
            ),
            "start_time": self.bot.start_time.isoformat(),
            "uptime_seconds": uptime_seconds,
            "is_ready": self.bot.is_ready(),
            "timestamp": current_time.isoformat(),
            "last_stats_sent_time": (
                self.bot.last_stats_sent_time.isoformat()
                if self.bot.last_stats_sent_time
                else None
            ),
            # Add at top level for backward compatibility
            "loaded_cogs": self.bot.loaded_cogs,
            "failed_cogs": self.bot.failed_cogs,
            "timestamp_last_kev_check_success": (
                self.bot.timestamp_last_kev_check_success.isoformat()
                if self.bot.timestamp_last_kev_check_success
                else None
            ),
            "timestamp_last_kev_alert_sent": (
                self.bot.timestamp_last_kev_alert_sent.isoformat()
                if self.bot.timestamp_last_kev_alert_sent
                else None
            ),
            # Embed the core stats dictionary under the 'stats' key
            "stats": {
                **core_stats_dict,  # Unpack the dictionary from StatsManager
                # Add stats not managed by StatsManager directly here
                "loaded_cogs": self.bot.loaded_cogs,
                "failed_cogs": self.bot.failed_cogs,
                "last_kev_check_success": (
                    self.bot.timestamp_last_kev_check_success.isoformat()
                    if self.bot.timestamp_last_kev_check_success
                    else None
                ),
                "last_kev_alert_sent": (
                    self.bot.timestamp_last_kev_alert_sent.isoformat()
                    if self.bot.timestamp_last_kev_alert_sent
                    else None
                ),
                "kev_enabled_guilds": kev_enabled_count,
            },
        }

        headers = {"Content-Type": "application/json"}
        if WEBAPP_API_KEY:
            headers["Authorization"] = f"Bearer {WEBAPP_API_KEY}"

        try:
            logger.info(f"Sending stats payload to {full_url} from TasksCog")
            status_code, response_text = await self._post_stats(
                full_url, stats_payload, headers
            )
            if 200 <= status_code < 300:
                logger.info(
                    f"Successfully sent stats to web app (TasksCog - Status: {status_code})"
                )
                self.bot.last_stats_sent_time = datetime.datetime.now(
                    datetime.timezone.utc
                )  # Update timestamp on bot
            else:
                logger.error(
                    f"Failed to send stats to web app (TasksCog). Status: {status_code}. Response: {response_text[:200]}"
                )
        except aiohttp.ClientConnectorError as e:
            logger.error(
                f"Connection error sending stats (TasksCog) to {full_url}: {type(e).__name__} - {e}"
            )
        except asyncio.TimeoutError:
            logger.error(f"Timeout sending stats (TasksCog) to {full_url}")
        except RuntimeError as e:
            logger.error(f"Cannot send stats (TasksCog): {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error sending stats (TasksCog): {e}", exc_info=True
            )

    @send_stats_to_webapp.before_loop
    async def before_send_stats(self):
        """Ensures the bot is ready before the stats loop starts."""
        await self.bot.wait_until_ready()
        logger.info("Starting Web App Stats sending loop from TasksCog...")

    # --- End Stats Reporting Task ---


async def setup(bot: SecurityBot):
    """Standard setup function to add the cog to the bot."""
    await bot.add_cog(TasksCog(bot))
    logger.info("TasksCog has been loaded.")
