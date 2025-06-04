import logging
import asyncio
import discord

logger = logging.getLogger(__name__)

# Define color mapping for log levels
LOG_LEVEL_COLORS = {
    logging.CRITICAL: discord.Color.dark_red(),
    logging.ERROR: discord.Color.red(),
    logging.WARNING: discord.Color.gold(),
    logging.INFO: discord.Color.blue(),
    logging.DEBUG: discord.Color.dark_grey(),
    logging.NOTSET: discord.Color.light_grey(),
}
DEFAULT_LOG_COLOR = discord.Color.light_grey()


class DiscordLogHandler(logging.Handler):
    """A logging handler that sends log records as embeds to a Discord channel."""

    def __init__(self, bot, channel_id: int, level=logging.NOTSET):
        super().__init__(level=level)
        self.bot = bot
        self.channel_id = channel_id
        self._channel = None  # Cache the channel object

    def emit(self, record):
        """Emit a record.

        Format the record, determine the embed color based on level,
        and send it to the specified Discord channel using an embed.
        Handle potential errors like channel not found or permissions issues.
        Uses asyncio.create_task to avoid blocking.
        """
        if not self.bot.is_ready():
            # print("Bot not ready, skipping Discord log emit.") # Debug print
            return  # Don't try to send logs if bot isn't ready

        try:
            log_entry = self.format(record)
            log_level = record.levelno

            # Use cached channel if available, otherwise try to fetch it
            if self._channel is None:
                self._channel = self.bot.get_channel(self.channel_id)

            if channel := self._channel:
                max_len = 4096
                if len(log_entry) > max_len:
                    log_entry = f"{log_entry[:max_len - 4]}..."

                # Create task to send message without blocking handler
                asyncio.create_task(self._send_log_embed(channel, log_entry, log_level))
            elif not hasattr(
                self, "_channel_fetch_error_logged"
            ):  # Log only periodically
                logger.error(
                    f"DiscordLogHandler: Could not find/fetch configured logging channel with ID {self.channel_id}. Will retry later."
                )
                # Set a temporary flag to avoid spamming, could potentially reset this after a delay
                self._channel_fetch_error_logged = True
        except Exception:
            # Catch-all for formatting errors etc.
            self.handleError(record)

    async def _send_log_embed(
        self, channel: discord.TextChannel, message: str, level: int
    ):
        """Asynchronously sends the log message as an embed, handling potential Discord errors
        and implementing a custom retry mechanism for rate limits."""
        embed_color = LOG_LEVEL_COLORS.get(level, DEFAULT_LOG_COLOR)
        embed = discord.Embed(
            description=f"```log\n{message}```",
            color=embed_color,
            timestamp=discord.utils.utcnow(),
        )

        max_retries = 3
        # Minimum time to wait before retrying, even if Discord suggests shorter.
        MINIMUM_RETRY_DELAY_SECONDS = 30.0

        for attempt in range(max_retries):
            try:
                await channel.send(embed=embed)

                # Reset error flags on successful send
                if hasattr(self, "_permission_error_logged"):
                    delattr(self, "_permission_error_logged")
                if hasattr(self, "_http_error_logged"):
                    delattr(self, "_http_error_logged")
                if hasattr(self, "_send_error_logged"):
                    delattr(self, "_send_error_logged")
                if hasattr(self, "_channel_fetch_error_logged"):
                    delattr(self, "_channel_fetch_error_logged")
                return  # Success, exit the method

            except discord.Forbidden:
                if not hasattr(self, "_permission_error_logged"):
                    logger.error(
                        f"DiscordLogHandler: Bot lacks permissions to send messages/embeds in channel #{channel.name} (ID: {self.channel_id}, Guild: {channel.guild.id}). Check bot roles."
                    )
                    self._permission_error_logged = True
                self._channel = None  # Reset channel cache to force refetch
                return  # Don't retry on permission errors
            except discord.HTTPException as e:
                if e.status == 429:  # Rate limited
                    discord_suggested_retry_after = getattr(e, "retry_after", None)

                    wait_duration = MINIMUM_RETRY_DELAY_SECONDS
                    if discord_suggested_retry_after is not None:
                        wait_duration = max(
                            discord_suggested_retry_after, MINIMUM_RETRY_DELAY_SECONDS
                        )

                    logger.warning(
                        f"DiscordLogHandler: Rate limited sending log to #{channel.name} (ID: {self.channel_id}). "
                        f"Attempt {attempt + 1}/{max_retries}. Waiting {wait_duration:.2f} seconds before retrying. "
                        f"(Discord suggested: {discord_suggested_retry_after if discord_suggested_retry_after is not None else 'N/A'}s, Using: {wait_duration:.2f}s)"
                    )
                    if attempt < max_retries - 1:
                        await asyncio.sleep(wait_duration)
                        continue  # Go to next attempt
                    else:
                        logger.error(
                            f"DiscordLogHandler: Failed to send log to #{channel.name} (ID: {self.channel_id}) after {max_retries} rate limit retries."
                        )
                        # Store the fact that we are still rate limited for this type of error
                        if not hasattr(self, "_http_error_logged"):
                            self._http_error_logged = True  # So we don't spam further http errors if other sends also fail
                else:  # Other HTTP error
                    if not hasattr(self, "_http_error_logged"):
                        logger.error(
                            f"DiscordLogHandler: Failed to send log embed to #{channel.name} (ID: {self.channel_id}, Guild: {channel.guild.id}): {e.status} {e.text}"
                        )
                        self._http_error_logged = True
                self._channel = None  # Reset channel cache to force refetch
                return  # Don't retry on other HTTP errors for now, or after max retries for 429
            except Exception as e:
                if not hasattr(self, "_send_error_logged"):
                    logger.error(
                        f"DiscordLogHandler: Unexpected error sending log embed to #{channel.name} (ID: {self.channel_id}, Guild: {channel.guild.id}): {e}",
                        exc_info=True,
                    )
                    self._send_error_logged = True
                self._channel = None  # Reset channel cache to force refetch
                return  # Don't retry on unknown errors
