import logging
import asyncio
import discord

logger = logging.getLogger(__name__)

class DiscordLogHandler(logging.Handler):
    """A logging handler that sends log records to a Discord channel."""

    def __init__(self, bot, channel_id: int, level=logging.NOTSET):
        super().__init__(level=level)
        self.bot = bot
        self.channel_id = channel_id
        self._channel = None # Cache the channel object

    def emit(self, record):
        """Emit a record.

        Format the record and send it to the specified Discord channel.
        Handle potential errors like channel not found or permissions issues.
        Uses asyncio.create_task to avoid blocking.
        """
        if not self.bot.is_ready():
            # print("Bot not ready, skipping Discord log emit.") # Debug print
            return # Don't try to send logs if bot isn't ready

        try:
            log_entry = self.format(record)
            
            # Use cached channel if available, otherwise try to fetch it
            if self._channel is None:
                self._channel = self.bot.get_channel(self.channel_id)
            
            channel = self._channel

            if channel:
                 # Ensure message is within Discord limits (2000 chars)
                max_len = 2000
                if len(log_entry) > max_len:
                    log_entry = log_entry[:max_len-4] + "..."
                
                # Create task to send message without blocking handler
                asyncio.create_task(self._send_log_message(channel, log_entry))
            else:
                # Log error locally if channel not found (only log once?)
                # This avoids spamming if channel ID is wrong
                if not hasattr(self, '_channel_error_logged'):
                    logger.error(f"DiscordLogHandler: Could not find channel with ID {self.channel_id}. Logging to channel disabled.")
                    self._channel_error_logged = True

        except Exception:
            # Catch-all for formatting errors etc.
            self.handleError(record)

    async def _send_log_message(self, channel: discord.TextChannel, message: str):
        """Asynchronously sends the log message, handling potential Discord errors."""
        try:
            await channel.send(f"```log\n{message}```") # Send in a code block
        except discord.Forbidden:
            if not hasattr(self, '_permission_error_logged'):
                 logger.error(f"DiscordLogHandler: Bot lacks permissions to send messages in channel {channel.name} ({self.channel_id}).")
                 self._permission_error_logged = True
        except discord.HTTPException as e:
             if not hasattr(self, '_http_error_logged'):
                 # Use e.text instead of e.reason for discord.py v2
                 logger.error(f"DiscordLogHandler: Failed to send log message to {channel.name} ({self.channel_id}): {e.status} {e.text}")
                 self._http_error_logged = True
        except Exception as e:
            # Catch other unexpected errors during send
             if not hasattr(self, '_send_error_logged'):
                 logger.error(f"DiscordLogHandler: Unexpected error sending log to {channel.name} ({self.channel_id}): {e}", exc_info=True)
                 self._send_error_logged = True 