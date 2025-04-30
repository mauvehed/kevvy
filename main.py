import os
from dotenv import load_dotenv
from kevvy.bot import SecurityBot
import logging
import discord

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    load_dotenv()
    logger.info("Loaded environment variables from .env file (if present).")

    # --- Log Configuration ---
    token = os.getenv("DISCORD_TOKEN")
    nvd_api_key = os.getenv("NVD_API_KEY")
    vulncheck_api_token = os.getenv("VULNCHECK_API_TOKEN")
    command_prefix = os.getenv("DISCORD_COMMAND_PREFIX", "!")
    kevvy_web_url = os.getenv("KEVVY_WEB_URL")
    logging_channel_id = os.getenv("LOGGING_CHANNEL_ID")
    disable_discord_logging = (
        os.getenv("DISABLE_DISCORD_LOGGING", "false").lower() == "true"
    )

    logger.info("--- Bot Configuration ---")
    logger.info(f"Command Prefix: {command_prefix}")
    logger.info(f"NVD API Key Provided: {bool(nvd_api_key)}")
    logger.info(f"VulnCheck API Token Provided: {bool(vulncheck_api_token)}")
    logger.info(f"Kevvy Web URL: {kevvy_web_url or 'Not Set'}")
    logger.info(f"Discord Logging Channel ID: {logging_channel_id or 'Not Set'}")
    logger.info(f"Discord Logging Disabled: {disable_discord_logging}")
    logger.info("-------------------------")
    # --- End Log Configuration ---

    if not token:
        logger.critical(
            "Missing required DISCORD_TOKEN environment variable. Bot cannot start."
        )
        raise ValueError("Missing required DISCORD_TOKEN environment variable")

    bot = SecurityBot(nvd_api_key=nvd_api_key, vulncheck_api_token=vulncheck_api_token)
    try:
        logger.info("Starting bot...")
        bot.run(token)
    except discord.LoginFailure:
        logger.critical("Failed to log in. Check the DISCORD_TOKEN.")
    except discord.HTTPException as http_err:
        logger.critical(
            f"HTTP Exception occurred during bot execution: {http_err.status} - {http_err.text}",
            exc_info=True,
        )
    except Exception as e:
        logger.critical(
            f"An unexpected error occurred running the bot: {e}", exc_info=True
        )
    finally:
        logger.info("Bot process exiting.")


if __name__ == "__main__":
    main()
