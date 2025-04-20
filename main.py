import json
import os
from dotenv import load_dotenv
from cve_search.bot import SecurityBot
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')

def main():
    # Load environment variables
    load_dotenv()
    
    # Get configuration
    token = os.getenv('DISCORD_TOKEN')
    vulners_api_key = os.getenv('VULNERS_API_KEY')
    
    if not token or not vulners_api_key:
        raise ValueError("Missing required environment variables")

    # Create and run the bot
    bot = SecurityBot(vulners_api_key)
    bot.run(token)

if __name__ == "__main__":
    main() 