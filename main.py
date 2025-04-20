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
    # vulners_api_key = os.getenv('VULNERS_API_KEY') # Removed Vulners key
    nvd_api_key = os.getenv('NVD_API_KEY') # Added optional NVD key
    
    # if not token or not vulners_api_key: # Updated check
    #     raise ValueError("Missing required environment variables")
    if not token:
        raise ValueError("Missing required DISCORD_TOKEN environment variable")

    # Create and run the bot
    # bot = SecurityBot(vulners_api_key) # Updated instantiation
    bot = SecurityBot(nvd_api_key=nvd_api_key)
    bot.run(token)

if __name__ == "__main__":
    main() 