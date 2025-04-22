import json
import os
from dotenv import load_dotenv
from kevvy.bot import SecurityBot
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')

def main():
    load_dotenv()
    
    token = os.getenv('DISCORD_TOKEN')
    nvd_api_key = os.getenv('NVD_API_KEY')
    vulncheck_api_token = os.getenv('VULNCHECK_API_TOKEN')
    
    if not token:
        raise ValueError("Missing required DISCORD_TOKEN environment variable")

    bot = SecurityBot(nvd_api_key=nvd_api_key, vulncheck_api_token=vulncheck_api_token)
    bot.run(token)

if __name__ == "__main__":
    main() 