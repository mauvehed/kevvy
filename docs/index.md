# Welcome to Kevvy Bot Documentation

**kevvy** is a Discord bot designed to help you stay informed about software vulnerabilities.

Key features include:

*   **Automatic CVE Detection:** Identifies CVE IDs in chat messages and provides details.
*   **Direct CVE Lookup:** `/cve lookup` command for specific vulnerability details.
*   **CISA KEV Monitoring:** Optional alerts for new additions to the Known Exploited Vulnerabilities catalog.
*   **Configurable Alerts:** Control alert channels and verbosity using slash commands.

For a full overview, installation instructions, and contribution guidelines, please see the main [README.md file on GitHub](https://github.com/mauvehed/kevvy/blob/main/README.md).

## Getting Started

The easiest way to get started with the bot is to simply invite it to your Discord and away you go!

<a href= "https://discord.com/api/oauth2/authorize?client_id=1363214368648724630&permissions=277025459200&scope=bot%20applications.commands">
  <img src="https://img.shields.io/badge/Add Me To Your Discord-purple?style=for-the-badge&logo=python&logoColor=white" />
</a>

### Prerequisites

*   **Docker** and **Docker Compose** (Recommended for running)
*   OR **Python 3.10+** and **Poetry** (For local development/running)
*   A **Discord Bot Token**. You can create a bot and get a token from the [Discord Developer Portal](https://discord.com/developers/applications).

### Configuration

The bot is configured using environment variables. Create a `.env` file in the project root by copying the example:

```bash
cp .env.example .env
```

Then, edit the `.env` file:

*   `DISCORD_TOKEN` (Required): Your Discord bot token.
*   `NVD_API_KEY` (Optional): Your NVD API key. Request one [here](https://nvd.nist.gov/developers/request-an-api-key) for significantly higher request rate limits. Used as the primary data source for CVE details.
*   `VULNCHECK_API_TOKEN` (Optional): Your VulnCheck API key. *(Note: This is planned for future integration as a potential primary data source but is not currently used by the core CVE lookup commands).* Get one from [VulnCheck](https://vulncheck.com/).
*   `DISCORD_COMMAND_PREFIX` (Optional): The prefix for traditional commands (if any are added later). Defaults to `!`. The primary interaction is automatic detection and slash commands.
*   `LOGGING_CHANNEL_ID` (Optional): The ID of the Discord channel to which log messages should be sent.
*   `DISABLE_DISCORD_LOGGING` (Optional): Set to `true` to disable sending logs to the Discord channel specified by `LOGGING_CHANNEL_ID`. Defaults to `false`.

### Running with Docker (Recommended)

1.  Ensure Docker and Docker Compose are installed.
2.  Make sure you have configured your `.env` file (especially `DISCORD_TOKEN`).
3.  Start the bot container in detached mode:
    ```bash
    docker-compose up -d --build
    ```
    _(This will automatically pull the `ghcr.io/mauvehed/kevvy:latest` image if you don't have it locally)._
4.  **View Logs:**
    ```bash
    docker-compose logs -f kevvy-bot
    ```
5.  **Stop Container:**
    ```bash
    docker-compose down
    ```

### Running Locally with Poetry

1.  Ensure Python 3.10+ and Poetry are installed.
2.  Clone the repository: `git clone https://github.com/mauvehed/kevvy.git && cd kevvy`
3.  Install bot dependencies: `poetry install`
4.  Configure your `.env` file.
5.  Run the bot: `poetry run python main.py`


## Commands

Explore the available slash commands:

*   [Overview](commands/index.md)
*   [KEV Commands (`/kev`)](commands/kev.md)
*   [CVE Commands (`/cve`)](commands/cve.md)
*   [Verbosity Commands (`/verbose`)](commands/verbose.md) 