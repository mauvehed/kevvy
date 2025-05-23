<h1 align="center">
  <a href="https://github.com/mauvehed/kevvy">
    <img src="docs/images/kevvy_logo_transparent.png" alt="kevvy Logo" width="200" height="200">
  </a>
</h1>

<div align="center">
  A Discord bot for searching the Common Vulnerabilities and Exposures (CVE) list and providing Known Exploitable Vulnerabilities (KEV) updates.
</div>

<div align="center">
<br />

<a href= "https://discord.com/api/oauth2/authorize?client_id=1363214368648724630&permissions=277025459200&scope=bot%20applications.commands">
  <img src="https://img.shields.io/badge/Add Me To Your Discord-purple?style=for-the-badge&logo=python&logoColor=white" />
</a>

<a href="https://kevvy.mauve.haus/">
  <img src="https://img.shields.io/badge/Live Dashboard-blue?style=for-the-badge&logo=vue.js&logoColor=white" />
</a>

<br />

[![Kevvy CI/CD](https://github.com/mauvehed/kevvy/actions/workflows/ci.yml/badge.svg)](https://github.com/mauvehed/kevvy/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mauvehed/kevvy/actions/workflows/codeql-analysis.yml/badge.svg?branch=main)](https://github.com/mauvehed/kevvy/actions/workflows/codeql-analysis.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/4ec1fc69d8a14048a80124167f6f7664)](https://www.codacy.com/gh/mauvehed/kevvy/dashboard)

<a href="https://kevvy.readthedocs.io/en/latest/">
  <img src="https://img.shields.io/badge/Documentation-blue?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Documentation Status"/>
</a>

</div>

<hr />

<br />

<details open="open">
<summary>Table of Contents</summary>

- [About](#about)
  - [Built With](#built-with)
  - [Usage](#usage)
  - [Screenshots](#screenshots)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Configuration](#configuration)
  - [Running with Docker (Recommended)](#running-with-docker-recommended)
  - [Running Locally with Poetry](#running-locally-with-poetry)
- [Roadmap](#roadmap)
- [Support](#support)
- [Contributing](#contributing)
- [Authors & contributors](#authors--contributors)
- [Security](#security)
- [License](#license)
- [Acknowledgements](#acknowledgements)

</details>

---

## About

**kevvy** is a Discord bot with the following main functions:

1.  **Automatic CVE Detection:** It automatically monitors chat messages for CVE (Common Vulnerabilities and Exposures) identifiers (e.g., `CVE-2023-12345`). When a CVE is detected, the bot fetches detailed information using VulnCheck as the primary source if a `VULNCHECK_API_TOKEN` is provided, falling back to the NIST National Vulnerability Database (NVD) API v2.0 otherwise.
2.  **Direct CVE Lookup:** Users can explicitly request details for a specific CVE using the `/cve lookup` command.
3.  **CISA KEV Monitoring:** Optionally monitors the [CISA Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and sends alerts for new entries to configured channels.

Key features:

- Automatic detection of CVE IDs in messages.
- Direct lookup of specific CVEs via `/cve lookup`.
- Fetches details using VulnCheck first (if `VULNCHECK_API_TOKEN` is configured), then NVD.
- Displays CVSS score (v3.1/v3.0/v2.0), vector string, description, publication dates, CWEs, and reference links.
- Consolidates responses for messages containing multiple CVEs (max 5 embeds per message by default, with delays between sends) to prevent spam.
- Optionally checks the CISA KEV catalog periodically and posts alerts for new entries to a designated channel (configurable per server).

### Built With

- <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
- <img src="https://img.shields.io/badge/discord.py-2.x-5865F2?style=for-the-badge&logo=discord&logoColor=white" />
- <img src="https://img.shields.io/badge/Poetry-1.8+-60A5FA?style=for-the-badge&logo=poetry&logoColor=white" />
- <img src="https://img.shields.io/badge/Docker-26.1+-0db7ed?style=for-the-badge&logo=docker&logoColor=white" />
- <img src="https://img.shields.io/badge/aiohttp-library-blueviolet?style=for-the-badge&logo=python&logoColor=white" />
- <img src="https://img.shields.io/badge/NVD API v2.0-darkgreen?style=for-the-badge&logo=python&logoColor=white" />
- <img src="https://img.shields.io/badge/CISA KEV Catalog-red?style=for-the-badge&logo=python&logoColor=white" />

## Usage

1.  **Invite the Bot:** Invite the configured bot to your Discord server.
2.  **Automatic Detection:** Simply type or paste a message containing one or more CVE IDs (e.g., `Check out CVE-2024-1234 and CVE-2024-5678`). The bot will automatically detect them and post embed(s) with the details. The verbosity of the details depends on server and channel settings (see `/verbose` commands).
    - If multiple unique CVEs are in one message, the bot will post details for up to 5 of them (by default) and indicate if more were found.
3.  **Direct CVE Lookup:** Use the slash command `/cve lookup cve_id:<CVE-ID>` (e.g., `/cve lookup cve_id:CVE-2024-0001`) to get details for a specific vulnerability.
4.  **CISA KEV Alerts (Optional Setup):**
    - `/kev feed enable channel:<#your-alert-channel>`: A server administrator with 'Manage Server' permissions can run this command to enable KEV monitoring and designate a specific channel for alerts.
    - `/kev feed disable`: Disables KEV alerts for the server.
    - `/kev feed status`: Checks the status of KEV monitoring.
    - `/kev latest [count] [days] ...`: Shows the latest KEV entries with optional filters.
5.  **CVE Monitoring Channel Configuration:**
    - `/cve channel add channel:<#channel>`: Enables automatic CVE scanning for messages in the specified channel. Ensures global monitoring is also enabled for the server.
    - `/cve channel remove channel:<#channel>`: Removes automatic CVE monitoring configuration for the specified channel.
    - `/cve channel list`: Shows the global CVE monitoring status (enabled/disabled) and lists channels configured for scanning.
    - `/cve channel enable_global`: Enables automatic CVE message scanning globally for the server (channels still need to be added via `/cve channel add` to be monitored).
    - `/cve channel disable_global`: Disables automatic CVE message scanning globally for the server. No messages will be scanned in any channel.
6.  **Alert Verbosity Configuration:**
    - `/verbose enable_global`: Sets the default alert style to **verbose** for the whole server.
    - `/verbose disable_global`: Sets the default alert style to **standard** (non-verbose) for the whole server.
    - `/verbose set channel:<#channel> verbosity:<True|False>`: Overrides the verbosity setting for a specific channel.
    - `/verbose unset channel:<#channel>`: Removes the override for a specific channel (it uses the global setting).
    - `/verbose setall verbosity:<True|False>`: Sets an override for **all** channels.
    - `/verbose status [channel]`: Shows the current global and channel-specific verbosity settings.
7.  **CVE Threshold Configuration:**
    - `/cve threshold set <level>`: Sets the minimum CVSS severity (`critical`, `high`, `medium`, `low`, `all`) required for a CVE mentioned in a message to trigger an automatic alert (global server setting).
    - `/cve threshold view`: Shows the current global severity threshold.
    - `/cve threshold reset`: Resets the global severity threshold to `all`.
8.  **Help Command:**

    - `/kevvy help [command_name]`: Shows a general overview of all command groups, or detailed help for a specific command or command group (e.g., `/kevvy help cve` or `/kevvy help cve lookup`).

9.  **Admin Commands (Bot Owner Only):**
    - `/kevvy admin status`: Shows the operational status of the bot (uptime, server count, etc.)
    - `/kevvy admin stats`: Shows detailed statistics about the bot's operations (command usage, CVE lookups, etc.)
    - `/kevvy admin reload [extension]`: Reloads bot extensions/cogs (useful for applying code changes without restarting)
    - `/kevvy admin version`: Shows detailed version information for the bot
    - `/kevvy admin servers`: Lists all servers the bot is in
    - `/kevvy admin debug <code>`: Evaluates Python code for debugging
    - `/kevvy admin announce <message>`: Sends an announcement message to all servers the bot is in
      > Note: These commands are restricted to the bot owner only (configured via `BOT_OWNER_ID`).

## Screenshots

Here's the bot in action:

**Automatic CVE Detection and Information:**

![CVE Information Embed](docs/images/CVE%20Info.png)

**CISA KEV Alert Notification:**

![KEV Alert Notification](docs/images/KEV%20Alert.png)

**Web Dashboard Status:**

![Kevvy Dashboard](docs/images/kevvy_dashboard.png)

## Getting Started

### Prerequisites

- **Docker** and **Docker Compose** (Recommended for running)
- OR **Python 3.10+** and **Poetry** (For local development/running)
- A **Discord Bot Token**. You can create a bot and get a token from the [Discord Developer Portal](https://discord.com/developers/applications).

### Configuration

The bot is configured using environment variables. Create a `.env` file in the project root by copying the example:

```bash
cp .env.example .env
```

Then, edit the `.env` file:

- `DISCORD_TOKEN` (Required): Your Discord bot token.
- `NVD_API_KEY` (Optional): Your NVD API key. Request one [here](https://nvd.nist.gov/developers/request-an-api-key) for significantly higher request rate limits. Used as a fallback data source if VulnCheck is not configured or fails.
- `VULNCHECK_API_TOKEN` (Optional): Your VulnCheck API key. If provided, Kevvy will use VulnCheck as the primary source for CVE details, offering richer information. Get one from [VulnCheck](https://vulncheck.com/).
<!-- KEVVY_WEB_URL and KEVVY_WEB_API_KEY removed as they are for a private feature -->
- `DISCORD_COMMAND_PREFIX` (Optional): The prefix for traditional commands (if any are added later). Defaults to `!`. The primary interaction is automatic detection and slash commands.
- `LOGGING_CHANNEL_ID` (Optional): The ID of the Discord channel to which log messages should be sent.
- `DISABLE_DISCORD_LOGGING` (Optional): Set to `true` to disable sending logs to the Discord channel specified by `LOGGING_CHANNEL_ID`. Defaults to `false`.

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

## Roadmap

See the [open issues](https://github.com/mauvehed/kevvy/issues) for a list of proposed features (and known issues).

- [Top Feature Requests](https://github.com/mauvehed/kevvy/issues?q=label%3Aenhancement+is%3Aopen+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Top Bugs](https://github.com/mauvehed/kevvy/issues?q=is%3Aissue+is%3Aopen+label%3Abug+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Newest Bugs](https://github.com/mauvehed/kevvy/issues?q=is%3Aopen+is%3Aissue+label%3Abug) (Squash Em!)

## Support

Reach out to the maintainer at one of the following places:

- Contact options listed on [this GitHub profile](https://github.com/mauvehed)
- @mauvehed just about anywhere else online

## Contributing

First off, thanks for taking the time to contribute! Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make will benefit everybody else and are **greatly appreciated**.

Please read [our contribution guidelines](CONTRIBUTING.md), and thank you for being involved!

The project includes automated testing using `pytest` and CI checks via GitHub Actions to help maintain code quality.

## Authors & contributors

The original setup of this repository is by [mauvehed](https://github.com/mauvehed).

For a full list of all authors and contributors, see [the contributors page](https://github.com/mauvehed/kevvy/contributors).

## Security

- **kevvy** follows good practices of security, but 100% security cannot be assured.
- **kevvy** is provided **"as is"** without any **warranty**. Use at your own risk.

_Please report security vulnerabilities privately via **GitHub's Private Vulnerability Reporting feature** (go to the 'Security' tab -> 'Report a vulnerability'). For more information on our security practices, see our [security policy](docs/SECURITY.md)._

## License

This project is licensed under the **MIT license**.

See [LICENSE](LICENSE) for more information.

## Acknowledgements

- Data sourced primarily from [VulnCheck](https://vulncheck.com/) (if configured) and [NVD](https://nvd.nist.gov).
- Known Exploited Vulnerabilities feed monitored via [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- Thanks to all contributors and users who have helped make this project better!
