<h1 align="center">
  <a href="https://github.com/mauvehed/cve-search-discord">
    <!-- Update link/image if logo exists -->
    <!-- <img src="docs/images/cve-search_logo.png" alt="cve-search Logo" width="100" height="100"> -->
  </a>
</h1>

<div align="center">
  **cve-search-discord**
  <br />
  A Discord bot for automatically searching CVE details using the NVD API.
  <br />

  <a href="https://github.com/mauvehed/cve-search-discord/issues/new?assignees=&labels=bug&template=01_BUG_REPORT.md&title=bug%3A+">Report a Bug</a>
  -
  <a href="https://github.com/mauvehed/cve-search-discord/issues/new?assignees=&labels=enhancement&template=02_FEATURE_REQUEST.md&title=feat%3A+">Request a Feature</a>
  -
  <a href="https://github.com/mauvehed/cve-search-discord/issues/new?assignees=&labels=enhancement&template=03_CODEBASE_IMPROVEMENT.md&title=dev%3A+">Suggest Improvement</a>

</div>

<div align="center">
<br />

[![CodeQL](https://github.com/mauvehed/cve-search-discord/actions/workflows/codeql-analysis.yml/badge.svg?branch=main)](https://github.com/mauvehed/cve-search-discord/actions/workflows/codeql-analysis.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/4ec1fc69d8a14048a80124167f6f7664)](https://www.codacy.com/gh/mauvehed/cve-search-discord/dashboard)
[![Project license](https://img.shields.io/github/license/mauvehed/cve-search-discord.svg?style=flat-square)](LICENSE)

</div>

<details open="open">
<summary>Table of Contents</summary>

- [About](#about)
  - [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Configuration](#configuration)
  - [Running with Docker (Recommended)](#running-with-docker-recommended)
  - [Running Locally with Poetry](#running-locally-with-poetry)
- [Usage](#usage)
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

**cve-search-discord** is a Discord bot that automatically monitors chat messages for CVE (Common Vulnerabilities and Exposures) identifiers (e.g., `CVE-2023-12345`). When a CVE is detected, the bot fetches detailed information from the [NIST National Vulnerability Database (NVD) API v2.0](https://nvd.nist.gov/developers/vulnerabilities) and presents it in an informative embed directly in the channel.

Key features:
*   Automatic detection of CVE IDs in messages.
*   Fetches details from the official NVD API.
*   Displays CVSS score (v3.1/v3.0/v2.0), vector string, description, publication dates, CWEs, and reference links.
*   Consolidates responses for messages containing multiple CVEs (max 5 embeds per message by default) to prevent spam.
*   Includes a `/version` slash command to check the running bot version.

### Built With

*   <img src="https://img.shields.io/badge/Python-3.10-3776AB?style=for-the-badge&logo=python&logoColor=white" />
*   <img src="https://img.shields.io/badge/discord.py-2.5.2-5865F2?style=for-the-badge&logo=discord&logoColor=white" />
*   <img src="https://img.shields.io/badge/Poetry-1.8-60A5FA?style=for-the-badge&logo=poetry&logoColor=white" />
*   <img src="https://img.shields.io/badge/Docker-26.1-0db7ed?style=for-the-badge&logo=docker&logoColor=white" />
*   NVD API v2.0

## Getting Started

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
*   `NVD_API_KEY` (Optional): Your NVD API key. Request one [here](https://nvd.nist.gov/developers/request-an-api-key) for significantly higher request rate limits. Highly recommended for active bots.
*   `DISCORD_COMMAND_PREFIX` (Optional): The prefix for traditional commands (if any are added later). Defaults to `!`. The primary interaction is automatic detection and slash commands.

### Running with Docker (Recommended)

1.  Ensure Docker and Docker Compose are installed.
2.  Make sure you have configured your `.env` file.
3.  Build and start the container in detached mode:
    ```bash
    docker-compose up --build -d
    ```
4.  To view logs:
    ```bash
    docker-compose logs -f
    ```
5.  To stop the container:
    ```bash
    docker-compose down
    ```

### Running Locally with Poetry

1.  Ensure Python 3.10+ and Poetry are installed.
2.  Clone the repository:
    ```bash
    git clone https://github.com/mauvehed/cve-search-discord.git
    cd cve-search-discord
    ```
3.  Install dependencies:
    ```bash
    poetry install
    ```
4.  Configure your `.env` file.
5.  Run the bot:
    ```bash
    poetry run python main.py
    ```

## Usage

1.  **Invite the Bot:** Invite the configured bot to your Discord server.
2.  **Automatic Detection:** Simply type or paste a message containing one or more CVE IDs (e.g., `Check out CVE-2024-1234 and CVE-2024-5678`). The bot will automatically detect them and post embed(s) with the details.
    *   If multiple unique CVEs are in one message, the bot will post details for up to 5 of them (by default) and indicate if more were found.
3.  **Version Check:** Use the slash command `/version` to see the current running version of the bot.

## Roadmap

See the [open issues](https://github.com/mauvehed/cve-search-discord/issues) for a list of proposed features (and known issues).

- [Top Feature Requests](https://github.com/mauvehed/cve-search-discord/issues?q=label%3Aenhancement+is%3Aopen+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Top Bugs](https://github.com/mauvehed/cve-search-discord/issues?q=is%3Aissue+is%3Aopen+label%3Abug+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Newest Bugs](https://github.com/mauvehed/cve-search-discord/issues?q=is%3Aopen+is%3Aissue+label%3Abug) (Squash Em!)

## Support

Reach out to the maintainer at one of the following places:

- Contact options listed on [this GitHub profile](https://github.com/mauvehed)
- @mauvehed just about anywhere else online

## Contributing

First off, thanks for taking the time to contribute! Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make will benefit everybody else and are **greatly appreciated**.


Please read [our contribution guidelines](docs/CONTRIBUTING.md), and thank you for being involved!

## Authors & contributors

The original setup of this repository is by [mauvehed](https://github.com/mauvehed).

For a full list of all authors and contributors, see [the contributors page](https://github.com/mauvehed/cve-search-discord/contributors).

## Security

- **cve-search** follows good practices of security, but 100% security cannot be assured.
- **cve-search** is provided **"as is"** without any **warranty**. Use at your own risk.

_For more information and to report security issues, please refer to our [security documentation](docs/SECURITY.md)._

## License

This project is licensed under the **MIT license**.

See [LICENSE](LICENSE) for more information.

## Acknowledgements

Thanks to all contributors and users who have helped make this project better!

