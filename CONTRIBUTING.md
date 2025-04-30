# Contributing to Kevvy

First off, thank you for considering contributing to Kevvy! We appreciate your time and effort. Contributions are essential for making Kevvy better for everyone.

This document provides guidelines for contributing to the project, setting up your development environment, and understanding the workflow.

Please note we have a [Code of Conduct](CODE_OF_CONDUCT.md), please follow it in all your interactions with the project.

## Table of Contents

- [Ways to Contribute](#ways-to-contribute)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)
- [Setting Up Your Development Environment](#setting-up-your-development-environment)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Running with Docker/Podman for Development (Using dev.sh)](#running-with-dockerpodman-for-development-using-devsh)
  - [Running Locally with Poetry](#running-locally-with-poetry)
- [Development Workflow](#development-workflow)
  - [Branching](#branching)
  - [Running Tests](#running-tests)
  - [Writing Commit Messages](#writing-commit-messages)
  - [Submitting Pull Requests](#submitting-pull-requests)
- [Project Structure Overview](#project-structure-overview)
- [Documentation](#documentation)
- [Getting Help](#getting-help)

## Ways to Contribute

There are many ways to contribute to Kevvy:

- **Reporting Bugs:** If you find a bug, please report it by opening an issue.
- **Suggesting Enhancements:** Have an idea for a new feature or improvement? Open an issue to discuss it.
- **Improving Documentation:** Help us make the documentation clearer and more comprehensive.
- **Writing Code:** Fix bugs or implement new features.
- **Adding Tests:** Improve test coverage for better stability.

## Reporting Bugs

Before creating a bug report, please check existing [GitHub Issues](https://github.com/mauvehed/kevvy/issues) to see if the bug has already been reported.

If you find a new bug, please provide a clear and concise report including:

- Steps to reproduce the bug.
- Expected behavior.
- Actual behavior.
- Screenshots (if applicable).
- Your environment details (e.g., OS, Python version, Docker version if used).

## Suggesting Enhancements

We welcome suggestions for new features and improvements! Please open an issue to describe your suggestion, including:

- The problem your enhancement solves.
- A clear description of the proposed solution.
- Any potential alternatives you considered.

## Setting Up Your Development Environment

### Prerequisites

- **Git:** For version control.
- **Python:** Version 3.10 or higher.
- **Poetry:** For dependency management and packaging. Install it following the [official Poetry documentation](https://python-poetry.org/docs/#installation).
- **(Optional) Docker & Docker Compose:** If you plan to build or run the Docker image locally.
  - Note: A development image tagged as `:dev` may be available (e.g., `ghcr.io/mauvehed/kevvy:dev`). Check the project's container registry or `docker-compose.yml` for details on using development-specific images.

### Installation

1.  **Fork the Repository:** Create your own fork of the [mauvehed/kevvy](https://github.com/mauvehed/kevvy) repository on GitHub.
2.  **Clone Your Fork:**
    ```bash
    git clone https://github.com/YOUR_USERNAME/kevvy.git
    cd kevvy
    ```
3.  **Install Dependencies:** Use Poetry to install project dependencies, including development dependencies.
    ```bash
    poetry install
    ```
    This command creates a virtual environment specific to this project and installs all required packages listed in `pyproject.toml`.

### Configuration

1.  **Copy the Example Environment File:**
    ```bash
    cp .env.example .env
    ```
2.  **Edit `.env`:** Fill in the necessary environment variables, especially `DISCORD_TOKEN` for running the bot locally. Refer to the main `README.md` for details on each variable.

### Running with Docker/Podman for Development (Using dev.sh)

If you have Docker or Podman installed along with `docker-compose` or `podman-compose`, the easiest way to run the bot for development, including automatic rebuilding and log viewing, is using the provided script:

```bash
./dev.sh
```

This script typically uses a development-specific compose file (like `docker-compose.dev.yml`) which might mount your local code into the container for live updates. It handles stopping old containers, building the new image (often tagged `:dev`), running the new container in the background, and then attaching to the logs (`logs -f`).

### Running Locally with Poetry

If you prefer not to use containers, you can run the bot directly using Poetry after completing the Installation and Configuration steps:

```bash
poetry run python main.py
```

## Development Workflow

### Branching

When working on a specific GitHub Issue, please check if a branch has already been created for that issue (e.g., `issue/123-description`). If such a branch exists, please use it for your development work related to that ticket.

If no specific branch exists for the issue, create a new branch for each feature or bug fix you work on. Base your branch off the `main` branch. Use a descriptive name, e.g., `feat/add-new-command` or `fix/resolve-lookup-bug`.

```bash
# Example: Checking out a pre-existing issue branch
git fetch origin
git checkout issue/123-description

# Example: Creating a new branch
git checkout main
git pull origin main # Ensure your main branch is up-to-date
git checkout -b your-branch-name
```

### Running Tests

We use `pytest` for testing. Tests are located in the `tests/` directory. Ensure all existing tests pass and add new tests for your changes.

- **Run all tests:**
  ```bash
  poetry run pytest
  ```

### Writing Commit Messages

We follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification. This helps automate changelog generation and makes commit history easier to understand.

Examples:

- `feat: add /cve latest command`
- `fix: correct assertion in test_channel_list_enabled`
- `docs: update README with new channel commands`
- `refactor: simplify embed creation logic`
- `test: add tests for verbose status command`
- `chore: update dependencies`

### Submitting Pull Requests

1.  Commit your changes following the commit message guidelines.
2.  Push your branch to your fork:
    ```bash
    git push origin your-branch-name
    ```
3.  Open a Pull Request (PR) from your fork's branch to the `main` branch of the `mauvehed/kevvy` repository.
4.  Provide a clear title and description for your PR, explaining the changes and linking to any relevant issues (e.g., "Fixes #123").
5.  Ensure all automated checks (CI/CD, linting, tests) pass on your PR.
6.  Participate in the code review process, addressing any feedback.

## Project Structure Overview

- `kevvy/`: Contains the main bot source code.
  - `cogs/`: Houses the different command groups (Cogs).
  - `clients/`: (If applicable) API client implementations (e.g., `nvd_client.py`).
  - `bot.py`: The main `discord.Bot` subclass definition.
  - `db_utils.py`: Database interaction logic.
  - `cve_monitor.py`: Helper class for CVE processing.
  - ... (other core modules)
- `tests/`: Contains all automated tests (`pytest`).
- `docs/`: Project documentation source files (for `mkdocs`).
- `main.py`: The entry point for running the bot.
- `pyproject.toml`: Defines project metadata, dependencies, and tool configurations (Poetry, linters, etc.).
- `.env.example`: Example environment variable file.
- `Dockerfile`, `docker-compose.yml`: Docker configuration.
- `README.md`, `PRD.md`: High-level project information.
- `LICENSE`: Project license.

## Documentation

Documentation is important! If your changes affect user-facing features, commands, or configuration, please update the relevant documentation:

- `README.md`: For the main overview and usage examples.
- `PRD.md`: For the detailed command specification.
- `docs/`: For the `mkdocs` generated documentation site (especially files in `docs/commands/`).

To build and preview the documentation locally:

```bash
# Assuming mkdocs is installed via development dependencies
poetry run mkdocs serve
```

Then open `http://127.0.0.1:8000` in your browser.

## Getting Help

If you have questions about contributing or need help with your development setup, feel free to:

- Open an issue on GitHub.
- Reach out to the maintainer ([@mauvehed](https://github.com/mauvehed)).

Thank you for contributing to Kevvy!
