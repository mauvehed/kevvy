# PRD: Kevvy Test Coverage Enhancement

**Version:** 1.0
**Status:** Draft
**Date:** 2025-04-29

## 1. Introduction

This document outlines the requirements, plan, and design for significantly enhancing the automated test coverage of the Kevvy Discord bot. Robust test coverage is crucial for ensuring the bot's reliability, stability, maintainability, and for preventing regressions as new features are added or existing code is refactored.

## 2. Goals

The primary goals of this initiative are to:

*   **Increase Code Coverage:** Achieve a target overall code coverage of **> 80%** as measured by `pytest-cov`.
*   **Ensure Critical Path Reliability:** Guarantee that core functionalities like message processing (`on_message`), command handling, and background tasks (`check_cisa_kev_feed`, `send_stats_to_webapp`) are thoroughly tested under various conditions.
*   **Validate Core Logic:** Verify the correctness of business logic related to CVE/KEV lookups, severity thresholds, verbosity settings, and data processing.
*   **Test Integrations:** Ensure proper interaction between different components (Core Bot, Cogs, CVEMonitor, API Clients, Database).
*   **Cover Edge Cases & Errors:** Test expected error handling paths, invalid inputs, and boundary conditions.
*   **Boost Developer Confidence:** Enable developers to make changes and add features with higher confidence that they are not breaking existing functionality.
*   **Improve Maintainability:** Well-tested code is easier and safer to refactor and maintain over time.

## 3. Existing Test Coverage (Summary)

The current test suite (`tests/`) provides a foundational level of coverage, primarily focused on unit/integration testing of specific components with external dependencies mocked:

*   **KEV Command Cog (`cogs/kev_commands.py` - ~70%):** Tests cover the basic functionality of slash commands related to enabling, disabling, and setting the KEV feed channel (`/kev feed enable/disable/set`). Mocking is used for database interactions.
*   **Database Utilities (`db_utils.py` - ~59%):** Core database operations, such as setting/getting KEV configurations, guild/channel CVE configurations, and retrieving seen KEVs, have reasonable test coverage. Tests likely use an in-memory SQLite database or mock cursor results.
*   **CVE Monitor (`cve_monitor.py` - ~52%):** Key utility functions like `find_cves` (matching CVE patterns) and the basic structure generation of `create_cve_embed` and `create_kev_status_embed` (checking presence of core fields, title, color based on mocked data) are tested. External client calls are typically mocked.
*   **CVE Lookup Cog (`cogs/cve_lookup.py` - ~28%):** The most basic success path for the `/cve lookup` command is likely covered, mocking the NVD client interaction.

While these tests are valuable, they primarily focus on isolated component logic and "happy path" scenarios.

## 4. Current State & Problem Definition (Coverage Gaps)

Despite the existing tests, a recent analysis using `pytest-cov` revealed an overall code coverage of approximately **30%**. This indicates significant gaps, particularly in integration points and core operational logic.

Key areas with low or non-existent coverage include:

*   **Core Bot Logic (`kevvy/bot.py` - ~11%):** The main event loop (`on_message`), background task execution (`check_cisa_kev_feed`, `send_stats_to_webapp`), bot lifecycle events (`setup_hook`, `close`), statistic collection, caching logic, and error handling within these core functions are largely untested.
*   **External API Clients (`kevvy/*_client.py` - ~11-20%):** The internal logic responsible for making HTTP requests, parsing responses (success and error), handling rate limits, and managing specific client state (like seen KEVs) is not adequately tested.
*   **Complex Cog Logic (`kevvy/cogs/cve_lookup.py` - Remaining ~72%):** Beyond the basic lookup, complex filtering logic (`/cve latest`), channel/verbosity/threshold management subcommands, and the cog's own `on_message` handler lack sufficient testing.
*   **Error Handling:** Many `try...except` blocks across the codebase, designed to handle specific errors (API errors, Discord errors, database errors), are not validated by tests.
*   **Untested Modules:** `kevvy/cogs/diagnostics.py` (0%) and `kevvy/discord_log_handler.py` (~19%) have minimal or no coverage.

**Risks of Current State:**

*   High likelihood of regressions going unnoticed.
*   Potential for unexpected runtime failures in untested code paths.
*   Increased difficulty and risk associated with refactoring or adding features.
*   Reduced confidence in the stability and correctness of deployed versions.

## 5. Proposed Solution & Plan for Enhancement

We will adopt an iterative approach to improving test coverage, prioritizing the most critical and least-tested modules first. The primary tools will be `pytest`, `pytest-asyncio`, `pytest-cov` (for measuring progress), and `pytest-mock` (or `unittest.mock`) for isolating components and simulating external dependencies (Discord API, HTTP APIs, Database).

**Testing Phases:**

1.  **Phase 1: Core Bot & Message Processing (`bot.py`):**
    *   Focus on integration tests for the `on_message` handler, covering various scenarios (thresholds, verbosity, caching, errors).
    *   Test the logic and error handling of background tasks (`check_cisa_kev_feed`, `send_stats_to_webapp`).
    *   Validate statistic increments and core bot lifecycle methods.
2.  **Phase 2: API Clients & Complex Commands (`*_client.py`, `cogs/cve_lookup.py`):**
    *   Write unit tests for the internal logic of each API client (requesting, parsing, error handling).
    *   Add comprehensive tests for complex commands like `/cve latest` and the configuration management commands in `cve_lookup.py`.
3.  **Phase 3: Remaining Modules & Error Paths:**
    *   Address specific missed lines identified by `pytest-cov` in moderately covered modules (`db_utils.py`, `cve_monitor.py`, `cogs/kev_commands.py`).
    *   Add tests for currently uncovered modules (`cogs/diagnostics.py`, `discord_log_handler.py`).
    *   Specifically target untested `try...except` blocks across the codebase.

## 6. Detailed Requirements & Scope for New/Enhanced Tests (By Module)

New and enhanced tests should be added to cover the following functionalities:

**6.1. `kevvy/bot.py` (Core Bot)**

*   **`on_message` Handler:**
    *   Messages with/without CVEs.
    *   CVEs matching/failing severity thresholds.
    *   Global vs. Channel verbosity application.
    *   Cache hits and misses (`recently_processed_cves`).
    *   Updating the cache upon successful processing.
    *   Correct embed generation (verbose/non-verbose, CVE/KEV).
    *   Correct sequencing of API calls and sleeps.
    *   Hitting the `MAX_EMBEDS_PER_MESSAGE` limit and sending the notice.
    *   Error Handling: `NVDRateLimitError`, `discord.Forbidden`, `discord.HTTPException`, KEV check errors, other generic errors.
    *   Verification of stat increments (`stats_cve_lookups`, `stats_nvd_fallback_success`, error/rate limit counters).
*   **`check_cisa_kev_feed` Task:**
    *   Scenario: No new KEV entries found.
    *   Scenario: New KEV entries found.
    *   Interaction with `db.get_enabled_kev_configs()`.
    *   Correctly iterating through enabled guilds/channels.
    *   Handling missing guilds/channels (`bot.get_guild`/`get_channel` returning `None`).
    *   Correct embed creation (`_create_kev_embed`).
    *   Successful message sending (`target_channel.send`).
    *   Error Handling: CISA client errors, `discord.Forbidden`, `discord.HTTPException`.
    *   Verification of DB updates (`add_seen_kevs`).
    *   Verification of stat increments (`stats_kev_alerts_sent`, `stats_api_errors_cisa`).
*   **`send_stats_to_webapp` Task:**
    *   Verification of the collected stats payload structure.
    *   Mocking `aiohttp.ClientSession.post` for success (200/204).
    *   Mocking `aiohttp.ClientSession.post` for failures (connection error, timeout, HTTP status codes).
    *   Correct usage of `WEBAPP_ENDPOINT_URL` and `WEBAPP_API_KEY`.
*   **`setup_hook`:**
    *   Successful initialization of clients, DB.
    *   Successful loading of all extensions.
    *   Handling errors during extension loading (`commands.ExtensionError`).
    *   Successful command tree syncing.
    *   Handling errors during command tree syncing.
*   **`close`:**
    *   Verification that background tasks are cancelled.
    *   Verification that `aiohttp.ClientSession` and `db` connections are closed.
*   **Signal Handling:** (Best-effort testing, might be limited).
*   **Statistic Increments:** Explicitly assert that relevant counters are modified under the appropriate conditions tested above and in `on_app_command_error`.

**6.2. API Clients (`nvd_client.py`, `cisa_kev_client.py`, `vulncheck_client.py`)**

*   Mock underlying `aiohttp` requests/responses.
*   Test successful response parsing into expected data structures.
*   Test handling of API error status codes (e.g., 404, 429, 5xx) and raising/returning appropriate indicators.
*   Test internal helper methods (e.g., `_parse_cve_details`).
*   `CisaKevClient`: Test interaction with mocked DB for loading/saving seen KEV IDs.

**6.3. Cogs (`cogs/cve_lookup.py`, `cogs/kev_commands.py`, `cogs/diagnostics.py`)**

*   Cover **all** defined slash commands and subcommands.
*   Test input validation (e.g., correct CVE format, choice validation).
*   Mock interactions with `bot`, `db`, `cve_monitor`, clients as needed.
*   Verify correct ephemeral/non-ephemeral responses are sent.
*   Verify correct embeds/messages are generated.
*   Test permission checks (`@app_commands.checks.has_permissions`).
*   `cogs/cve_lookup.py`:
    *   Test `/cve latest` filtering logic extensively with various combinations.
    *   Test all `/verbose`, `/threshold`, `/channels` subcommands, verifying DB calls and interaction responses.
    *   Test the cog's internal `on_message` handler logic (if applicable and distinct from `bot.on_message`).
*   `cogs/kev_commands.py`: Add tests for remaining error paths/conditions.
*   `cogs/diagnostics.py`: Add unit tests covering the functionality of its commands.

**6.4. `cve_monitor.py`**

*   Test `check_severity_threshold` with various scores and threshold levels.
*   Test `get_severity_string` logic.
*   Test embed creation (`create_cve_embed`, `create_kev_status_embed`) with edge cases: missing data fields, excessively long strings requiring truncation, different verbosity settings.
*   Verify correct color selection based on severity.

**6.5. `db_utils.py`**

*   Test all CRUD operations for `cve_guild_config`, `cve_channel_configs`, `kev_config`, `kev_seen_entries`, etc.
*   Test `get_effective_verbosity` scenarios thoroughly.
*   Test `load_seen_kevs` and `add_seen_kevs`.
*   Mock database connection/cursor errors (`sqlite3.Error`) and verify they are caught and logged appropriately.
*   Test logging methods (`log_cve_alert_history`, `log_kev_latest_query`).

**6.6. `discord_log_handler.py`**

*   Test the `emit` method with mocked log records.
*   Mock `bot.get_channel` to return a mock channel or `None`.
*   Mock `channel.send`.
*   Verify log message formatting.
*   Test handling when the target channel is not found or inaccessible.

## 7. Success Metrics

*   **Primary:** Overall code coverage reported by `pytest --cov=kevvy` increases from ~30% to **> 80%**.
*   **Secondary:** Coverage for critical modules (`bot.py`, `cogs/cve_lookup.py`, `nvd_client.py`, `cisa_kev_client.py`) reaches **> 80%**.
*   CI builds incorporating coverage checks pass consistently.
*   Qualitative: Observed reduction in regressions and unexpected runtime errors related to untested areas.

## 8. Open Issues / Future Considerations

*   Testing true concurrency and potential race conditions remains challenging with standard unit/integration tests.
*   Consideration of adding end-to-end tests using a dedicated test bot instance (potentially out of scope for this initial push).
*   Integrating coverage thresholds into the CI pipeline to automatically fail builds if coverage drops below the target. 