# Kevvy Command Structure PRD

## 1. Command Overview
This PRD defines the structure and behavior of Kevvy's security-related commands, focusing on CVE and CISA KEV catalog monitoring and lookups within Discord.

## 2. Core Features

### 2.1 Automatic Message Scanning (`on_message`)
**Purpose:** Passively scan messages in configured channels for CVE IDs and provide relevant information.
**Permission:** Relies on channel configurations set by users with "Manage Server" permission.
**Behavior:**
- Listens to messages in guilds where the bot is present.
- Ignores messages from bots (including itself) and messages in DMs.
- Uses regex (`CVE-\d{4}-\d{4,}`) to detect potential CVE IDs.
- For each detected CVE ID:
    - Checks if the message's channel is configured for CVE monitoring (`cve_channel_configs` table).
    - If configured:
        - Fetches CVE details (NVD).
        - Checks if the CVE's severity meets the *globally* configured threshold (`/cve threshold`).
        - Determines the appropriate verbosity (checking channel override then global setting via `/verbose` commands).
        - Creates a CVE information embed (standard or verbose).
        - Checks if the CVE is present in the CISA KEV catalog.
        - Sends the CVE embed to the channel.
        - If in KEV, sends a separate KEV information embed.
- Handles potential errors during API lookups gracefully (e.g., logs errors, may send a notification if lookup fails).

### 2.2 `/cve` Group
**Purpose:** Manage CVE lookups and monitoring configuration.
**Base Permission:** None (public access for lookup)

#### 2.2.1 `/cve lookup <cve_id>`
**Purpose:** Look up detailed information about a specific CVE.
**Parameters:**
- `cve_id`: The CVE identifier (e.g., "CVE-2024-1234")
**Behavior:**
- Searches NVD for the CVE ID.
- Displays comprehensive CVE information in a standard embed format (currently, verbosity settings do not affect manual lookups).
- Includes a check and notes if the CVE is present in the CISA KEV catalog.
**Response Format (Embed):**
- Title: CVE ID
- URL: Link to NVD page
- Description: CVE description text.
- Fields: CVSS Score, Severity, Vector, CWEs, Published Date, Modified Date, References, KEV Status (if applicable).

#### 2.2.2 `/cve channels` Group
**Purpose:** Configure channels for automatic CVE monitoring (`on_message`). Supports multiple configurations per server.
**Permission:** Requires "Manage Server" permission

##### Subcommands:
- `/cve channels add <channel>`: Add/Enable automatic CVE monitoring for the specified channel. Creates a default guild configuration if none exists.
- `/cve channels remove <channel>`: Remove/Disable automatic CVE monitoring for the specified channel.
- `/cve channels list`: List all channels currently configured for automatic CVE monitoring in the server.
- `/cve channels status`: Show if CVE monitoring is enabled globally for the server and list configured channels. *(Note: Replaces previous `/cve channel list` functionality)*
- `/cve channels disable_global`: Disable CVE monitoring globally for the server. This stops `on_message` checks entirely, regardless of channel configs. *(Note: Replaces previous `/cve channel disable` functionality)*
- `/cve channels enable_global`: Enable CVE monitoring globally for the server (if previously disabled). Channels still need to be added via `add`. *(Note: Implicitly handled by `add` if guild config doesn't exist, but useful for re-enabling after `disable_global`)*

#### 2.2.3 `/cve latest`
**Purpose:** Display the most recent CVEs published on NVD.
**Parameters:**
- `count`: (Optional) Number of CVEs to display (default: 5, max: 10)
- `days`: (Optional) Look back period in days (default: 7, max: 30)
- `severity`: (Optional) Filter by minimum severity level (`critical`, `high`, `medium`, `low`).
- `kev_only`: (Optional, Boolean) Show only CVEs also present in the KEV catalog.
**Behavior:**
- Fetches recent CVEs from NVD based on publication date range (`days` parameter).
- Displays in chronological order (most recent first).
- Includes basic information (ID, Score, Title excerpt, Published date).
- Supports filtering by severity and KEV status.
**Response Format (Embed):**
- Title: Includes date range and any filters used.
- Description: List of CVEs matching criteria.

**Future Enhancements:**
- More advanced filtering (vendor, product, vulnerability type, exploit status).

#### 2.2.4 `/verbose` Group (Top-Level)
**Purpose:** Configure global and per-channel verbosity of *automatic* CVE alerts triggered by messages (`on_message`).
**Permission:** Requires "Manage Server" permission

**Default Behavior:**
- The default global setting is **non-verbose** (standard format).
- Channels inherit the global setting unless overridden.

**Subcommands:**
- `/verbose enable_global`: Set the default alert format to verbose globally.
- `/verbose disable_global`: Set the default alert format to standard (non-verbose) globally.
- `/verbose set <channel> <verbosity: True|False>`: Set a verbosity override (verbose/standard) for a specific channel.
- `/verbose unset <channel>`: Remove the verbosity override for a specific channel, reverting it to the global setting.
- `/verbose setall <verbosity: True|False>`: Set a verbosity override for **all** currently configured channels.
- `/verbose status [channel]`: Show the current global verbosity setting and any channel-specific overrides. If a channel is specified, shows the effective setting for that channel.

**Verbose Mode Differences (Automatic `on_message` Responses):**
- **Standard Mode:**
    - **CVE Embed:** Shows minimal info: CVE ID, Title link, CVSS Score.
    - **KEV Embed (if applicable):** Shows minimal info: Confirmation, NVD link.
- **Verbose Mode:**
    - **CVE Embed:** Shows full details: CVE ID, Title, Full Description, CVSS Score & Vector, Dates, CWEs, References.
    - **KEV Embed (if applicable):** Shows full KEV details.

**Interaction:**
- Per-channel settings (`/verbose set`) take precedence over the global setting.
- `/verbose setall` overrides all existing per-channel settings.

#### 2.2.5 `/cve threshold` Group
**Purpose:** Set the minimum severity level for CVEs to trigger *automatic* alerts via `on_message`. This is a **global** setting for the server.
**Permission:** Requires "Manage Server" permission

**Subcommands:**
- `/cve threshold set <level>`: Set the global minimum severity level.
    - Levels: "critical", "high", "medium", "low", "all" (default)
- `/cve threshold view`: Display the current global threshold.
- `/cve threshold reset`: Reset the global threshold to the default ("all").

#### 2.2.6 `/cve format` Group (Future)
**Purpose:** Allow servers to customize how automatic CVE alerts appear.
**Permission:** Requires "Manage Server" permission
*(Details omitted as it's a future feature)*

### 2.3 `/kev` Group
**Purpose:** Manage CISA KEV catalog monitoring and lookups.
**Base Permission:** None (public access for lookups)

#### 2.3.1 `/kev feed` Group
**Purpose:** Manage CISA KEV feed monitoring configuration (periodic checks for *new* KEV entries).
**Permission:** Requires "Manage Server" permission

##### Subcommands:
- `/kev feed enable <channel>`: Enable KEV feed alerts in the specified channel. *(Note: Currently supports only one channel per server for the feed).*
- `/kev feed disable`: Disable KEV feed alerts for the server.
- `/kev feed status`: Check current KEV feed monitoring status and configured channel.

#### 2.3.2 `/kev latest`
**Purpose:** Display the most recent entries added to the KEV catalog.
**Parameters:**
- `count`: (Optional) Number of entries to display (default: 5, max: 10)
- `days`: (Optional) Look back period in days based on date added to KEV (default: 30, max: 30)
- `vendor`: (Optional) Filter by vendor name.
- `product`: (Optional) Filter by product name.
**Behavior:**
- Fetches recent KEV entries from CISA KEV data source.
- Displays in chronological order based on date added.
- Includes comprehensive KEV information for each entry.
- Supports filtering options.
**Response Format (Embed):**
- Title: Indicates date range and filters.
- Description: List of KEV entries with details (CVE ID, Title, Vendor, Product, Date Added, Due Date, Ransomware Use).

**Future Enhancements:**
- Enhanced filtering (severity - requires mapping CVE severity to KEV entry, ransomware use).
- Multiple feed channels.

## 3. Database Schema
*(Consolidated and accurate representation)*
```sql
-- Stores global and KEV feed config per guild
CREATE TABLE kev_config (
    guild_id INTEGER PRIMARY KEY,
    feed_channel_id INTEGER,            -- Channel for periodic KEV feed checks
    feed_enabled BOOLEAN DEFAULT false,
    last_kev_check TIMESTAMP,           -- Timestamp of last periodic KEV feed check
    -- Global CVE Settings moved here
    cve_monitoring_enabled BOOLEAN DEFAULT true, -- Master switch for on_message scanning
    cve_verbose_mode BOOLEAN DEFAULT false,      -- Global default verbosity for on_message
    cve_severity_threshold TEXT DEFAULT 'all',   -- Global severity threshold for on_message
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Stores configuration for individual channels for CVE on_message scanning
CREATE TABLE cve_channel_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    enabled BOOLEAN DEFAULT true,         -- If monitoring is active for this specific channel
    verbose_mode BOOLEAN,                 -- Per-channel verbosity override (NULL means inherit global)
    -- severity_threshold TEXT,           -- Per-channel threshold (Future Enhancement, currently global)
    -- alert_format TEXT,                 -- Per-channel format (Future Enhancement)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (guild_id, channel_id),
    FOREIGN KEY (guild_id) REFERENCES kev_config(guild_id) ON DELETE CASCADE
);

-- Optional: History/Logging Tables (Consider if needed for production)
/*
CREATE TABLE cve_alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id INTEGER,
    channel_id INTEGER,
    cve_id TEXT NOT NULL,
    alert_type TEXT, -- 'on_message', 'feed', 'lookup' ?
    severity_score REAL,
    severity_level TEXT,
    in_kev BOOLEAN,
    alert_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (guild_id) REFERENCES kev_config(guild_id)
);

CREATE TABLE command_usage_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id INTEGER,
    user_id INTEGER,
    command_name TEXT, -- e.g., '/cve lookup', '/kev latest'
    options TEXT, -- JSON representation of options used
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN,
    FOREIGN KEY (guild_id) REFERENCES kev_config(guild_id)
);
*/
```

## 4. Implementation Requirements

### 4.1 Code Structure
- Use Discord.py Cogs for organizing commands (`CVELookupCog`, `KEVCog`).
- Implement command groups (`/cve channels`, `/kev feed`, etc.).
- Clear separation of concerns (API clients, database utilities, Cog logic).

### 4.2 Permissions & Error Handling
- Apply `app_commands.checks.has_permissions(manage_guild=True)` decorator appropriately.
- Implement robust error handling for API calls (timeouts, rate limits, invalid responses) and database operations.
- Provide clear user feedback for success, failure, and invalid usage.

### 4.3 Database Integration (`db_utils.py`)
- Use `aiosqlite` for asynchronous database access.
- Implement functions for all required CRUD operations based on the schema in Section 3.
- Ensure proper use of transactions where necessary.
- Handle database schema creation and potential migrations (if evolving).

### 4.4 API Integration (`nvd_client.py`, `cisa_kev_client.py`)
- Maintain and potentially enhance existing API client classes.
- Implement caching strategies (e.g., in-memory with TTL) for frequently accessed data like KEV entries or recent CVEs to reduce API load.
- Implement fallback mechanisms if primary data sources fail (though NVD is currently the sole source for CVE details).

## 5. Future Considerations / Enhancements
- Per-channel severity thresholds for CVE `on_message` alerts.
- Custom alert formatting (`/cve format`).
- More advanced filtering for `/cve latest` and `/kev latest`.
- Support for multiple KEV feed channels.
- Potential use of other vulnerability data sources beyond NVD.

## 6. Success Metrics
- Command responsiveness and reliability.
- User satisfaction via feedback channels.
- Low rate of API errors or unhandled exceptions.
- Adoption rate of configuration features (thresholds, verbosity, channel management).

## 7. Technical Considerations
- Scalability as the bot joins more servers.
- Rate limiting (Discord commands, external APIs).
- Database performance (indexing, query optimization).
- Secure handling of potential future API keys or sensitive configuration.
- Efficient caching implementation.
