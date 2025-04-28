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
    - Checks if CVE monitoring is enabled globally for the guild (`cve_guild_config.enabled`).
    - Checks if the specific channel is configured for monitoring (`cve_channel_configs` table).
    - If global monitoring is enabled AND the channel is configured:
        - Fetches CVE details (NVD).
        - Checks if the CVE's severity meets the *globally* configured threshold (`cve_guild_config.severity_threshold`).
        - Determines the appropriate verbosity (checking channel override from `cve_channel_configs.verbose_mode` then global setting from `cve_guild_config.verbose_mode`).
        - Creates a CVE information embed (standard or verbose).
        - Checks if the CVE is present in the CISA KEV catalog.
        - Sends the CVE embed to the channel.
        - If in KEV, sends a separate KEV information embed.
- Handles potential errors during API lookups gracefully.

### 2.2 `/cve` Group
**Purpose:** Manage CVE lookups and monitoring configuration.
**Base Permission:** None (public access for lookup)

#### 2.2.1 `/cve lookup <cve_id>`
**Purpose:** Look up detailed information about a specific CVE.
**Parameters:**
- `cve_id`: The CVE identifier (e.g., "CVE-2024-1234")
**Behavior:**
- Searches NVD for the CVE ID.
- Displays comprehensive CVE information in a standard embed format.
- Includes a check and notes if the CVE is present in the CISA KEV catalog.
**Response Format (Embed):**
- Title: CVE ID
- URL: Link to NVD page
- Description: CVE description text.
- Fields: CVSS Score, Severity, Vector, CWEs, Published Date, Modified Date, References, KEV Status (if applicable).

#### 2.2.2 `/cve channel` Group
**Purpose:** Configure specific channels for automatic CVE scanning (`on_message`).
**Permission:** Requires "Manage Server" permission

##### Subcommands:
- `/cve channel enable <channel>`: Enable automatic CVE scanning for messages in the specified channel. Ensures global monitoring is also enabled for the server.
- `/cve channel disable`: Disable automatic CVE scanning *globally* for the entire server. No messages will be scanned in any channel.
- `/cve channel set <channel>`: Updates the channel configuration (same effect as `enable`).
- `/cve channel all`: Lists all channels currently configured for automatic CVE scanning.

#### 2.2.3 `/cve latest`
**Purpose:** Display the most recent CVEs published on NVD.
**Parameters:**
- `count`: (Optional) Number of CVEs to display (default: 5, max: 10)
- `days`: (Optional) Look back period in days (default: 7, max: 30)
- `severity`: (Optional) Filter by minimum severity level (`critical`, `high`, `medium`, `low`).
- `in_kev`: (Optional, Boolean) Show only CVEs also present in the KEV catalog.
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
**Purpose:** Set the minimum severity level for CVEs to trigger *automatic* alerts via `on_message`. This is a **global** setting for the server, affecting all configured channels.
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
- `/kev feed enable <channel>`: Enable KEV feed alerts in the specified channel. *(Note: Currently supports only one channel per server for the feed).* Updates `kev_config` table.
- `/kev feed disable`: Disable KEV feed alerts for the server. Updates `kev_config` table.
- `/kev feed status`: Check current KEV feed monitoring status and configured channel from `kev_config` table.

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
*(Current Schema Representation)*
```sql
-- Stores global settings for both KEV feed and CVE on_message scanning
CREATE TABLE IF NOT EXISTS cve_guild_config (
    guild_id INTEGER PRIMARY KEY,
    enabled BOOLEAN DEFAULT true, -- Global switch for CVE on_message scanning
    verbose_mode BOOLEAN DEFAULT false, -- Global default verbosity for CVE on_message
    severity_threshold TEXT DEFAULT 'all', -- Global severity threshold for CVE on_message
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Stores KEV feed specific settings (can potentially be merged with cve_guild_config later)
CREATE TABLE IF NOT EXISTS kev_config (
    guild_id INTEGER PRIMARY KEY,
    channel_id INTEGER NOT NULL, -- Channel for KEV feed alerts
    enabled BOOLEAN NOT NULL DEFAULT 0 -- Whether KEV feed is enabled
);

-- Stores configuration for individual channels for CVE on_message scanning
CREATE TABLE IF NOT EXISTS cve_channel_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    enabled BOOLEAN DEFAULT true,         -- If monitoring is active for this specific channel
    verbose_mode BOOLEAN DEFAULT NULL,    -- Per-channel verbosity override (NULL means inherit global)
    severity_threshold TEXT DEFAULT NULL, -- Per-channel threshold override (Future Enhancement, NULL means inherit global)
    alert_format TEXT DEFAULT NULL,       -- Per-channel format override (Future Enhancement)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(guild_id, channel_id)
);

-- Tracks previously seen KEV IDs for the feed monitor
CREATE TABLE IF NOT EXISTS seen_kevs (
    cve_id TEXT PRIMARY KEY
);

-- Optional: History/Logging Tables (Consider if needed for production)
CREATE TABLE IF NOT EXISTS cve_monitoring_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id INTEGER,
    channel_id INTEGER,
    cve_id TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS kev_latest_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id INTEGER,
    user_id INTEGER,
    query_params TEXT, 
    queried_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 4. Implementation Requirements

### 4.1 Code Structure
- Use Discord.py Cogs for organizing commands (`CVELookupCog`, `KEVCog`).
- Implement command groups (`/cve channel`, `/kev feed`, etc.).
- Clear separation of concerns (API clients, database utilities, Cog logic).

### 4.2 Permissions & Error Handling
- Apply `app_commands.checks.has_permissions(manage_guild=True)` decorator appropriately.
- Implement robust error handling for API calls (timeouts, rate limits, invalid responses) and database operations.
- Provide clear user feedback for success, failure, and invalid usage.

### 4.3 Database Integration (`db_utils.py`)
- Use standard `sqlite3` module (or consider `aiosqlite` if intensive async DB ops needed).
- Implement functions for all required CRUD operations based on the schema in Section 3.
- Ensure proper handling of database connections and cursors.
- Handle database schema creation and potential migrations (like the ones already implemented).

### 4.4 API Integration (`nvd_client.py`, `cisa_kev_client.py`)
- Maintain and potentially enhance existing API client classes.
- Implement caching strategies (e.g., in-memory with TTL) for frequently accessed data like KEV entries or recent CVEs to reduce API load.

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
