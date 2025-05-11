# Kevvy Commands (`/kevvy`)

This section describes utility commands available under the `/kevvy` group.

## `/kevvy help [command_name]`

Shows help information for Kevvy commands.

**Purpose:** Provides a way for users to discover commands and understand their usage without needing to refer to external documentation.

**Usage:**

- `/kevvy help`: Displays a general overview of all main command groups, their descriptions, and their primary subcommands.
- `/kevvy help <command_group>`: Shows detailed help for a specific command group (e.g., `/kevvy help cve`). This includes a description of the group and a list of its subcommands.
- `/kevvy help <command_group> <subcommand>`: Shows detailed help for a specific subcommand (e.g., `/kevvy help cve lookup`). This includes its description, parameters (with types, whether they are optional/required, and default values if any), and a usage example.

**Parameters:**

- `command_name` (Optional): The specific command or command group you want help for (e.g., `cve`, `cve lookup`, `kev feed enable`). If omitted, general help is shown.

**Example Output (General Help):**

An embed message listing all top-level command groups like `/cve`, `/kev`, `/verbose`, and `/kevvy`, with their descriptions and main subcommands.

**Example Output (Specific Command Help - e.g., `/kevvy help cve lookup`):**

An embed message detailing:

- Command: `/cve lookup`
- Description: "Look up detailed information about a specific CVE."
- Parameters:
  - `cve_id`: _str_ (Required) - The CVE identifier (e.g., "CVE-2024-1234")
- Usage Example: `/cve lookup cve_id:CVE-2024-1234`

## Admin Commands

The following commands are restricted to the bot owner only (configured via `BOT_OWNER_ID`).

### `/kevvy admin status`

Shows the operational status of the bot.

**Purpose:** Provides a quick overview of the bot's health and operational metrics.

**Output includes:**

- Overall status
- Version information
- Latency
- Uptime
- Server count
- Loaded extensions/cogs
- API connectivity status
- Database status

### `/kevvy admin stats`

Shows detailed statistics about the bot's operations.

**Purpose:** Provides insights into bot usage and performance metrics.

**Output includes:**

- CVE-related statistics (messages processed, lookups, rate limits)
- KEV-related statistics (alerts sent)
- API error statistics
- Command usage statistics

### `/kevvy admin reload [extension]`

Reloads bot extensions/cogs.

**Purpose:** Allows for applying code changes without restarting the bot.

**Parameters:**

- `extension` (Optional): The specific extension to reload. If omitted, reloads all extensions.

### `/kevvy admin version`

Shows detailed version information for the bot.

**Purpose:** Provides comprehensive information about the bot's environment and dependencies.

**Output includes:**

- Current version
- Python version
- discord.py version
- OS information
- Key dependency versions

### `/kevvy admin servers`

Lists all servers the bot is in.

**Purpose:** Provides an overview of all Discord servers where the bot is present.

**Output includes:**

- Server name and ID
- Member count
- Owner information
- Creation date
- Bot join date

### `/kevvy admin debug <code>`

Evaluates Python code for debugging.

**Purpose:** Allows the bot owner to run Python code for debugging purposes.

**Parameters:**

- `code` (Required): The Python code to evaluate.

### `/kevvy admin announce <message>`

Sends an announcement message to all servers the bot is in.

**Purpose:** Allows the bot owner to broadcast important messages to all servers.

**Parameters:**

- `message` (Required): The announcement message to send.

**Behavior:**

- Creates an embed with the announcement message
- Attempts to send to each server using the following channel priority:
  1. KEV feed channel (if configured)
  2. Announcements channel or system channel
  3. General channel or first available text channel
- Provides a summary of successful and failed deliveries
- Shows detailed error information for failed deliveries (up to 5)

**Example:**

```
/kevvy admin announce message:Important update: New features have been added to the bot!
```
