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
