# Kevvy Command Structure PRD

## 1. Command Overview
This PRD defines the structure and behavior of Kevvy's security-related commands, focusing on CVE monitoring and KEV alerts.

## 2. Existing Commands

### 2.1 `/kev` Group
**Purpose:** Manage CISA KEV monitoring and lookups
**Base Permission:** None (public access)

#### 2.1.1 `/kev feed` Group
**Purpose:** Manage CISA KEV feed monitoring configuration
**Permission:** Requires "Manage Server" permission

##### Subcommands:
- `/kev feed enable <channel>`: Enable KEV feed alerts in specified channel
- `/kev feed disable`: Disable KEV feed alerts for the server
- `/kev feed status`: Check current KEV feed monitoring status

**Response Format for `/kev feed status`:**
```
KEV Feed Status:
🟢 Enabled
Channel: #security-alerts
Last Check: [Timestamp]
Last Alert: [Timestamp]
```

#### 2.1.2 `/kev latest`
**Purpose:** Display the most recent KEV entries
**Parameters:**
- `count`: (Optional) Number of entries to display (default: 5, max: 10)
- `days`: (Optional) Look back period in days (default: 7, max: 30)
- `vendor`: (Optional) Filter by vendor
- `product`: (Optional) Filter by product
- `severity`: (Optional) Filter by severity level

**Behavior:**
- Fetches recent KEV entries from CISA
- Displays in chronological order
- Includes comprehensive information for each entry
- Supports filtering options

**Response Format:**
```
Latest KEV Entries (Last 7 days):
1. CVE-2024-XXXX
   Title: [Vulnerability Title]
   Vendor: [Vendor Name]
   Product: [Product Name]
   Added: [Date Added]
   Due Date: [Due Date]
   Ransomware Use: [Yes/No]

2. CVE-2024-YYYY
   [Same format as above]
...
```

**Example Usage:**
```
/kev latest count:3
/kev latest days:14 vendor:microsoft
/kev latest severity:high
```

#### 2.1.3 Future Enhancements
- **Multiple Feed Channels**
  - Allow servers to send KEV alerts to multiple channels
  - Different configurations per channel
  - Channel-specific severity thresholds
  - Channel-specific formatting

- **Enhanced Filtering**
  - Filter by vendor
  - Filter by product
  - Filter by severity
  - Filter by ransomware use
  - Filter by due date

## 3. Command Structure

### 3.1 `/cve` Group
**Purpose:** Manage CVE monitoring and lookups
**Base Permission:** None (public access)

#### 3.1.1 `/cve lookup <cve_id>`
**Purpose:** Look up detailed information about a specific CVE
**Parameters:**
- `cve_id`: The CVE identifier (e.g., "CVE-2024-1234")
**Behavior:**
- Searches multiple sources (VulnCheck primary, NVD fallback)
- Displays comprehensive CVE information
- Shows if the CVE is in the KEV catalog
**Response Format:**
```
Title: [CVE Title]
Description: [Detailed description]
Severity: [CVSS Score]
Status: [KEV Status if applicable]
Vendor: [Affected vendor]
Product: [Affected product]
Published: [Date]
Last Modified: [Date]
```

#### 3.1.2 `/cve channel` Group
**Purpose:** Configure CVE monitoring channels
**Permission:** Requires "Manage Server" permission

##### Subcommands:
- `/cve channel enable <channel>`: Enable CVE monitoring in specified channel
- `/cve channel disable`: Disable CVE monitoring for the server
- `/cve channel set <channel>`: Set the default channel for CVE alerts
- `/cve channel all`: List all channels with CVE monitoring enabled

**Response Format for `/cve channel all`:**
```
CVE Monitoring Channels:
1. #channel-name (Default)
2. #other-channel
3. #another-channel
```

#### 3.1.3 `/cve latest`
**Purpose:** Display the most recent CVEs
**Parameters:**
- `count`: (Optional) Number of CVEs to display (default: 5, max: 10)
- `days`: (Optional) Look back period in days (default: 7, max: 30)
**Behavior:**
- Fetches recent CVEs from NVD based on the publication date range (`days` parameter).
- Displays in chronological order (most recent first).
- Includes basic information for each CVE (ID, Score, Title excerpt, Published date).
- Supports filtering (severity, vendor[basic], product[basic], in_kev).
**Response Format:**
```
Latest CVEs (Last 7 days):
1. CVE-2024-XXXX - [Title] - [Severity]
2. CVE-2024-YYYY - [Title] - [Severity]
...
```

**Future Enhancements:**
- **Enhanced Filtering**
  - `severity`: Filter by CVSS score range
  - `vendor`: Filter by specific vendor
  - `product`: Filter by specific product
  - `type`: Filter by vulnerability type
  - `has_exploit`: Filter for CVEs with known exploits
  - `in_kev`: Filter for CVEs in KEV catalog

**Example Usage:**
```
/cve latest count:5 severity:high vendor:microsoft
/cve latest days:14 type:rce has_exploit:true
/cve latest in_kev:true
```

#### 3.1.4 `/cve verbose` Group
**Purpose:** Configure verbosity of automatic CVE alerts triggered by messages.
**Permission:** Requires "Manage Server" permission

##### Subcommands:
- `/cve verbose enable`: Enable detailed CVE alerts.
- `/cve verbose disable`: Disable detailed CVE alerts (use standard format).

**Verbose Mode Differences (Automatic Message Responses):**
- **Standard Mode (Default):**
  - **CVE Embed:** Shows: CVE ID, Title, CVSS Score. Description contains a link to the NVD page.
  - **KEV Embed (if applicable):** Shows: Title, Confirmation, NVD link.
  
- **Verbose Mode:**
  - **CVE Embed:** Shows: CVE ID, Title, Full Description, CVSS Score, Published Date, Last Modified Date, CVSS Vector (if available), CWE IDs (if available), References (limited count).
  - **KEV Embed (if applicable):** Shows full details (Vulnerability Name, Vendor, Product, Dates, Action, Ransomware Use, Notes).

#### 3.1.5 `/cve threshold` Group (Future)
**Purpose:** Allow servers to set minimum severity levels for alerts
**Permission:** Requires "Manage Server" permission

**Subcommands:**
- `/cve threshold set <level>`: Set minimum severity level
  - Levels: "critical", "high", "medium", "low", "all"
- `/cve threshold view`: Display current threshold
- `/cve threshold reset`: Reset to default (all)

**Database Schema:**
```sql
ALTER TABLE cve_channel_config
ADD COLUMN severity_threshold TEXT DEFAULT 'all';
```

#### 3.1.6 `/cve format` Group (Future)
**Purpose:** Allow servers to customize how CVE alerts appear
**Permission:** Requires "Manage Server" permission

**Subcommands:**
- `/cve format set <template>`: Set custom alert template
- `/cve format preview`: Preview current format
- `/cve format reset`: Reset to default format

**Template Variables:**
```
{cve_id} - CVE identifier
{title} - CVE title
{description} - CVE description
{severity} - CVSS score
{vector} - CVSS vector
{vendor} - Affected vendor
{product} - Affected product
{published} - Publication date
{modified} - Last modified date
{kev_status} - KEV catalog status
{references} - Reference links
```

**Example Templates:**
```
Default:
New CVE: {cve_id}
Title: {title}
Severity: {severity}

Custom:
🚨 {cve_id} - {severity}
📝 {title}
🔗 {references}
```

#### 3.1.7 `/cve channels` Group (Future)
**Purpose:** Allow servers to send CVE alerts to multiple channels with different configurations
**Permission:** Requires "Manage Server" permission

**Subcommands:**
- `/cve channels add <channel> [options]`: Add new monitoring channel
  - Options:
    - `--severity`: Set severity threshold
    - `--format`: Set custom format
    - `--verbose`: Enable/disable verbose mode
- `/cve channels remove <channel>`: Remove monitoring channel
- `/cve channels list`: List all monitoring channels
- `/cve channels edit <channel> [options]`: Edit channel configuration

**Database Schema:**
```sql
CREATE TABLE cve_channel_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id INTEGER,
    channel_id INTEGER,
    enabled BOOLEAN DEFAULT true,
    verbose_mode BOOLEAN DEFAULT false,
    severity_threshold TEXT DEFAULT 'all',
    alert_format TEXT DEFAULT 'default',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (guild_id) REFERENCES kev_config(guild_id)
);
```

**Example Usage:**
```
/cve channels add #security-alerts --severity high --verbose true
/cve channels add #dev-alerts --format custom
/cve channels edit #security-alerts --severity critical
```

## 4. Database Schema Updates
```sql
-- New table for CVE channel configuration
CREATE TABLE cve_channel_config (
    guild_id INTEGER PRIMARY KEY,
    channel_id INTEGER,
    enabled BOOLEAN DEFAULT true,
    verbose_mode BOOLEAN DEFAULT false,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- New table for CVE monitoring history
CREATE TABLE cve_monitoring_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id INTEGER,
    channel_id INTEGER,
    cve_id TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (guild_id) REFERENCES kev_config(guild_id)
);

-- New table for KEV latest queries
CREATE TABLE kev_latest_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id INTEGER,
    user_id INTEGER,
    query_params TEXT, -- JSON string of parameters
    queried_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (guild_id) REFERENCES kev_config(guild_id)
);
```

## 5. Implementation Requirements

### 5.1 Command Handler
- Implement command group structure using Discord.py's app_commands
- Add proper permission checks
- Implement rate limiting for API calls
- Add error handling and user feedback
- **Bot `on_message` handler must check guild's `verbose_mode` setting before generating CVE embed.**

### 5.2 Database Integration
- Add new tables to existing SQLite database
- Implement CRUD operations for channel configuration
- Add monitoring history tracking

### 5.3 API Integration
- Maintain existing VulnCheck and NVD API integration.
- **NVDClient includes `get_recent_cves` method for fetching CVEs by date range.**
- Add caching for recent CVEs and KEV entries.
- Implement fallback mechanisms.

## 6. Success Metrics
- Command response time < 2 seconds
- API call success rate > 95%
- User feedback satisfaction
- Command usage statistics

## 7. Implementation Priority
1. CVE Severity Thresholds (High)
   - Basic functionality needed for effective monitoring
   - Relatively simple to implement
   - High user value

2. Enhanced `/cve latest` Filtering (High)
   - Improves existing functionality
   - Moderate implementation complexity
   - High user value

3. Multiple Monitoring Channels (Medium)
   - Complex implementation
   - Requires database changes
   - High user value for larger servers

4. Custom Alert Formatting (Low)
   - Complex implementation
   - Requires template system
   - Nice-to-have feature

## 8. Technical Considerations
- Implement caching for filtered results
- Add rate limiting for API calls
- Consider database indexing for new fields
- Plan for template validation
- Consider migration strategy for existing configurations

## 9. Success Metrics
- Feature adoption rate
- User satisfaction with customization options
- Performance impact of new features
- API call efficiency
- Database query performance 