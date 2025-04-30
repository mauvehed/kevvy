# CVE Commands (`/cve`)

Commands related to searching and configuring Common Vulnerabilities and Exposures (CVE) information.

---

## Lookup CVE Details (`/cve lookup`)

Look up detailed information about a specific CVE identifier.

**Parameters:**

- **`cve_id`**: (Required) The CVE identifier (e.g., `CVE-2024-1234`).

**Behavior:**

- Fetches details primarily from the NVD API v2.0.
- Displays description, CVSS score, publication dates, CWEs, references, and KEV status (if applicable).

**Example:**

```
/cve lookup cve_id:CVE-2023-3884
```

---

## Channel Configuration (`/cve channel`)

Configure which channels the bot should automatically scan for CVE IDs in messages.

**Permission Required:** Manage Server

### `/cve channel add <channel>`

Enables automatic CVE scanning for messages posted in the specified channel. Requires global monitoring to be enabled (see `/cve channel enable_global`).

- **`<channel>`:** (Required) The text channel to monitor.

**Example:**

```
/cve channel add channel:#security-feed
```

### `/cve channel remove <channel>`

Disables automatic CVE scanning for messages posted in the specified channel. The global setting remains unaffected.

- **`<channel>`:** (Required) The text channel to stop monitoring.

**Example:**

```
/cve channel remove channel:#security-feed
```

### `/cve channel list`

Shows the global CVE message scanning status (enabled/disabled) and lists the channels currently configured for automatic scanning.

**Example:**

```
/cve channel list
```

**Example Response:**

```
ℹ️ Global automatic CVE monitoring is currently **enabled** for this server.

Configured channels:
- #security-feed
- #vuln-reports
```

or

```
ℹ️ Global automatic CVE monitoring is currently **enabled** for this server.

No specific channels are currently configured and enabled. Use `/cve channel add` to add one.
```

or

```
⚪ Global automatic CVE monitoring is currently **disabled** for this server.
```

### `/cve channel enable_global`

Enables automatic CVE message scanning globally for the server. You still need to add specific channels using `/cve channel add` for the bot to actually scan them.

**Example:**

```
/cve channel enable_global
```

### `/cve channel disable_global`

Disables automatic CVE message scanning globally for the server. No messages will be scanned in any channel, regardless of individual channel configurations.

**Example:**

```
/cve channel disable_global
```

---

## Severity Threshold (`/cve threshold`)

Configure the minimum CVSS severity required for a CVE found in a message to trigger an automatic alert.

**Permission Required:** Manage Server

### `/cve threshold set <level>`

Set the minimum severity level.

- **`<level>`**: (Required) The minimum severity.
  - _Choices:_ `critical`, `high`, `medium`, `low`, `all` (default)

**Example:**

```
/cve threshold set level:high
```

### `/cve threshold view`

Displays the current global minimum severity threshold setting.

**Example:**

```
/cve threshold view
```

**Example Response:**

```
ℹ️ Current global CVE severity threshold: **high**
```

### `/cve threshold reset`

Resets the global minimum severity threshold to the default (`all`).

**Example:**

```
/cve threshold reset
```

---

## Latest CVE Entries (`/cve latest`)

Display the most recent CVEs published by NVD, with optional filters.

**Parameters:**

- **`count`**: (Optional) Number of CVEs to display.
  - _Default:_ 5
  - _Maximum:_ 10
- **`days`**: (Optional) Look back period in days based on publication date.
  - _Default:_ 7
  - _Maximum:_ 30
- **`severity`**: (Optional) Filter by minimum CVSS severity.
  - _Choices:_ `critical`, `high`, `medium`, `low`
- **`vendor`**: (Optional) Filter by vendor name (basic case-insensitive description match).
- **`product`**: (Optional) Filter by product name (basic case-insensitive description match).
- **`in_kev`**: (Optional) Filter for CVEs present (`True`) or not present (`False`) in the CISA KEV catalog.

**Example Usage:**

```
/cve latest
/cve latest count:3 days:14
/cve latest severity:high vendor:Microsoft
/cve latest in_kev:true
```

**Response Format:**

Displays a list of recent CVEs matching the criteria, sorted by publication date (most recent first). Each entry includes the CVE ID (linked to NVD), CVSS score, a short description excerpt, and publication date.

---

## Future Enhancements

_(Note: The following features are planned but not yet implemented)_

### Alert Formatting (`/cve format`) (Future)

Customize the appearance of future CVE alerts.

**Permission Required:** Manage Server

- **/cve format set `<template>`**: Set a custom alert template using variables like `{cve_id}`, `{title}`, `{severity}`, etc.
- **/cve format preview**: Show a preview of how alerts will look with the current format.
- **/cve format reset**: Reset the alert format to the default style.

### Multi-Channel Configuration (`/cve channels`) (Future)

_(This section might be superseded or clarified by the existing `/cve channel` and `/verbose` commands)_

Configure CVE alerts to be sent to multiple channels with potentially different settings (severity, format, verbosity) per channel.

**Permission Required:** Manage Server

- **/cve channels add `<channel> [options]`**: Add a channel for monitoring.
- **/cve channels remove `<channel>`**: Stop monitoring alerts in a channel.
- **/cve channels list**: View all configured monitoring channels and their settings.
- **/cve channels edit `<channel> [options]`**: Modify settings for an existing monitored channel.
