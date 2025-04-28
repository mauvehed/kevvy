# CVE Commands (`/cve`)

Commands related to searching and configuring Common Vulnerabilities and Exposures (CVE) information.

---

## Lookup CVE Details (`/cve lookup`)

Look up detailed information about a specific CVE identifier.

**Parameters:**

-   **`cve_id`**: (Required) The CVE identifier (e.g., `CVE-2024-1234`).

**Behavior:**

-   Fetches details primarily from VulnCheck (if configured), falling back to NVD.
-   Displays description, CVSS score, publication dates, CWEs, references, and KEV status (if applicable).

**Example:**
```
/cve lookup cve_id:CVE-2023-3884
```

---

## Channel Configuration (`/cve channel`)

Configure channels for CVE-related features (currently affects `/cve latest` context, future use for targeted alerts).

**Permission Required:** Manage Server

### `/cve channel enable <channel>`

Enables CVE monitoring features for the specified channel. This currently sets the context for commands like `/cve latest` and prepares for future targeted alert features.

-   **`<channel>`:** (Required) The text channel to enable/configure.

**Example:**
```
/cve channel enable channel:#security-feed
```

### `/cve channel disable`

Disables global CVE monitoring features for the server (affects `/cve latest` context and future alerts).

**Example:**
```
/cve channel disable
```

### `/cve channel set <channel>`

Sets or updates the specific channel for CVE features (effectively the same as `/cve channel enable`). Ensures global monitoring is enabled.

-   **`<channel>`:** (Required) The text channel to set.

**Example:**
```
/cve channel set channel:#security-feed
```

### `/cve channel list`

Lists all channels specifically configured for CVE alerts.

**Example:**
```
/cve channel list
```
**Example Response:**
```
ℹ️ CVE monitoring is **enabled** globally.
Configured channels:
- #security-feed
```

### `/cve channel all`

Enables global CVE monitoring and clears any specific channel configurations, making the bot listen for CVEs in all channels.

**Example:**
```
/cve channel all
```

---

## Latest CVE Entries (`/cve latest`)

Display the most recent CVEs published by NVD, with optional filters.

**Parameters:**

-   **`count`**: (Optional) Number of CVEs to display.
    -   *Default:* 5
    -   *Maximum:* 10
-   **`days`**: (Optional) Look back period in days based on publication date.
    -   *Default:* 7
    -   *Maximum:* 30
-   **`severity`**: (Optional) Filter by minimum CVSS severity.
    -   *Choices:* `critical`, `high`, `medium`, `low`
-   **`vendor`**: (Optional) Filter by vendor name (basic case-insensitive description match).
-   **`product`**: (Optional) Filter by product name (basic case-insensitive description match).
-   **`in_kev`**: (Optional) Filter for CVEs present (`True`) or not present (`False`) in the CISA KEV catalog.

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

*(Note: The following features are planned but not yet implemented)*

### Severity Threshold (`/cve threshold`) (Future)

Configure a minimum CVSS severity threshold for future CVE alert features.

**Permission Required:** Manage Server

-   **/cve threshold set `<level>`**: Set the minimum severity.
    -   *Levels:* `critical`, `high`, `medium`, `low`, `all` (default)
-   **/cve threshold view**: Display the current threshold setting.
-   **/cve threshold reset**: Reset the threshold to the default (`all`).

### Alert Formatting (`/cve format`) (Future)

Customize the appearance of future CVE alerts.

**Permission Required:** Manage Server

-   **/cve format set `<template>`**: Set a custom alert template using variables like `{cve_id}`, `{title}`, `{severity}`, etc.
-   **/cve format preview**: Show a preview of how alerts will look with the current format.
-   **/cve format reset**: Reset the alert format to the default style.

### Multi-Channel Configuration (`/cve channels`) (Future)

Configure CVE alerts to be sent to multiple channels with potentially different settings (severity, format, verbosity) per channel.

**Permission Required:** Manage Server

-   **/cve channels add `<channel> [options]`**: Add a channel for monitoring.
-   **/cve channels remove `<channel>`**: Stop monitoring alerts in a channel.
-   **/cve channels list**: View all configured monitoring channels and their settings.
-   **/cve channels edit `<channel> [options]`**: Modify settings for an existing monitored channel. 