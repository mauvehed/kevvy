# KEV Commands (`/kev`)

Commands related to the CISA Known Exploited Vulnerabilities (KEV) catalog.

---

## Feed Management (`/kev feed`)

Manage the CISA KEV feed monitoring for this server.

**Permission Required:** Manage Server

### `/kev feed enable <channel>`

Enables KEV feed alerts in the specified channel. New entries from the KEV catalog will be posted here.

-   **`<channel>`:** (Required) The text channel where alerts should be sent.

**Example:**
```
/kev feed enable channel:#security-alerts
```

### `/kev feed disable`

Disables KEV feed alerts for this server. The bot will stop checking for new KEV entries for this server.

**Example:**
```
/kev feed disable
```

### `/kev feed status`

Checks the current status of KEV feed monitoring, including the configured channel and last check/alert times.

**Example:**
```
/kev feed status
```

**Example Response:**
```
🟢 KEV feed monitoring is **enabled**.
Alerts channel: #security-alerts
Last successful check: 2 minutes ago
Last alert sent: 1 day ago
```
or
```
⚪ KEV feed monitoring is **disabled**.
```

---

## Latest KEV Entries (`/kev latest`)

Display the most recent entries added to the CISA KEV catalog, with optional filters.

**Parameters:**

-   **`count`**: (Optional) Number of entries to display.
    -   *Default:* 5
    -   *Maximum:* 10
-   **`days`**: (Optional) Look back period in days for entries added.
    -   *Default:* 30
    -   *Maximum:* 30
-   **`vendor`**: (Optional) Filter entries by vendor name (case-insensitive match).
-   **`product`**: (Optional) Filter entries by product name (case-insensitive match).

**Example Usage:**
```
/kev latest
/kev latest count:3 days:14
/kev latest vendor:"Microsoft"
/kev latest product:"Exchange Server"
```

**Response Format:**

Displays a list of KEV entries matching the criteria, sorted by date added (most recent first). Each entry includes the CVE ID (linked to NVD), Vulnerability Name, Date Added, Due Date, and Known Ransomware Use.

---
## Future Enhancements

*(Note: The following features are planned but not yet implemented)*

-   **Multiple Feed Channels:** Ability to configure alerts for different channels with separate settings.
-   **Enhanced Filtering:** More specific filtering options for `/kev latest`, such as by ransomware use or due date ranges. 