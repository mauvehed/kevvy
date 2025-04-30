# Verbosity Commands (`/verbose`)

Configure the level of detail provided in automatic CVE alerts triggered by messages containing CVE IDs. These settings do not affect the output of `/cve lookup`.

**Permission Required:** Manage Server

**Default Behavior:**

- By default, automatic CVE alerts use the **standard (non-verbose)** format.
- The global setting applies to all channels unless a specific channel override is set.

---

## `/verbose enable_global`

Sets the default alert style to **verbose** for the entire server. Alerts in channels without specific overrides will show more detail.

**Example:**

```
/verbose enable_global
```

---

## `/verbose disable_global`

Sets the default alert style to **standard (non-verbose)** for the entire server. This is the default behavior. Alerts in channels without specific overrides will show less detail.

**Example:**

```
/verbose disable_global
```

---

## `/verbose set <channel> <verbosity>`

Sets a verbosity override for a specific channel, ignoring the global setting for that channel.

**Parameters:**

- **`<channel>`**: (Required) The text channel to configure.
- **`<verbosity>`**: (Required) Whether to use verbose alerts (`True`) or standard alerts (`False`) in this channel.

**Example:**

```
/verbose set channel:#important-alerts verbosity:True
/verbose set channel:#general-feed verbosity:False
```

---

## `/verbose unset <channel>`

Removes the verbosity override for a specific channel. That channel will revert to using the current global server setting.

**Parameters:**

- **`<channel>`**: (Required) The text channel to reset.

**Example:**

```
/verbose unset channel:#important-alerts
```

---

## `/verbose setall <verbosity>`

Sets a verbosity override for **all** currently configured CVE monitoring channels in the server. This is a quick way to make all channels behave the same, overriding any previous individual settings.

**Parameters:**

- **`<verbosity>`**: (Required) Whether to set all channels to verbose (`True`) or standard (`False`).

**Example:**

```
/verbose setall verbosity:True
```

---

## `/verbose status [channel]`

Shows the current global verbosity setting and lists any channels that have specific overrides. If a channel is provided, it shows the effective setting for that specific channel (whether inherited or overridden).

**Parameters:**

- **`[channel]`**: (Optional) A specific text channel to check the effective status for.

**Example:**

```
/verbose status
/verbose status channel:#important-alerts
```

**Example Response (No Channel Specified):**

```
CVE Alert Verbosity Status
Global Setting: **Standard (Non-Verbose)**

Channel Overrides
#important-alerts: **Verbose** (Override)
#other-feed: **Standard** (Override)
```

or if no overrides:

```
CVE Alert Verbosity Status
Global Setting: **Verbose**

Channel Overrides
No channels have specific verbosity overrides. All are using the global setting.
```

**Example Response (Channel Specified):**

```
CVE Alert Verbosity Status
Global Setting: **Standard (Non-Verbose)**

#important-alerts: Verbose (Override)
```

or

```
CVE Alert Verbosity Status
Global Setting: **Verbose**

#general-chat: Inheriting Global (Verbose)
```

---

## Verbosity Mode Differences

The verbosity setting affects the detail level of embeds posted automatically when a CVE is detected in a message:

- **Standard Mode (Default):**
  - Shows CVE ID, Title, and CVSS Score.
  - Links to the NVD page for more details.
  - If in KEV, shows a brief KEV confirmation.
- **Verbose Mode:**
  - Shows CVE ID, Title, Full Description, CVSS Score, Published/Modified Dates, CVSS Vector, CWE IDs, and References (limited).
  - If in KEV, shows full KEV details (Name, Vendor, Product, Dates, Action, Ransomware Use, Notes).

```

```
