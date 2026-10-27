# Microsoft 365 Audit Log Explorer

A desktop GUI tool for SOC analysts to fetch, hunt, investigate and export the **Microsoft 365 unified audit log** (Entra ID, Exchange, SharePoint / OneDrive, Teams, Power Platform, DLP) through the Office 365 Management Activity API, with no scripting and without the slow Purview portal.

It includes built-in threat detections, 27 ready-made hunts mapped to **MITRE ATT&CK**, IP enrichment, and a per-user investigation timeline.

![Screenshot](screenshot.png)
<!-- Add a screenshot of the tool with any real data blurred, saved as screenshot.png -->

---

## Features

| Area | What it does |
|---|---|
| **Fetch** | Pull audit events for any window in the last 7 days (presets from 15 minutes to 7 days, or a custom UTC range). Handles late-arriving events, de-duplicates by event ID, and downloads content in parallel within API rate limits. |
| **Events** | Filter by workload, operation, user, client IP, result, country or free text. Summary panel groups by operation, user, IP, country, workload or result; double-click to drill down. Right-click any cell to pivot. |
| **Quick hunts** | 27 one-click hunts for common SOC checks, each mapped to MITRE ATT&CK (see below). |
| **Detections** | Threshold-based detections that run automatically after each fetch: password spray, brute force, mass download and mass deletion. Thresholds are adjustable in the tab. |
| **IP Intel** | Every IP with event counts and sign-in results. Optional geo lookup (country, ASN, VPN / hosting flags) and AbuseIPDB reputation check. |
| **User Timeline** | One user's activity across all workloads in time order, with hunt flags, MITRE IDs, IP, country and user agent. |
| **Export** | CSV, JSON, JSONL or Excel, optionally zipped, each with a `.meta.json` file recording tenant, time window, filter, analyst and whether the data is complete. Large pulls can stream straight to file. |
| **Audit trail** | Every connect, fetch, export and lookup is logged to a local activity log (analyst, machine, tenant, action, row count). |

## Detections

| Detection | Logic (defaults) | Severity | MITRE ATT&CK |
|---|---|---|---|
| Password spray | One IP fails sign-in for 10+ different users within 60 min | High if any of those users later signs in from the same IP, else Medium | T1110.003 |
| Brute force then successful sign-in | 5+ failed sign-ins for one user within 30 min, followed by a success | High | T1110.001 |
| Repeated failed sign-ins | Same as above, no success | Medium | T1110.001 |
| Mass file download | 100+ files downloaded by one user within 10 min | Medium (High at 3x threshold) | T1530 |
| Mass file / folder deletion | 100+ deletions by one user within 10 min | Medium (High at 3x threshold) | T1485 |

## Quick hunts

| Category | Hunts | MITRE ATT&CK |
|---|---|---|
| Exchange / Mailbox | Inbox rules, mail forwarding, mailbox permissions, mail items accessed, mail deleted, transport rule changes, mailbox auditing disabled, anti-phish / spam / malware protection weakened | T1564.008, T1114.003, T1098.002, T1114.002, T1070.008, T1562.008, T1562.001 |
| Identity (Entra ID) | Failed / successful sign-ins, admin role changes, user account changes, guest invites, MFA changes, Conditional Access changes, domain and federation changes, app consent | T1110, T1078.004, T1098.003, T1136.003, T1556.006, T1484.002, T1528, T1098.001 |
| SharePoint / OneDrive | External / anonymous sharing, file downloads, file deletions, site collection admin changes | T1567, T1530, T1213.002, T1485, T1098 |
| Teams | Team and membership changes | T1098 |
| Power Platform | Power Automate flows created or changed | T1020 |
| Admin & Compliance | eDiscovery searches, audit configuration changes, DLP matches, failed operations | T1213, T1114.002, T1562.008 |

---

## Requirements

- Python 3.9 or later (Tkinter is included with the standard Windows and macOS installers)
- `requests`, plus `openpyxl` for Excel export

```bash
pip install -r requirements.txt
```

## Azure setup

1. In the Entra admin center, go to **App registrations → New registration**.
2. Under **API permissions**, add **Office 365 Management APIs → Application permissions → `ActivityFeed.Read`**. Add `ActivityFeed.ReadDlp` too if you need DLP events.
3. Click **Grant admin consent**.
4. Under **Certificates & secrets**, create a client secret and copy its **Value**.
5. Note the **Tenant ID** and **Application (client) ID**.

Unified audit logging must be turned on in the tenant (it is on by default for most tenants).

## Usage

```bash
python m365_audit_explorer.py
```

1. Enter the tenant ID, client ID and client secret in the Connect window.
2. **First time only:** in the Subscriptions panel, select the content types and click **Start selected**. New subscriptions can take up to 12 hours to show data.
3. Pick a time window and log types, then click **Fetch events**.
4. Use the **Events**, **Quick hunts**, **Detections**, **IP Intel** and **User Timeline** tabs to investigate.
5. Export what you need, or use **Download directly** for very large windows.

---

## Security and privacy by design

- **The client secret is never written to disk.** It lives in memory only and is wiped on disconnect or exit. Saved profiles hold only tenant ID, client ID and URLs.
- **The AbuseIPDB key is memory-only too**, and is cleared on disconnect.
- **Nothing leaves your machine unless you click.** Geo lookup and AbuseIPDB only send IP addresses, never user names or log content, and each asks for confirmation first.
- **Exports state their completeness.** If any content failed to download, or the window was clipped to the 7-day retention, the warning is shown and recorded in the `.meta.json` file.

> **Note:** the free ip-api.com service uses plain HTTP. If you work with client data, check that sending IP addresses to a third-party lookup is allowed under your agreements, or change `GEO_LOOKUP_URL` in the settings at the top of the script.

## Configuration

Optional settings are at the top of `m365_audit_explorer.py`, for example:

| Setting | Default | Purpose |
|---|---|---|
| `OUTPUT_DIR` | `output_m365_audit` | Download folder |
| `DEFAULT_FORMAT` | `csv` | csv, json, jsonl or xlsx |
| `PROXY` / `VERIFY_SSL` | none / `True` | Corporate proxy and SSL-inspection support |
| `DOWNLOAD_THREADS` | `6` | Parallel content downloads |
| `MAX_EVENTS_IN_MEMORY` | `300000` | Fetch limit; use Download directly for more |
| `LATE_ARRIVAL_HOURS` | `12` | Extra look-ahead for late events |
| `SPRAY_MIN_USERS`, `BRUTE_MIN_FAILS`, ... | see script | Default detection thresholds |
| `ABUSEIPDB_MAX_IPS` | `200` | Max IPs checked per click |

## Limitations

- The Management Activity API keeps content for **7 days** only. For older data, use Purview audit search or a SIEM.
- Audit events usually arrive **1 to 2 hours late**, and occasionally up to 24 hours.
- `MailItemsAccessed` and some other events need Microsoft Purview Audit (Premium) / E5 licensing.
- Operation names in the unified audit log occasionally differ from Microsoft's documentation, so hunts may need tuning per tenant.

## Author

**Siddhesh Nagarkar**, SOC Analyst
Part of a series of SOC log explorer tools for cloud security platforms.

## License

Released under the MIT License. See [LICENSE](LICENSE).

## Disclaimer

Use this tool only on tenants you are authorised to access. It reads audit data only and makes no changes to the tenant, apart from starting or stopping audit subscriptions when you explicitly click those buttons.
