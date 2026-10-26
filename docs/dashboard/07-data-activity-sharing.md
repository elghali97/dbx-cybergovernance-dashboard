# 7. Data activity & sharing

> Data leaving the platform: downloads and exports by people and automation, secrets usage, and Delta Sharing to
> external recipients.

**For:** SOC and insider-risk analysts (exfiltration), DLP teams, data owners sharing data with partners.

**Answers:**
- Who downloads query results, exports notebooks or dashboards, and through which channel?
- Is anyone exporting much more than usual?
- Who reads secrets, and are there failed secret accesses?
- Which external (open-sharing) recipients exist, with which shares, IP restrictions and token expiry?
- What did Delta Sharing recipients access, and were requests denied by IP lists?

**Filters:** Date, Workspace.
**Data:** `data_export_daily`, `data_export_events`, `secret_access_daily`, `delta_sharing_posture`,
`delta_sharing_activity_daily`.
**Checks:** DP-02 high volume of interactive exports · DP-04 secret scope shared with all users · DS-01 open recipient
without IP allow-list · DS-02 open-sharing token without expiry.

## Counters

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Interactive exports** | Downloads and exports started by people (SQL / notebook results, Genie and dashboard downloads, notebook exports, browser file downloads) | The exfiltration-relevant volume |
| **Automated exports** | Exports by the CLI, SDKs and services | Usually pipelines and sync tools; a new principal here deserves a look |
| **Secret reads** | Secret reads (`getSecret`) | |
| **Secret access failures** | Denied or failed secrets calls (missing-secret lookups excluded) | Someone trying secrets they are not allowed to read |
| **Open-sharing recipients** | Token-based recipients outside Databricks | Each one is data leaving the account |
| **Open recipients w/o IP list** | Open recipients with no IP allow-list | Should be 0 (DS-01, HIGH): anyone with the token file can read the shares |

## Charts

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Interactive exports per day by channel** | Daily interactive exports per channel | A spike on one day and channel points to a person in the table below |
| **Top interactive exporters** (30 days) | People with the most exports, by channel | Compare with their role; DP-02 flags 50+ exports in 7 days |

## Tables

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Interactive export events** | Each export: who, channel, action, object (query, notebook, dashboard, file), format, source IP | The evidence for an insider-risk case |
| **Delta Sharing recipients** | Recipient, exposure (Databricks-to-Databricks, open with / without IP list), shares, IP ranges, token expiry, owner | Rotate tokens without expiry (DS-02), add IP lists (DS-01), remove unused recipients |
| **Secret access** | Per day: principal, action, scope, events, failures | Humans reading production secrets, or failures, are worth a question |
| **Delta Sharing activity** | Per day: activity type, action, principal / recipient, share, object, events, IP-denied events | What partners actually read; IP-denied events = token used from an unexpected network |

**Near real-time and alerts:** the [Splunk app](../splunk.md) includes a *Mass interactive data export* alert (20+
exports by one person in an hour).
