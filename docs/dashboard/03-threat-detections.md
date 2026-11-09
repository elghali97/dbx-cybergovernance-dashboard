# 3. Threat detections

> Behavioural detections and sensitive operations modelled on the Databricks Security Reference Architecture (SRA)
> queries and alerts, plus where Databricks is accessed from and which data is used.

**For:** SOC analysts and incident responders (triage and investigation), threat hunters, security engineers tuning
detections.

**Answers:**
- Is anyone brute-forcing logins, harvesting secrets, probing Unity Catalog, escalating privileges, deleting or
  downloading in bulk?
- Which sensitive operations happened: Terms of Service, account settings and admins, Databricks support access,
  global init scripts, DBFS mounts, libraries on all clusters, open-sharing recipients without IP list, recipient
  token lifetime, IP-denied sharing queries, host security alerts?
- Which IP addresses and /24 ranges access Databricks, for which access level, and who uses them?
- Which principals are active in many workspaces (lateral movement, blast radius)?
- Which tables are the most used, and who runs `print()` in notebooks?

**Filters:** Date (detections, sensitive operations, print statements), Detection (rule), Workspace (sensitive
operations, print statements). The access footprint and data usage tables always cover the last 90 days.
**Data:** `security_detections` (rules in `detection_rules`), `sensitive_operations`, `access_footprint_daily`,
`table_access_activity`, `security_activity_hourly`.
**Checks:** IA-08, IA-09, AC-07, AC-08, AC-09, DP-05, DP-06, DP-07, CO-04, CO-05, CO-06, DS-03 (see [checks.md](../checks.md)).
Use case by use case: [use-cases.md](../use-cases.md).

## Counters

All count detections in the selected period, with a sparkline per day; red / orange when above 0.

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Failed-login bursts** | Principal-hours with 10+ failed logins (401 / 403) or 10+ IP access list blocks | Brute force, leaked or expired credentials, or users outside the trusted network. Look at the source IPs |
| **Secret-read bursts** | Principal-hours with 10+ distinct secrets read | Credential harvesting, or a job reading many secrets (normal for some pipelines: confirm with the owner) |
| **Unauthorized bursts** | Principal-hours with 25+ Unity Catalog requests or 15+ data requests refused | Probing or privilege escalation attempts, or a pipeline missing a grant |
| **Privilege escalation** | Principal-hours with 25+ permission changes (grants, ACLs, groups, admin, ownership, tokens) | Expected for provisioning automation; unexpected for a person |
| **Data bursts** | Principal-days with 50+ deletions, principal-hours with 20+ downloads, or 20+ securables read and 20+ written | Sabotage, exfiltration or bulk copy |
| **Many workspaces** | Principal-days active in 5 or more workspaces | Lateral movement or excessive workspace assignment |

## Charts and detections

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Detections by rule** | Detections per rule, by severity | Where the noise and the signal are; tune a noisy rule in `detection_rules` |
| **Detections per day** | Daily detections per rule | A new rule appearing or a spike is the day to investigate |
| **Behavioural detections** | One row per principal and window above a rule: window, severity, rule (hover for its description and SRA query), principal, workspaces, events, distinct objects, threshold, sample objects (secrets, securables, actions, notebooks), evidence (error or command), source IPs | Start from HIGH / MEDIUM. Pivot on the principal in the other pages (identity, access control, exports) or in the [Splunk live dashboard](../splunk.md) |

## Sensitive operations

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Sensitive operations by type** | Events per operation, by severity | HIGH: account admin changes, open-sharing recipients without IP list, host security alerts |
| **Sensitive operation events** | Time, severity, operation, workspace, actor, target and detail (approver / reason of a support access, mount point and source, library, init script SHA-256, recipient token lifetime …), source IP | Check each one against a change or support ticket |

## Access footprint (last 90 days)

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Top source IP addresses** | Requests per client IP | Compare with the corporate egress ranges and the IP access lists |
| **Principals in the most workspaces** | Distinct workspaces per principal | Service principals spanning workspaces are common; people less so |
| **IP addresses used to access Databricks** | Per IP: range, access levels (ACCOUNT / UNITY_CATALOG / WORKSPACE), principals and a sample, workspaces, requests, data access requests, failed requests, first and last seen | A new IP with failures, or a personal-looking IP using data access, deserves a look. Events issued by Databricks compute on behalf of a principal have no client IP and are excluded |
| **IP ranges (/24) used to access Databricks** | The same per /24 network | Input for IP access lists and context-based ingress policies |
| **Workspaces accessed per principal** | Per principal: workspaces, active days, requests, workspace sample | Review principals with many workspaces against their role |

## Data usage

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Most popular data assets** | Tables by readers and reads (lineage, 90 days), with writers and writes | The most valuable data to classify, tag and protect first; compare with the *Tags & metadata* gaps |
| **Print statements** | Hours where a principal ran commands calling `print()`, with notebooks / jobs and a sample command | Needs verbose audit logs. The audit log records the command, not its output: check whether sensitive values are printed into results and logs |
