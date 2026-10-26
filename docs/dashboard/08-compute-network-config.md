# 8. Compute, network & config

> Cluster isolation and policies, network policy denials and workspace security settings.

**For:** platform security and cloud security teams (hardening baseline), platform administrators.

**Answers:**
- Which interactive clusters are not secured by Unity Catalog (no-isolation / legacy access modes)?
- Which clusters run without a compute policy, on an unsupported runtime, or with init scripts?
- What do network policies deny, inbound (context-based ingress, IP rules) and outbound (serverless egress)?
- Which workspaces have risky security settings (IP access lists off, verbose audit logs off, downloads allowed …), and
  who changed them?

**Filters:** Date (network and setting changes), Workspace.
**Data:** `compute_posture`, `network_events_daily`, `workspace_config_latest`, `workspace_config_changes`.
**Checks:** CO-01 cluster not secured by Unity Catalog · CO-02 interactive cluster without policy · CO-03 unsupported
runtime · NW-01 inbound denials · NW-02 serverless egress blocked · AU-01 verbose audit logs disabled · AU-02 IP access
lists disabled · DP-03 data exfiltration setting enabled · IA-03 max token lifetime not enforced.

## Counters

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Interactive clusters** | All-purpose clusters (current state) | |
| **Not UC-secured** | Clusters in no-isolation or legacy access modes | They bypass Unity Catalog access control: move to standard or dedicated access mode |
| **Without compute policy** | Clusters created without a compute policy | Policies enforce access mode, runtime, sizes and tags |
| **Runtime < 13** | Clusters on Databricks Runtime older than 13 | Unsupported runtimes miss security patches |
| **Network denials** | Requests denied by network policies in the period | Empty if the network system tables are not enabled |
| **Risky settings** | Security settings whose last known value is risky, across workspaces | Each one is a failing configuration check |

## Charts

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Interactive clusters by access mode** | Clusters per access mode | Anything other than standard (shared) or dedicated (single user) is a finding |
| **Top denied network targets** (30 days) | Inbound paths and outbound destinations denied most | Outbound denials to unknown domains can be exfiltration attempts; repeated legitimate ones need an allow-list entry |
| **Security settings by status** | Settings per name, ✅ OK vs ⚠️ Risky across workspaces | The hardening gaps, setting by setting |

## Tables

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Workspace security settings (last known value)** | Per workspace and setting: value, status, last changed, by whom | The configuration baseline. Values are reconstructed from audit changes within retention: a setting never changed in the last 365 days does not appear |
| **Security setting changes** | Each change: actor, setting, new value, status | Who switched off a control. A risky change is a HIGH signal in the [Splunk live dashboard](../splunk.md) |
| **Interactive clusters** | Workspace, cluster, owner, access mode, UC-secured, policy, runtime, init scripts | Hand the list to the cluster owners |
