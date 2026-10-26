# Splunk dashboards and alerts

A Splunk app, **Databricks Security Posture** (`splunk/databricks_security_posture`), brings the security posture and
near real-time security activity of Databricks into Splunk Enterprise (on-premises), for SOC teams that work in Splunk.
It queries Databricks through the [Databricks Add-on for Splunk](https://github.com/databrickslabs/splunk-integration)
(`TA-Databricks`, [Splunkbase 5416](https://splunkbase.splunk.com/app/5416)): no data is indexed in Splunk, no
forwarder, no export job.

| | What | Source | Freshness |
|---|---|---|---|
| 📡 **Databricks Security - Live activity** | Security events as they happen: KPIs, timeline by category, HIGH signals to act on, latest events, most active actors, failing source IPs, denied data access, network denials. Filters: time range, workspace, signal, actor (click an actor to pivot) | `live_*` views, reading `system.access.audit` at query time | Refreshes every 5 minutes; audit events arrive about 10 minutes after they happen |
| 🛡️ **Databricks Security - Posture** | Posture score and trend, category scorecard, the 32 checks (click a title for the best practice, a recommendation for the documentation), findings by severity and category, activity this week vs last week | Tables materialised by the refresh job | Every 6 hours (refresh job schedule) |
| 🚨 **4 alerts** (disabled until you enable them) | HIGH security signal · failed authentication burst · mass interactive data export · denied data access burst | `live_*` views | Every 15 minutes |

## How it works

```
Splunk search head ──▶ TA-Databricks `databricksquery` ──▶ SQL warehouse ──▶ <catalog>.<schema>.live_*   ──▶ system.access.audit
 (dashboards, alerts)    (OAuth M2M / PAT / Entra ID)       (Statement API)      <catalog>.<schema>.posture tables (refresh job)
```

The Security Posture bundle creates the views; the Splunk app only sends SQL:

| View | One row per | Used by |
|---|---|---|
| `live_security_events` | security event, with `category` and `signal` (HIGH / MEDIUM / INFO) | live dashboard, HIGH-signal, failed-auth and export alerts |
| `live_access_denied_events` | denied Unity Catalog / SQL request | live dashboard, denied-access alert |
| `live_network_denials` | network policy denial (inbound and serverless egress) | live dashboard |
| `live_failed_auth_events`, `live_identity_changes`, `live_token_events`, `live_uc_permission_changes`, `live_workspace_acl_changes`, `live_tag_changes`, `live_policy_changes`, `live_data_export_events`, `live_workspace_config_changes`, … | the same topic views as the dashboard (`20_semantic.sql`), read live | your own searches |

**Signals** in `live_security_events` (only successful changes are HIGH or MEDIUM; refused changes are INFO):

| Signal | Events |
|---|---|
| **HIGH**, act now | admin rights granted · PAT created without expiry · high privilege (ALL PRIVILEGES, MANAGE, MODIFY, CREATE …) granted to all users · IP access list deleted · ABAC policy deleted · open-sharing recipient token retrieved |
| **MEDIUM**, review | failed authentication · IP access list block · IP access list change · workspace setting change · admin rights removed · PAT > 90 days · grant to all users or ALL PRIVILEGES / MANAGE grant · classification tag removed · governed tag policy, cluster / serverless policy deletion or global init script change · recipient created, token rotated or share permissions changed · object or secret ACL change for all users |
| **INFO** | every other security event: user and group changes, grants and revokes, tag changes, policy updates, exports … |

The live views run with their owner's rights (the identity that deployed the bundle), so Splunk only needs `SELECT`
on the schema, not on the system tables.

## Prerequisites

1. **Security Posture bundle 1.2.0 or later deployed**, and the refresh job run at least once (it creates the `live_*`
   views). See [deployment.md](deployment.md).
2. **Splunk Enterprise 9.1 – 9.3** with the **Databricks Add-on for Splunk 1.4 or later** (SQL warehouse support) on
   the search head.
3. **A Databricks service principal for Splunk** (recommended: OAuth M2M), with:
   ```sql
   -- run as the schema owner or a metastore admin
   GRANT USE CATALOG ON CATALOG <catalog> TO `<splunk-sp-application-id>`;
   GRANT USE SCHEMA, SELECT ON SCHEMA <catalog>.security_posture TO `<splunk-sp-application-id>`;
   ```
   and **CAN USE** on a SQL warehouse (serverless recommended: it starts in seconds, and the add-on starts a stopped
   warehouse). Alternatively, add the service principal to the security group of the bundle (`security_group` in
   `config.yml`), which already has these grants.

## Install

### 1. Configure the Databricks Add-on

In Splunk: **Apps → Databricks Add-on for Splunk → Configuration**:

- **Databricks Credentials → Add**: Account Name `databricks` (or any name, see step 2), Databricks Instance
  `https://<workspace-url>`, *'databricksquery' to run on* **DBSQL Warehouse**, Databricks Warehouse ID `<warehouse id>`,
  Authentication Method **Databricks OAuth (M2M)** with the service principal's client ID and secret.
- **Additional Parameters**: keep *Query Result Limit* at 10000 or more and *Command Timeout Value* at 300 or more.

Check it from the Search app: `| databricksquery account_name="databricks" query="SELECT current_user()"`.

### 2. Install the app

**Option A — app package (recommended, includes the alerts).** Build it with your values:

```bash
python3 tools/build_splunk.py --account databricks --schema <catalog>.security_posture --package
# optional: --warehouse-id <id> to pin a warehouse instead of the one configured on the add-on account
```

then in Splunk: **Apps → Manage Apps → Install app from file** → `dist/databricks_security_posture-1.2.0.tar.gz`. On a
search head cluster, deploy it with the deployer like any app.

**Option B — paste a dashboard.** **Dashboards → Create New Dashboard → Classic Dashboards**, give it a name, then
**Source** and paste `splunk/databricks_security_posture/default/data/ui/views/databricks_security_live.xml` (or
`..._posture.xml`). Set your values in the `<init>` block at the top:

```xml
<set token="dbx_account">databricks</set>                 <!-- add-on account name -->
<set token="sp">security.security_posture</set>           <!-- <catalog>.<schema> of the bundle -->
<set token="dbx_warehouse"> </set>                        <!-- or warehouse_id="<id>" -->
```

### 3. Enable the alerts (option A)

**Settings → Searches, reports, and alerts**, app *Databricks Security Posture*: enable each alert and add an action
(e-mail, webhook, notable event …). They run every 15 minutes and are suppressed per event / principal for 2 hours so
the overlapping windows do not alert twice.

| Alert | Fires when | Suppressed on |
|---|---|---|
| Databricks - HIGH security signal | any HIGH signal in the last 45 minutes (one result per event) | `event_id` |
| Databricks - Failed authentication burst | ≥ 20 failed authentications for one principal and IP in an hour | principal, IP |
| Databricks - Mass interactive data export | ≥ 20 interactive downloads / exports by one person in an hour | principal |
| Databricks - Denied data access burst | ≥ 50 denied Unity Catalog / SQL requests by one principal in an hour | principal |

Thresholds are in `ALERTS` in `tools/build_splunk.py` (or edit the alert in Splunk).

## Using the live dashboard

- **Time range**: relative ranges (last 15 minutes … last 90 days). Charts bucket by 1 minute up to 2 hours, then 5 /
  15 minutes, 1 hour, 1 day. Ranges are capped at 90 days.
- **Signal**: start with HIGH + MEDIUM for triage; INFO adds the full trail.
- **Actor**: type a user, service principal ID or pattern (`*@contractor.com`), or **click an actor** in any table to
  pivot every panel on it.
- **Audit feed delay** shows how far behind the audit log is (normally 5 to 15 minutes). Above 30 minutes, events are
  delayed on the Databricks side.

## Cost and performance

Each refresh of the live dashboard runs 8 small SQL statements (plus the workspace list when it opens) (one scan of the audit log each, partition-pruned on
the selected dates). Measured on a large account (about 800,000 audit events per hour): 5 to 20 seconds each on a
small serverless warehouse. The warehouse stays up while someone watches the dashboard (5-minute refresh) and the
alerts run (every 15 minutes): with the default auto-stop, expect it to run continuously if alerts are enabled. Size
the warehouse (or use a dedicated one) accordingly; the posture dashboard only reads small tables.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Account 'databricks' not found` | Use the account name of the add-on configuration (`--account`, or the `dbx_account` token) |
| `TABLE_OR_VIEW_NOT_FOUND ... live_security_events` | Wrong schema (`--schema` / `sp` token), or the bundle is older than 1.2.0 / the refresh job never ran |
| `PERMISSION_DENIED` / `INSUFFICIENT_PERMISSIONS` | Grant the Splunk service principal `USE CATALOG`, `USE SCHEMA`, `SELECT` (see prerequisites) |
| `No SQL warehouse found with ID` | Warehouse ID of the add-on account, or `--warehouse-id`; the service principal needs CAN USE |
| Panels stay on *Waiting for input* | A token is missing: check the `<init>` block, and use a relative or absolute time range (real-time ranges are not supported) |
| Unclear error | `$SPLUNK_HOME/var/log/TA-Databricks/` logs of the add-on |

## What was tested

The app was installed in Splunk Enterprise 9.3 (Docker) with TA-Databricks 1.4.2 and rendered with every panel on live
data from a large Databricks account, the actor drill-down and filters were exercised, and the four alert searches
were executed. In that test the add-on's HTTP call was replaced by a replay of the same SQL statements run against
Databricks (the statements, tokens, SPL post-processing and visualizations are the real ones). `tools/check_splunk.py`
runs every SQL statement of the app against a deployed schema.
