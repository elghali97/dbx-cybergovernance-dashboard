# Architecture

```
 system tables                        refresh job (every 6 h)                   <catalog>.security_posture            consumers
 ─────────────                        ───────────────────────                   ──────────────────────────            ─────────
 access.audit                 ─┐      incremental: last 2 days replaced        audit_security_events (365 d)    ┐
 access.table_lineage          │ ──▶  atomically (INSERT … REPLACE WHERE) ──▶  auth / denied / secrets /        │
 access.inbound|outbound_net   │                                               exports / sharing / network /    ├─▶ semantic views ─▶ Dashboard
 access.workspaces_latest      │                                               lineage *_daily (90 d)           │   checks, findings     Genie agent
 information_schema.*          │ ──▶  rebuilt every run                  ──▶   uc_grants, owners, tags, ABAC,   │   score, KPIs   ─▶ Genie One weekly
 tags.governed_tags            │                                               masks, sensitive columns,        │                       scheduled task
 data_classification.results   │                                               coverage, sharing, compute       ┘
 compute.clusters             ─┘      findings + daily snapshot         ──▶   security_findings_latest, posture_snapshots
```

## Layers

| Layer | Objects | Defined in | Refreshed |
|---|---|---|---|
| Sources | `src_*` views over system tables | `src/sql/10_sources.sql` | never queried by consumers |
| Activity tables | `audit_security_events`, `auth_events_daily`, `access_denied_daily`, `secret_access_daily`, `data_export_daily`, `delta_sharing_activity_daily`, `network_events_daily`, `table_access_activity` | `src_<name>` views | incrementally on `event_date`, liquid-clustered |
| State tables | `workspaces`, `uc_grants`, `securable_owners`, `governed_tags`, `tag_assignments`, `abac_policies`, `fine_grained_controls`, `sensitive_columns`, `table_governance_coverage`, `delta_sharing_posture`, `compute_posture` | `src_<name>` views | rebuilt every run |
| Semantic views | `failed_auth_events`, `identity_changes`, `token_events`, `ip_access_list_changes`, `uc_permission_changes`, `workspace_acl_changes`, `tag_changes`, `policy_changes`, `data_export_events`, `workspace_config_changes`, `workspace_config_latest` | `src/sql/20_semantic.sql` | views over `audit_security_events` |
| Posture | `security_checks`, `security_findings`, `security_findings_latest`, `check_results`, `posture_score`, `posture_snapshots`, `posture_trend`, `activity_kpis_daily`, `weekly_activity_kpis` | `src/sql/30_findings.sql` | findings materialised every run, one snapshot per day |
| Live views | `live_<semantic view>` (same definitions over `src_audit_security_events`), `live_security_events`, `live_access_denied_events`, `live_network_denials` | `src/sql/20_semantic.sql` (second variant), `src/sql/40_live.sql` | never: they read `system.access.audit` at query time (about 10 minutes behind), for the [Splunk app](splunk.md) |

Every table and view has a description. The Genie agent relies on these descriptions, so keep them accurate when you
change a definition.

## Refresh job (`src/refresh.py`)

1. **Preflight:**
   - fails with the exact `GRANT` statements if `system.access.audit` is not readable;
   - replaces each optional system table that is missing (Preview / not granted) by an empty result with the same
     columns;
   - creates the catalog / schema if needed and grants the security group `USE SCHEMA` + `SELECT`.
2. **Source views:** renders and runs `10_sources.sql`.
3. **State tables:** `CREATE OR REPLACE TABLE <name> AS SELECT * FROM src_<name>`.
4. **Activity tables:**
   - the first load back-fills 365 days (security events) or 90 days (daily aggregates);
   - later runs replace the last 2 days atomically, to catch late-arriving audit events;
   - rows older than 365 days are purged;
   - a table whose columns no longer match its `src_` view is rebuilt.
5. **Semantic and posture views:** `20_semantic.sql`, `30_findings.sql`.
6. **Findings:** materialises `security_findings_latest` and writes today's row in `posture_snapshots`.

It logs one line per step with its duration and result.

**Live views.** `20_semantic.sql` is rendered twice (`SEMANTIC_VARIANTS` in `refresh.py`): over the materialised
`audit_security_events` for the dashboard, Genie and the checks, and as `live_*` views over `src_audit_security_events`,
which read the audit log when queried. `live_security_events` (`40_live.sql`) is one feed of all security events with
a `category` and a `signal` (HIGH / MEDIUM / INFO), computed in a single scan of the audit log (a union of the topic
views would scan it once per topic: 6 seconds instead of 100 for a day on a large account). Its rules mirror the topic
views: keep them in sync. Live queries must filter on `event_date` (partition pruning) and `event_time`.

## Publish task (`src/publish.py`)

Runs after the refresh task:
- creates or updates the **Genie agent** from `src/genie/security_posture.genie.json` (Genie requires the tables to
  exist, which is why this is not done at deploy time);
- creates or updates the **dashboard** from `src/dashboards/security_posture.lvdash.json`, with its datasets pointed at
  the schema and its Ask Genie button at the agent, and publishes it (without embedded credentials);
- gives the security group `CAN RUN` on both.

Both live in the bundle's `resources` folder. Their ids and a hash of what was published are stored in
`published_assets`: unchanged assets are left alone, so UI edits survive the scheduled runs, and a deleted asset is
created again.

## Why it is fast

- Consumers never scan `system.access.audit`, which holds hundreds of millions of rows a week at large accounts.
  Only security-relevant events are kept, and high-volume activity is pre-aggregated per day.
- `information_schema` state is snapshotted once per run instead of being joined at query time.
- Dashboard counters sum columns of datasets pre-aggregated by their filter dimensions (date, workspace, catalog), so
  each KPI is a tiny query with a sparkline. High-cardinality rankings use top-15 datasets.

Measured on a very large internal account (about 4,500 workspaces):
- first load: 9 minutes;
- incremental refresh: 5 minutes;
- all 139 dashboard widget queries: 71 seconds, against more than 20 minutes when querying system tables directly.

## Security considerations

- The refresh job runs with the deployer's identity. Prod files therefore go to the deployer's home folder, never
  `/Workspace/Shared`, so nobody else can change the code that runs with those rights.
- The schema contains security-sensitive metadata (grants, admin changes, IP addresses). Keep the catalog / schema
  restricted to the security group.
- The dashboard does not embed credentials: every viewer queries with their own permissions.
