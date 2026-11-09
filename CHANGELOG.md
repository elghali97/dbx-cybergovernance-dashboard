# Changelog

## 1.3.0

- **Threat detections** modelled on the Databricks Security Reference Architecture (SRA) queries and alerts
  ([docs/use-cases.md](docs/use-cases.md)): new dashboard page, `detection_rules` (thresholds) and `security_detections`
  (repeated failed logins, IP access list failures, repeated access to secrets, repeated unauthorized Unity Catalog and
  data requests, potential privilege escalation, download / destructive / read-write bursts, print statements, access
  to multiple workspaces), `sensitive_operations` (Terms of Service, account settings and admins, Databricks support
  access, global init scripts, DBFS mounts, libraries on all clusters, open-sharing recipients without IP access list,
  recipient token lifetime, IP-denied sharing queries, compliance security profile host alerts), and two new activity
  tables: `security_activity_hourly` and `access_footprint_daily` (IP addresses, /24 ranges, workspaces per principal).
- 12 new checks (44): IA-08, IA-09, AC-07, AC-08, AC-09, DP-05, DP-06, DP-07, CO-04, CO-05, CO-06, DS-03.
- **Fix:** Unity Catalog and other account-level audit events are now attributed to the workspace they came from
  (`request_params.workspace_id`); they were shown as account console events.
- Activity tables are rebuilt when their source view definition changes (definition hash), not only their columns.
  The first run after this upgrade rebuilds them all.
- Secret access keeps the secret key; setting changes show their scope (ACCOUNT / WORKSPACE).
- Splunk: new *Threat detections* dashboard (one panel per SRA use case, refreshed or live source), behavioural
  detections on the live dashboard, alerts consolidated to three (HIGH signal, behavioural detection, sensitive
  operation) using the thresholds of `detection_rules`.
- Genie agent: detections, sensitive operations and the access footprint replace three daily tables (30-table limit).

## 1.2.0

- **Splunk app** (`splunk/`, [docs/splunk.md](docs/splunk.md)) for Splunk Enterprise with the Databricks Add-on for
  Splunk: *Live activity* dashboard (near real-time, drill-down on actors), *Posture* dashboard, and four alerts (HIGH
  signal, failed authentication burst, mass export, denied access burst). `tools/build_splunk.py --package` builds the
  installable app with the customer's add-on account and schema; `tools/check_splunk.py` checks its SQL.
- **Live views** created by the refresh job: `live_*` variants of every semantic view, and `live_security_events`,
  `live_access_denied_events`, `live_network_denials`, reading `system.access.audit` at query time (about 10 minutes
  behind). `live_security_events` classifies every security event with a category and a HIGH / MEDIUM / INFO signal.
- Semantic views expose `source_ip` (who changed what, from where).
- **Dashboard guide** ([docs/dashboard](docs/dashboard/README.md)): one page per dashboard page, explaining each
  visualization, how to read it and what to do; the README maps every page to its coverage and use cases.

## 1.1.0

- Fix: the first Deploy failed with `cannot create resources.genie_spaces.security_posture_genie ... does not exist`
  because Genie checks that the agent's tables exist, and they are only created by the refresh job. The dashboard
  and the Genie agent are now created by a new `publish` task of the job, after the refresh: Deploy, then run the
  job once. Existing deployments: the next Deploy removes the bundle-managed dashboard and agent, the next run
  creates them again (new URLs).
- `tools/links.py` prints the links of a deployment (used by `deploy.sh` and the GitHub Actions workflow).

## 1.0.0

- Dashboard (8 pages, SAT-style). The posture overview links each check to the Databricks security best practice
  and the remediation docs.
- Security Posture Analyst Genie agent: 30 tables, instructions and example queries.
- Refresh job: materialised, incremental layer over system tables, with a preflight check and fallbacks for
  optional Preview tables.
- 32 security checks with weighted posture score and daily snapshots.
- Weekly report as a Genie One scheduled task.
- One-step deployment: workspace UI Deploy button, `./deploy.sh`, GitHub Actions workflow.
