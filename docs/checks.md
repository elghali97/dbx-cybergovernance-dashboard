# Security checks

32 checks modelled on the [Security Analysis Tool](https://github.com/databricks-industry-solutions/security-analysis-tool)
(SAT) best practices, limited to what system tables can show. Each check (`check_results`) carries two links that
resolve to the cloud of the metastore (docs.databricks.com for AWS / GCP, learn.microsoft.com for Azure):

- `best_practice_url`: the Databricks security best-practice section behind the check. The check title on the
  dashboard links to it.
- `doc_url`: the documentation page explaining the remediation. The recommendation on the dashboard links to it.

**Score.** A check passes when it has no finding. The score is the weighted share of passing checks (HIGH 5,
MEDIUM 3, LOW 1), overall and per category.

| ID | Severity | Check | Detects | SAT ref |
|---|---|---|---|---|
| IA-01 | HIGH | PAT created without expiry | PATs created in the last 90 days without expiry | IA-4 |
| IA-02 | MEDIUM | PAT created with lifetime > 90 days | Long-lived PATs created in the last 90 days | IA-6 |
| IA-03 | MEDIUM | Max token lifetime not enforced | `maxTokenLifetimeDays` unset, 0 or > 90 | IA-5 |
| IA-04 | LOW | Users authenticating with PATs | Human users on PATs in the last 7 days | IA-8 |
| IA-05 | HIGH | Admin privileges granted | Admin rights / admin-group membership granted in 7 days | INFO-6 |
| IA-06 | MEDIUM | Repeated authentication failures | ≥ 20 failures per principal / IP per day | IA-1 |
| IA-07 | LOW | Requests blocked by IP access lists | ≥ 50 blocked requests per IP in 7 days | NS-5 |
| AC-01 | HIGH | High privilege granted to all users | ALL PRIVILEGES / MANAGE / MODIFY / CREATE … to all users | GOV-21 |
| AC-02 | MEDIUM | Catalog / schema open to all users | Direct catalog / schema / metastore grants to all users | GOV-21 |
| AC-03 | MEDIUM | Powerful privilege granted to an individual | ALL PRIVILEGES / MANAGE granted to a user | GOV-35 |
| AC-04 | MEDIUM | Critical securable owned by an individual | Catalogs, schemas, locations, credentials, shares … owned by a user | GOV-21 |
| AC-05 | MEDIUM | New grants to all users | Grants to all users in the last 7 days | GOV-21 |
| AC-06 | MEDIUM | Metastore privileges held by individuals | Metastore privileges granted to users | GOV-21 |
| DP-01 | HIGH | Sensitive column without protection | Classified / PII columns with no mask and no ABAC policy | DP-* |
| DP-02 | MEDIUM | High volume of interactive data exports | ≥ 50 interactive downloads / exports per principal in 7 days | DP-5 |
| DP-03 | MEDIUM | Data exfiltration setting enabled | Downloads, export, clipboard, DBFS browser, web terminal … enabled | DP-6 |
| DP-04 | MEDIUM | Secret scope shared with all users | Secret ACL granted to `users` in 90 days | DP-1 |
| GT-01 | LOW | Schemas with untagged tables | Tables with no tag (incl. inherited) | – |
| GT-02 | LOW | Schemas with undocumented tables | Tables without a description | – |
| GT-03 | MEDIUM | Classification tag removed | Classification / PII tag removed in 7 days | – |
| PO-01 | MEDIUM | Security policy deleted | ABAC, governed tag, cluster or serverless policy deleted in 7 days | – |
| PO-02 | HIGH | ABAC policy exempts all users | ABAC policy whose EXCEPT list contains all users | – |
| PO-03 | MEDIUM | Global init script changed | Global init script created / updated / deleted in 7 days | GOV-* |
| DS-01 | HIGH | Open-sharing recipient without IP allow-list | TOKEN recipient with shares and no IP list | GOV-18 |
| DS-02 | HIGH | Open-sharing token without expiry | Token never expires or expires in > 365 days | GOV-17 |
| CO-01 | MEDIUM | Cluster not secured by Unity Catalog | Interactive cluster in no-isolation / legacy access mode | GOV-* |
| CO-02 | LOW | Interactive cluster without policy | Interactive cluster without compute policy | GOV-* |
| CO-03 | MEDIUM | Cluster on unsupported runtime | Interactive cluster on DBR < 13 | GOV-* |
| NW-01 | LOW | Inbound requests denied by network policy | Context-based ingress / IP rule denials in 7 days | NS-12 |
| NW-02 | LOW | Serverless egress blocked | Serverless egress denials in 7 days | NS-14 |
| AU-01 | MEDIUM | Verbose audit logs disabled | `enableVerboseAuditLogs` = false (last known) | GOV-15 |
| AU-02 | HIGH | IP access lists disabled | `enableIpAccessLists` = false (last known) | NS-5 |

## Customising

- **Thresholds, windows and severities** are in `src/sql/30_findings.sql`: the `security_checks` values and the
  `security_findings` view, one block per check.
- **Adding a check:** add a row to `security_checks` (with a best-practice path and a doc path) and a `UNION ALL`
  block to `security_findings` returning `check_id, workspace_id, workspace_name, object_type, object_name, detail,
  detected_at`. Then redeploy and run the refresh.

## Not covered (needs account-level access)

Some account console settings are not recorded as audit events within retention: private connectivity / NCC,
customer-managed keys, account IP access lists, log delivery, the compliance security profile on workspaces that
never changed it, and service-principal secret age. Workspace settings are reconstructed from change events
(365-day audit retention), so a setting never changed in that window does not appear.
