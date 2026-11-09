# Security use cases: where the evidence is and where it is covered

The detection use cases of the [Databricks Security Reference Architecture (SRA) queries and alerts](https://github.com/databricks/terraform-databricks-sra/blob/main/aws/customizations/workspace/solution_accelerators/system_tables_audit_log/queries_and_alerts.json),
with the audit events that record them and where they are covered in this project:

- **Dashboard:** the *Threat detections* page ([guide](dashboard/03-threat-detections.md)), plus the page named.
- **Splunk:** one panel per use case in the *Threat detections* dashboard, named after the use case ([Splunk guide](splunk.md)).
- **Checks / alerts:** the posture check that fails on it, and the Splunk alert that fires on it.

Every use case reads `system.access.audit` (or another system table) directly, so the coverage does not depend on how
audit logs are exported to a SIEM.

## Why a search on exported raw logs can show "not observed"

These points come from the events of a large Databricks account, and explain most "not observed / not validated"
results when the same use cases are searched in exported logs:

1. **Unity Catalog and account console events are account-level.** They carry `audit_level = ACCOUNT_LEVEL` and
   `workspace_id = 0`; the workspace the request came from is in `request_params.workspace_id` (99.8 % of Unity Catalog
   events). A search on `workspaceId` therefore sees "one workspace", and an export that only covers workspace-level
   events (for example a workspace's diagnostic settings, or only the selected log categories) can miss them. Exports may
   also place account-level events under workspace `0`. This project attributes every event with
   `coalesce(request_params.workspace_id, workspace_id)`.
2. **Many events have no client IP, by design.** Requests issued by Databricks compute or services on behalf of a user
   carry no `source_ip_address`: about 73 % of Unity Catalog events (credentials vended to clusters and SQL warehouses)
   and 99 % of Databricks SQL statement events. Logins, account / workspace API calls and notebook events do carry it.
   IP analysis must keep only events with a non-empty IP, and say so.
3. **A denial is a status code, not an action.** A refused Unity Catalog request is the normal action (`getTable`,
   `generateTemporaryTableCredential` …) with `response.status_code` 401 / 403 (often `PERMISSION_DENIED` in
   `response.error_message`). `authzEval` or `getVolume` with status 200 are successful checks.
4. **Some events are rare or optional.** Terms of Service, mounts, libraries on all clusters or Databricks support access
   may simply not have happened in the period. `use_of_print_statements` needs **verbose audit logs**;
   `host_security_alerts` needs the **compliance security profile / enhanced security monitoring**.
5. **`getPopularTables` is not data usage.** It is the API behind the "popular tables" lists of the UI. Use lineage
   (`system.access.table_lineage`) or the credential requests (`generateTemporary*Credential` with status 200).

## Use cases

| Use case | Audit event (`service_name.action_name`, key fields) | Dashboard | Splunk panel / alert | Check |
|---|---|---|---|---|
| `terms_of_service_changes` | `accounts.acceptTos`, `accounts.sendTos` (account level; `request_params.account_id`, `workspace_id`) | Threat detections › Sensitive operations | panel · *Sensitive operation* alert | – |
| `account_settings_changes` | `accounts.setSetting` / `deleteSetting` with `audit_level = ACCOUNT_LEVEL` (`settingTypeName`, `settingValueForAudit`); account admins: `setAccountAdmin`, `changeAccountOwner` | Threat detections, Compute & config (setting changes, scope ACCOUNT) | panel · *Sensitive operation* alert (admin: HIGH signal) | – |
| `global_init_script_changes` | `globalInitScripts.create` / `update` / `delete` (`name`, `script_id`, `enabled`, `script-SHA256`) | Threat detections, Policies (policy changes) | panel · *Sensitive operation* alert | PO-03 |
| `mount_point_creation` | `dbfs.mount` (`mountPoint`, `source`). `searchMounts` only lists mounts | Threat detections | panel · *Sensitive operation* alert | CO-04 |
| `repeated_access_to_secrets` | `secrets.getSecret` (`scope`, `key`): 10+ distinct secrets per principal in an hour | Threat detections › detections | panel · *Behavioural detection* alert (`SECRET_ACCESS_BURST`) | DP-05 |
| `access_to_secrets_last_90_days` | `secrets.getSecret` per principal and secret (`secret_access_daily` keeps scope and key, 90 days) | Data activity › Secret access | panel `access_to_secrets` | – |
| `access_to_multiple_workspaces` | every event, workspace = `coalesce(request_params.workspace_id, workspace_id)`; 5+ workspaces in a day | Threat detections › Workspaces accessed per principal | panel · alert (`MULTI_WORKSPACE`) | IA-08 |
| `use_of_print_statements` | `notebook.runCommand` / `jobs.runCommand` with `print(` in `commandText` (verbose audit logs). The audit log records the command, not its output | Threat detections › Print statements | panel | – |
| `ip_addresses_used_to_access_databricks` | `source_ip_address` (port removed) of every event, per access level ACCOUNT / UNITY_CATALOG / WORKSPACE | Threat detections › IP addresses | panel | – |
| `ip_address_ranges_used_to_access_databricks` | same, grouped by /24 (IPv4) or /48 (IPv6) | Threat detections › IP ranges | panel | – |
| `repeated_unauthorized_uc_requests` | `unityCatalog.*` with `response.status_code` 401 / 403: more than 25 per principal in an hour | Threat detections, Data access control › Denied data access | panel · alert (`UC_DENIED_BURST`) | AC-07 |
| `repeated_unauthorized_uc_data_requests` | `generateTemporaryTableCredential` / `PathCredential` / `VolumeCredential`, `deltaSharingQueryTable` / `QueryTableChanges` with 401 / 403: more than 15 in an hour | Threat detections | panel · alert (`UC_DATA_DENIED_BURST`) | AC-08 |
| `unauthorized_uc_data_requests_last_90_days` | same events, every principal over the period | Threat detections, Data access control | panel `unauthorized_uc_data_requests` | – |
| `delta_sharing_recipients_without_ip_acls` | `unityCatalog.createRecipient` / `updateRecipient` with `authentication_type = TOKEN` and no `ip_access_list`; current state from `system.information_schema.recipients` / `recipient_allowed_ip_ranges` | Threat detections, Data activity & sharing › recipients | panel + current recipients panel · HIGH signal | DS-01 |
| `delta_sharing_ip_access_list_failures` | `deltaSharingQueryTable` / `QueryTableChanges` with `request_params.is_ip_access_denied = true` | Threat detections, Data activity & sharing › Delta Sharing activity | panel · *Sensitive operation* alert | DS-03 |
| `delta_sharing_recipient_token_lifetime_change` | `unityCatalog.updateMetastore` with `delta_sharing_recipient_token_lifetime_in_seconds` (0 = never expires) | Threat detections | panel · *Sensitive operation* alert | DS-02 (current tokens) |
| `most_popular_data_products_last_90_days` | `system.access.table_lineage` reads / writes per table and principal (not `getPopularTables`) | Threat detections › Most popular data assets | panel | – |

Other SRA use cases covered the same way:

| Use case | Audit event | Coverage |
|---|---|---|
| `repeated_failed_login_attempts`, `failed_login_attempts_last_90_days` | login actions with 401 / 403 | detection `FAILED_LOGIN_BURST`, Identity & authentication page, check IA-06 |
| `changes_to_admin_users` | `setAdmin`, `removeAdmin`, admins group membership, `setAccountAdmin` | Identity page, HIGH signal, check IA-05 |
| `changes_to_workspace_configuration` | `workspace.workspaceConfEdit` | Compute & config page, checks AU-01 / AU-02 / DP-03 / IA-03 |
| `data_downloads_from_control_plane` | result downloads and exports | detection `DOWNLOAD_BURST`, Data activity page, check DP-02 |
| `ip_access_list_failures`, `ip_access_list_changes` | `IpAccessDenied`, `accountIpAclsValidationFailed`; `create/update/deleteIpAccessList` | detection `IP_ACCESS_DENIED_BURST`, Identity page, check IA-07 |
| `databricks_access_to_customer_workspaces` | `databricksAccess` (`user`, `approver`, `reason`, `duration`) | sensitive operation, check IA-09 |
| `install_library_on_all_clusters` | `clusterLibraries.installLibraryOnAllClusters` | sensitive operation, check CO-05 |
| `long_lifetime_token_generation` | `accounts.generateDbToken` (`tokenExpirationTime`) | checks IA-01 / IA-02, HIGH signal for PATs without expiry |
| `destructive_activities` | delete / trash actions: more than 50 per principal in a day | detection `DESTRUCTIVE_BURST`, check DP-06 |
| `potential_privilege_escalation` | grants, ACL, group, admin, ownership and token changes: more than 25 in an hour | detection `PRIVILEGE_ESCALATION`, check AC-09 |
| `high_number_of_read_writes` | temporary credentials READ / WRITE: more than 20 securables read and 20 written in an hour | detection `READ_WRITE_BURST`, check DP-07 |
| `most_privileged_users` | `system.information_schema.*_privileges` | Data access control › Top grantees |
| `ip_addresses_used_to_access_uc_data` | credential requests with a client IP | Threat detections › IP addresses (column *Data access*) |
| `clam_av_*`, `capsule8_*` | `clamAVScanService-dataplane`, `capsule8-alerts-dataplane` | sensitive operations, check CO-06 |

## Tuning

- **Thresholds** of the behavioural detections are in the `detection_rules` view (`src/sql/25_detections.sql`); the
  checks, the dashboard and the Splunk alert all read it.
- **Windows** of the checks (7 days) are in `src/sql/30_findings.sql`.
- Service principals running automation can exceed volume thresholds every day (deletes, permission changes, read /
  writes). Review them once, then raise the rule's threshold in `detection_rules`, or filter them out in the Splunk
  alert (`| where principal!="<application id>"`).
