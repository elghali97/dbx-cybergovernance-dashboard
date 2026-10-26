-- =============================================================================
-- Security Posture — checks catalogue, findings, posture score, trend & activity KPIs
-- Checks are modelled on the Security Analysis Tool (SAT) best practices, limited to what can
-- be evaluated from system tables. sat_reference = closest SAT check id
-- (configs/security_best_practices.csv). Documentation links resolve to the cloud of the
-- metastore: docs.databricks.com/aws|gcp or learn.microsoft.com (Azure).
-- =============================================================================

CREATE OR REPLACE VIEW ${catalog}.${schema}.security_checks
COMMENT 'Catalogue of security posture checks evaluated from system tables (one row per check): check_id, category (+ category_order), severity (HIGH / MEDIUM / LOW), title, what it detects, recommendation, closest SAT check id, best_practice_url (Databricks security best practices section) and doc_url (documentation page explaining the remediation).'
AS
WITH c AS (
  SELECT * FROM VALUES
    ('IA-01', 'Identity & Access', 'HIGH', 'PAT created without expiry',
     'Personal access tokens created in the last 90 days with no expiration date.',
     'Set a maximum lifetime for new tokens and prefer OAuth (M2M / U2M) over PATs.', 'IA-4',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#identity-and-access-management-best-practices',
     'admin/access-control/tokens#set-the-maximum-lifetime-of-new-personal-access-tokens'),
    ('IA-02', 'Identity & Access', 'MEDIUM', 'PAT created with lifetime > 90 days',
     'Personal access tokens created in the last 90 days that live longer than 90 days.',
     'Reduce the maximum token lifetime to 90 days or less and revoke long-lived tokens.', 'IA-6',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#identity-and-access-management-best-practices',
     'admin/access-control/tokens#monitor-and-revoke-personal-access-tokens-in-the-account'),
    ('IA-03', 'Identity & Access', 'MEDIUM', 'Max token lifetime not enforced',
     'Workspaces whose last known maxTokenLifetimeDays is unset, 0 or above 90.',
     'Set the maximum lifetime of new personal access tokens to 90 days or less.', 'IA-5',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#identity-and-access-management-best-practices',
     'admin/access-control/tokens#set-the-maximum-lifetime-of-new-personal-access-tokens'),
    ('IA-04', 'Identity & Access', 'LOW', 'Users authenticating with PATs',
     'Human users that authenticated to APIs with a personal access token in the last 7 days.',
     'Move users to OAuth U2M and restrict who can create and use personal access tokens.', 'IA-8',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#identity-and-access-management-best-practices',
     'admin/access-control/tokens#use-oauth-instead-of-personal-access-tokens'),
    ('IA-05', 'Identity & Access', 'HIGH', 'Admin privileges granted',
     'Workspace / account admin rights or admin-group membership granted in the last 7 days.',
     'Review each admin grant; keep admins minimal and managed through groups synced from the identity provider.', 'INFO-6',
     'data-governance/unity-catalog/best-practices#admin-roles-and-powerful-privileges',
     'admin/users-groups/#sync-identities-from-your-identity-provider'),
    ('IA-06', 'Identity & Access', 'MEDIUM', 'Repeated authentication failures',
     'Principals or source IPs with 20+ failed authentications in a single day over the last 7 days.',
     'Investigate credential stuffing or misconfigured automation; rotate the credentials involved.', 'IA-1',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#5-monitor-system-security',
     'admin/system-tables/audit-logs'),
    ('IA-07', 'Identity & Access', 'LOW', 'Requests blocked by IP access lists',
     'Source IPs blocked by IP access lists 50+ times in the last 7 days.',
     'Confirm the source is not a legitimate integration; otherwise treat it as reconnaissance.', 'NS-5',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#network-security-best-practices',
     'security/network/front-end/ip-access-list-workspace'),
    ('AC-01', 'Access Control', 'HIGH', 'High privilege granted to all users',
     'Direct grants of high privileges (ALL PRIVILEGES, MANAGE, MODIFY, CREATE ...) to account users / users.',
     'Grant privileges to purpose-specific groups instead of all users.', 'GOV-21',
     'data-governance/unity-catalog/best-practices#privilege-assignment',
     'data-governance/unity-catalog/manage-privileges/#revoke-permissions-on-an-object'),
    ('AC-02', 'Access Control', 'MEDIUM', 'Catalog / schema open to all users',
     'Direct grants on catalogs, schemas or the metastore to account users / users.',
     'Confirm the data is meant to be open company-wide; otherwise scope grants to groups.', 'GOV-21',
     'data-governance/unity-catalog/best-practices#privilege-assignment',
     'data-governance/unity-catalog/manage-privileges/#revoke-permissions-on-an-object'),
    ('AC-03', 'Access Control', 'MEDIUM', 'Powerful privilege granted to an individual',
     'ALL PRIVILEGES or MANAGE granted directly to an individual user (not a group or service principal).',
     'Grant through groups so access follows joiner / mover / leaver processes.', 'GOV-35',
     'data-governance/unity-catalog/best-practices#privilege-assignment',
     'data-governance/unity-catalog/manage-privileges/#-grant-permissions-on-an-object'),
    ('AC-04', 'Access Control', 'MEDIUM', 'Critical securable owned by an individual',
     'Catalogs, schemas, external locations, storage credentials, connections, shares or recipients owned by a user.',
     'Transfer ownership to a group or a service principal.', 'GOV-21',
     'data-governance/unity-catalog/best-practices#admin-roles-and-powerful-privileges',
     'data-governance/unity-catalog/manage-privileges/#transfer-ownership'),
    ('AC-05', 'Access Control', 'MEDIUM', 'New grants to all users',
     'Grants to account users / users made in the last 7 days.',
     'Review recent broad grants and revoke the unintended ones.', 'GOV-21',
     'data-governance/unity-catalog/best-practices#privilege-assignment',
     'data-governance/unity-catalog/manage-privileges/#revoke-permissions-on-an-object'),
    ('AC-06', 'Access Control', 'MEDIUM', 'Metastore privileges held by individuals',
     'Metastore-level privileges (CREATE CATALOG, CREATE EXTERNAL LOCATION ...) granted directly to users.',
     'Delegate metastore privileges to an admin group.', 'GOV-21',
     'data-governance/unity-catalog/best-practices#admin-roles-and-powerful-privileges',
     'data-governance/unity-catalog/manage-privileges/admin-privileges'),
    ('DP-01', 'Data Protection', 'HIGH', 'Sensitive column without protection',
     'Classified / PII-tagged columns with no column mask, on tables not covered by any ABAC policy.',
     'Protect sensitive columns with an ABAC column-mask policy on the governed tag, or a column mask.', 'DP-*',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#4-meet-compliance-and-data-privacy-requirements',
     'data-governance/unity-catalog/abac/'),
    ('DP-02', 'Data Protection', 'MEDIUM', 'High volume of interactive data exports',
     'Principals with 50+ interactive downloads / exports (results, notebooks, files) in the last 7 days.',
     'Validate the business need; disable result downloads or notebook export where not required.', 'DP-5',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#2-protect-data-in-transit-and-at-rest',
     'admin/workspace-settings/notebooks#manage-the-ability-to-download-results-from-notebooks'),
    ('DP-03', 'Data Protection', 'MEDIUM', 'Data exfiltration setting enabled',
     'Last known workspace setting enables result downloads, notebook export, clipboard, DBFS browser, web terminal or uploads.',
     'Disable download, export and clipboard settings unless required.', 'DP-6',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#2-protect-data-in-transit-and-at-rest',
     'admin/workspace-settings/notebooks'),
    ('DP-04', 'Data Protection', 'MEDIUM', 'Secret scope shared with all users',
     'Secret scope ACLs granted to the users group in the last 90 days.',
     'Restrict secret scopes to the identities that need them.', 'DP-1',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#2-protect-data-in-transit-and-at-rest',
     'security/auth/access-control/#secret-acls'),
    ('GT-01', 'Tags & Metadata', 'LOW', 'Schemas with untagged tables',
     'Schemas where tables / views have no tags at table, column, schema or catalog level.',
     'Tag tables with governed tags (domain, classification, owner) to drive ABAC and discovery.', 'n/a',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#4-meet-compliance-and-data-privacy-requirements',
     'admin/governed-tags/'),
    ('GT-02', 'Tags & Metadata', 'LOW', 'Schemas with undocumented tables',
     'Schemas where tables / views have no description.',
     'Add table descriptions (AI-generated comments can help).', 'n/a',
     'data-governance/unity-catalog/best-practices#catalogs-and-schemas',
     'comments/ai-comments'),
    ('GT-03', 'Tags & Metadata', 'MEDIUM', 'Classification tag removed',
     'Classification / PII tags removed from a securable or column in the last 7 days.',
     'Confirm the de-classification was approved: removing a tag can disable ABAC protection.', 'n/a',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#4-meet-compliance-and-data-privacy-requirements',
     'data-governance/unity-catalog/data-classification'),
    ('PO-01', 'Policies', 'MEDIUM', 'Security policy deleted',
     'ABAC policies, governed tag policies, cluster or serverless policies deleted in the last 7 days.',
     'Confirm each deletion went through change management.', 'n/a',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#4-meet-compliance-and-data-privacy-requirements',
     'data-governance/unity-catalog/abac/policies'),
    ('PO-02', 'Policies', 'HIGH', 'ABAC policy exempts all users',
     'ABAC policies whose EXCEPT list includes account users / users (the policy is effectively disabled).',
     'Restrict policy exceptions to a small break-glass group.', 'n/a',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#4-meet-compliance-and-data-privacy-requirements',
     'data-governance/unity-catalog/abac/policies'),
    ('PO-03', 'Policies', 'MEDIUM', 'Global init script changed',
     'Global init scripts created, updated or deleted in the last 7 days (the code runs on every cluster).',
     'Review the script content and restrict who can manage global init scripts.', 'GOV-*',
     'data-governance/unity-catalog/best-practices#compute-configurations',
     'init-scripts/global'),
    ('DS-01', 'Delta Sharing', 'HIGH', 'Open-sharing recipient without IP allow-list',
     'TOKEN (open sharing) recipients with at least one share and no IP access list.',
     'Assign an IP access list to every open-sharing recipient.', 'GOV-18',
     'data-governance/unity-catalog/best-practices#cross-region-and-cross-platform-sharing',
     'opensharing/access-list'),
    ('DS-02', 'Delta Sharing', 'HIGH', 'Open-sharing token without expiry',
     'TOKEN recipients whose activation token never expires or expires in more than 365 days.',
     'Set a recipient token lifetime on the metastore and rotate long-lived tokens.', 'GOV-17',
     'data-governance/unity-catalog/best-practices#cross-region-and-cross-platform-sharing',
     'opensharing/create-recipient-token#update-recipient-token-lifetime'),
    ('CO-01', 'Compute', 'MEDIUM', 'Cluster not secured by Unity Catalog',
     'Active interactive clusters whose access mode is not standard / dedicated (no isolation or legacy), bypassing Unity Catalog controls.',
     'Use standard or dedicated access mode and enforce it with compute policies.', 'GOV-*',
     'data-governance/unity-catalog/best-practices#compute-configurations',
     'compute/configure#access-modes'),
    ('CO-02', 'Compute', 'LOW', 'Interactive cluster without policy',
     'Active UI / API-created clusters with no compute policy attached.',
     'Require compute policies for all users.', 'GOV-*',
     'data-governance/unity-catalog/best-practices#compute-configurations',
     'admin/clusters/policies'),
    ('CO-03', 'Compute', 'MEDIUM', 'Cluster on unsupported runtime',
     'Active interactive clusters on a Databricks Runtime major version below 13.',
     'Upgrade to a supported LTS runtime to receive security patches.', 'GOV-*',
     'data-governance/unity-catalog/best-practices#compute-configurations',
     'release-notes/runtime/databricks-runtime-ver'),
    ('NW-01', 'Audit & Network', 'LOW', 'Inbound requests denied by network policy',
     'Workspaces with inbound requests denied by context-based ingress / IP rules in the last 7 days.',
     'Review denied sources and confirm policies are in enforcement mode.', 'NS-12',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#network-security-best-practices',
     'security/network/front-end/context-based-ingress'),
    ('NW-02', 'Audit & Network', 'LOW', 'Serverless egress blocked',
     'Workspaces where serverless outbound connections were blocked by the network policy in the last 7 days.',
     'Review blocked destinations: possible exfiltration attempt or missing allow-list entry.', 'NS-14',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#network-security-best-practices',
     'security/network/serverless-network-security/network-policies'),
    ('AU-01', 'Audit & Network', 'MEDIUM', 'Verbose audit logs disabled',
     'Workspaces whose last known enableVerboseAuditLogs setting is false.',
     'Enable verbose audit logs to capture notebook and SQL commands.', 'GOV-15',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#5-monitor-system-security',
     'admin/account-settings/verbose-logs'),
    ('AU-02', 'Audit & Network', 'HIGH', 'IP access lists disabled',
     'Workspaces whose last known enableIpAccessLists setting is false.',
     'Enable and enforce IP access lists, or use private connectivity.', 'NS-5',
     'lakehouse-architecture/security-compliance-and-privacy/best-practices#network-security-best-practices',
     'security/network/front-end/ip-access-list-workspace')
  AS t(check_id, category, severity, title, description, recommendation, sat_reference, best_practice_path, doc_path)
),
base AS (
  SELECT CASE lower(split_part(current_metastore(), ':', 1))
           WHEN 'azure' THEN 'https://learn.microsoft.com/en-us/azure/databricks/'
           WHEN 'gcp' THEN 'https://docs.databricks.com/gcp/en/'
           ELSE 'https://docs.databricks.com/aws/en/'
         END AS url
)
SELECT
  c.check_id, c.category,
  CASE c.category WHEN 'Identity & Access' THEN 1 WHEN 'Access Control' THEN 2 WHEN 'Data Protection' THEN 3
                  WHEN 'Tags & Metadata' THEN 4 WHEN 'Policies' THEN 5 WHEN 'Delta Sharing' THEN 6
                  WHEN 'Compute' THEN 7 ELSE 8 END AS category_order,
  c.severity,
  CASE c.severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END AS severity_order,
  CASE c.severity WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 3 ELSE 1 END AS severity_weight,
  c.title, c.description, c.recommendation, c.sat_reference,
  concat(base.url, c.best_practice_path) AS best_practice_url,
  concat(base.url, c.doc_path) AS doc_url
FROM c CROSS JOIN base
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.security_findings
COMMENT 'Live security findings: one row per failing (check_id, object). workspace_id is NULL for metastore-level objects. object_type / object_name identify what failed, detail gives the evidence, detected_at is the most recent evidence time. Check metadata (severity, title, recommendation, documentation links) is denormalised. Query security_findings_latest (refreshed by the job) for speed.'
AS
WITH f AS (
  -- IA-01 / IA-02 PAT lifetime
  SELECT 'IA-01' AS check_id, workspace_id, workspace_name, 'TOKEN' AS object_type, coalesce(actor, token_hash) AS object_name,
         concat('PAT created without expiry on ', CAST(event_date AS STRING), coalesce(concat(' (scopes: ', token_scopes, ')'), '')) AS detail,
         event_time AS detected_at
  FROM ${catalog}.${schema}.token_events
  WHERE lifetime_bucket = 'No expiry' AND event_date >= current_date() - 90 AND coalesce(status_code, 200) < 400
  UNION ALL
  SELECT 'IA-02', workspace_id, workspace_name, 'TOKEN', coalesce(actor, token_hash),
         concat('PAT lifetime ', CAST(lifetime_days AS STRING), ' days, created ', CAST(event_date AS STRING)), event_time
  FROM ${catalog}.${schema}.token_events
  WHERE lifetime_bucket = '> 90 days' AND event_date >= current_date() - 90 AND coalesce(status_code, 200) < 400
  UNION ALL
  -- IA-03 max token lifetime
  SELECT 'IA-03', workspace_id, workspace_name, 'WORKSPACE_SETTING', setting_name,
         concat('maxTokenLifetimeDays = ', coalesce(nullif(setting_value, ''), '<unset>')), last_changed
  FROM ${catalog}.${schema}.workspace_config_latest
  WHERE setting_name = 'maxTokenLifetimeDays' AND is_risky_value
  UNION ALL
  -- IA-04 users on PATs
  SELECT 'IA-04', workspace_id, max(workspace_name), 'USER', principal,
         concat(CAST(sum(events) AS STRING), ' PAT-authenticated requests in the last 7 days'), CAST(max(event_date) AS TIMESTAMP)
  FROM ${catalog}.${schema}.auth_events_daily
  WHERE auth_category = 'PAT' AND principal_type = 'USER' AND event_date >= current_date() - 7
  GROUP BY workspace_id, principal
  UNION ALL
  -- IA-05 admin grants
  SELECT 'IA-05', workspace_id, workspace_name, 'PRINCIPAL', target,
         concat(action_name, ' by ', coalesce(actor, '?'), coalesce(concat(' (group ', group_name, ')'), '')), event_time
  FROM ${catalog}.${schema}.identity_changes
  WHERE is_privileged AND NOT is_removal AND event_date >= current_date() - 7 AND coalesce(status_code, 200) < 400
  UNION ALL
  -- IA-06 repeated authentication failures
  SELECT 'IA-06', workspace_id, max(workspace_name), 'PRINCIPAL_OR_IP', coalesce(principal, source_ip),
         concat(CAST(count(*) AS STRING), ' failures on ', CAST(event_date AS STRING), ' (', array_join(slice(collect_set(action_name), 1, 3), ', '), ')'),
         max(event_time)
  FROM ${catalog}.${schema}.failed_auth_events
  WHERE event_date >= current_date() - 7 AND NOT is_ip_blocked
  GROUP BY workspace_id, coalesce(principal, source_ip), event_date
  HAVING count(*) >= 20
  UNION ALL
  -- IA-07 IP access list blocks
  SELECT 'IA-07', workspace_id, max(workspace_name), 'SOURCE_IP', source_ip,
         concat(CAST(count(*) AS STRING), ' blocked requests, e.g. by ', coalesce(max(principal), '?')), max(event_time)
  FROM ${catalog}.${schema}.failed_auth_events
  WHERE event_date >= current_date() - 7 AND is_ip_blocked
  GROUP BY workspace_id, source_ip
  HAVING count(*) >= 50
  UNION ALL
  -- AC-01 / AC-02 broad grants (current state)
  SELECT CASE WHEN is_high_privilege THEN 'AC-01' ELSE 'AC-02' END, CAST(NULL AS STRING), CAST(NULL AS STRING), securable_type, securable_name,
         concat(privilege_type, ' granted to ', grantee), CAST(NULL AS TIMESTAMP)
  FROM ${catalog}.${schema}.uc_grants
  WHERE is_direct AND is_broad_principal AND (is_high_privilege OR securable_type IN ('CATALOG', 'SCHEMA', 'METASTORE'))
  UNION ALL
  -- AC-03 powerful privilege granted to an individual
  SELECT 'AC-03', NULL, NULL, securable_type, securable_name, concat(privilege_type, ' granted directly to ', grantee), NULL
  FROM ${catalog}.${schema}.uc_grants
  WHERE is_direct AND grantee_type = 'USER' AND privilege_type IN ('ALL PRIVILEGES', 'MANAGE') AND securable_type <> 'METASTORE'
  UNION ALL
  -- AC-04 critical securables owned by individuals
  SELECT 'AC-04', NULL, NULL, securable_type, securable_name, concat('Owned by user ', owner), created
  FROM ${catalog}.${schema}.securable_owners
  WHERE owner_type = 'USER' AND securable_type IN ('CATALOG', 'SCHEMA', 'EXTERNAL_LOCATION', 'STORAGE_CREDENTIAL', 'CONNECTION', 'SHARE', 'RECIPIENT')
  UNION ALL
  -- AC-05 new broad grants
  SELECT 'AC-05', workspace_id, workspace_name, securable_type, securable_name,
         concat(privilege, ' granted to ', principal, ' by ', coalesce(actor, '?')), event_time
  FROM ${catalog}.${schema}.uc_permission_changes
  WHERE change_type = 'GRANT' AND is_broad_principal AND event_date >= current_date() - 7 AND coalesce(status_code, 200) < 400
  UNION ALL
  -- AC-06 metastore privileges held by individuals
  SELECT 'AC-06', NULL, NULL, 'METASTORE', grantee, concat(privilege_type, ' on metastore'), NULL
  FROM ${catalog}.${schema}.uc_grants
  WHERE securable_type = 'METASTORE' AND grantee_type = 'USER'
  UNION ALL
  -- DP-01 unprotected sensitive columns
  SELECT 'DP-01', NULL, NULL, 'COLUMN', concat(s.table_full_name, '.', s.column_name), concat(s.classification, ' (', s.source, ')'), s.detected_at
  FROM ${catalog}.${schema}.sensitive_columns s
  LEFT JOIN ${catalog}.${schema}.table_governance_coverage c ON c.table_full_name = s.table_full_name
  WHERE NOT s.is_masked AND NOT coalesce(c.has_abac_policy_in_scope, FALSE)
  UNION ALL
  -- DP-02 heavy interactive exporters
  SELECT 'DP-02', workspace_id, max(workspace_name), 'PRINCIPAL', principal,
         concat(CAST(count(*) AS STRING), ' interactive exports (', array_join(collect_set(export_channel), ', '), ')'), max(event_time)
  FROM ${catalog}.${schema}.data_export_events
  WHERE event_date >= current_date() - 7
  GROUP BY workspace_id, principal
  HAVING count(*) >= 50
  UNION ALL
  -- DP-03 exfiltration settings enabled
  SELECT 'DP-03', workspace_id, workspace_name, 'WORKSPACE_SETTING', setting_name,
         concat(setting_name, ' = ', setting_value, ' (changed by ', coalesce(last_changed_by, '?'), ')'), last_changed
  FROM ${catalog}.${schema}.workspace_config_latest
  WHERE is_risky_value AND setting_name IN ('enableExportNotebook', 'enableNotebookTableClipboard', 'enableResultsDownloading', 'enableDbfsFileBrowser',
                                            'enableWebTerminal', 'enableUploadDataUis', 'enableFileStoreEndpoint', 'mlflowRunArtifactDownloadEnabled',
                                            'sqlResultsDownloading', 'enableDeprecatedGlobalInitScripts', 'enableDeprecatedClusterNamedInitScripts',
                                            'storeInteractiveNotebookResultsInCustomerAccount')
  UNION ALL
  -- DP-04 secret scopes shared with all users
  SELECT 'DP-04', workspace_id, workspace_name, 'SECRET_SCOPE', object_id,
         concat(coalesce(permission, '?'), ' granted to ', target_principal, ' by ', coalesce(actor, '?')), event_time
  FROM ${catalog}.${schema}.workspace_acl_changes
  WHERE object_type = 'secret_scope' AND action_name = 'putAcl' AND is_broad_principal AND event_date >= current_date() - 90
  UNION ALL
  -- GT-01 / GT-02 metadata gaps aggregated per schema
  SELECT 'GT-01', NULL, NULL, 'SCHEMA', concat_ws('.', catalog_name, schema_name),
         concat(CAST(count_if(NOT is_tagged_incl_inherited) AS STRING), ' of ', CAST(count(*) AS STRING), ' tables untagged'), max(last_altered)
  FROM ${catalog}.${schema}.table_governance_coverage
  GROUP BY catalog_name, schema_name
  HAVING count_if(NOT is_tagged_incl_inherited) > 0
  UNION ALL
  SELECT 'GT-02', NULL, NULL, 'SCHEMA', concat_ws('.', catalog_name, schema_name),
         concat(CAST(count_if(NOT has_comment) AS STRING), ' of ', CAST(count(*) AS STRING), ' tables without description'), max(last_altered)
  FROM ${catalog}.${schema}.table_governance_coverage
  GROUP BY catalog_name, schema_name
  HAVING count_if(NOT has_comment) > 0
  UNION ALL
  -- GT-03 classification tags removed
  SELECT 'GT-03', workspace_id, workspace_name, securable_type, concat_ws('.', securable_name, column_name),
         concat('Tag ', tag_name, ' removed by ', coalesce(actor, '?')), event_time
  FROM ${catalog}.${schema}.tag_changes
  WHERE change_type = 'REMOVE' AND is_classification_tag AND event_date >= current_date() - 7 AND coalesce(status_code, 200) < 400
  UNION ALL
  -- PO-01 security policies deleted
  SELECT 'PO-01', workspace_id, workspace_name, policy_kind, coalesce(policy_name, scope_name, '?'), concat(action_name, ' by ', coalesce(actor, '?')), event_time
  FROM ${catalog}.${schema}.policy_changes
  WHERE is_deletion AND policy_kind <> 'GLOBAL_INIT_SCRIPT' AND event_date >= current_date() - 7 AND coalesce(status_code, 200) < 400
  UNION ALL
  -- PO-02 ABAC policy exempting everyone
  SELECT 'PO-02', NULL, NULL, 'ABAC_POLICY', concat(scope_name, ' / ', policy_name), concat('EXCEPT ', except_principals), NULL
  FROM ${catalog}.${schema}.abac_policies
  WHERE lower(except_principals) RLIKE '(^|, )(account users|users)(,|$)'
  UNION ALL
  -- PO-03 global init scripts
  SELECT 'PO-03', workspace_id, workspace_name, 'GLOBAL_INIT_SCRIPT', coalesce(policy_name, '?'), concat(action_name, ' by ', coalesce(actor, '?')), event_time
  FROM ${catalog}.${schema}.policy_changes
  WHERE policy_kind = 'GLOBAL_INIT_SCRIPT' AND event_date >= current_date() - 7
  UNION ALL
  -- DS-01 / DS-02 open sharing
  SELECT 'DS-01', NULL, NULL, 'RECIPIENT', recipient_name,
         concat('Open-sharing recipient with ', CAST(shares_granted AS STRING), ' share(s) and no IP allow-list'), created
  FROM ${catalog}.${schema}.delta_sharing_posture
  WHERE authentication_type = 'TOKEN' AND shares_granted > 0 AND NOT has_ip_allowlist
  UNION ALL
  SELECT 'DS-02', NULL, NULL, 'RECIPIENT', recipient_name,
         CASE WHEN token_never_expires THEN 'Token never expires' ELSE concat('Token expires ', CAST(token_expiration AS STRING)) END, created
  FROM ${catalog}.${schema}.delta_sharing_posture
  WHERE authentication_type = 'TOKEN' AND tokens > 0 AND (token_never_expires OR token_expiration > current_timestamp() + INTERVAL 365 DAYS)
  UNION ALL
  -- CO-01 / CO-02 / CO-03 interactive compute
  SELECT 'CO-01', workspace_id, workspace_name, 'CLUSTER', concat(cluster_name, ' (', cluster_id, ')'),
         concat('Access mode ', access_mode, ', owner ', coalesce(owned_by, '?')), last_changed
  FROM ${catalog}.${schema}.compute_posture
  WHERE NOT is_uc_secured AND cluster_source IN ('UI', 'API')
  UNION ALL
  SELECT 'CO-02', workspace_id, workspace_name, 'CLUSTER', concat(cluster_name, ' (', cluster_id, ')'),
         concat('No compute policy, owner ', coalesce(owned_by, '?')), last_changed
  FROM ${catalog}.${schema}.compute_posture
  WHERE NOT has_policy AND cluster_source IN ('UI', 'API')
  UNION ALL
  SELECT 'CO-03', workspace_id, workspace_name, 'CLUSTER', concat(cluster_name, ' (', cluster_id, ')'), concat('Runtime ', dbr_version), last_changed
  FROM ${catalog}.${schema}.compute_posture
  WHERE dbr_major < 13 AND cluster_source IN ('UI', 'API')
  UNION ALL
  -- NW-01 / NW-02 network denials per workspace
  SELECT CASE WHEN direction = 'INBOUND' THEN 'NW-01' ELSE 'NW-02' END, workspace_id, max(workspace_name), 'WORKSPACE', coalesce(max(workspace_name), workspace_id),
         concat(CAST(sum(events) AS STRING), ' ', lower(direction), ' denials, top target: ', max_by(target, events)), CAST(max(event_date) AS TIMESTAMP)
  FROM ${catalog}.${schema}.network_events_daily
  WHERE event_date >= current_date() - 7 AND upper(outcome) IN ('DENY', 'DENIED', 'DROP', 'BLOCK', 'BLOCKED', 'REJECT')
  GROUP BY direction, workspace_id
  UNION ALL
  -- AU-01 / AU-02 audit & IP access list settings
  SELECT CASE WHEN setting_name = 'enableVerboseAuditLogs' THEN 'AU-01' ELSE 'AU-02' END, workspace_id, workspace_name, 'WORKSPACE_SETTING', setting_name,
         concat(setting_name, ' = ', setting_value, ' (changed by ', coalesce(last_changed_by, '?'), ')'), last_changed
  FROM ${catalog}.${schema}.workspace_config_latest
  WHERE setting_name IN ('enableVerboseAuditLogs', 'enableIpAccessLists') AND is_risky_value
)
SELECT
  f.check_id, c.category, c.category_order, c.severity, c.severity_order, c.title,
  f.workspace_id, coalesce(f.workspace_name, CASE WHEN f.workspace_id IS NULL THEN 'Metastore' ELSE f.workspace_id END) AS workspace_name,
  f.object_type, f.object_name, f.detail, f.detected_at,
  c.recommendation, c.sat_reference, c.best_practice_url, c.doc_url
FROM f
JOIN ${catalog}.${schema}.security_checks c USING (check_id)
;

CREATE TABLE IF NOT EXISTS ${catalog}.${schema}.security_findings_latest
COMMENT 'Materialised security findings, refreshed by the Security Posture job (refreshed_at). One row per failing (check_id, object) with severity, evidence (detail), recommendation and documentation links. Dashboards and Genie read this table; security_findings is the live equivalent.'
AS SELECT *, current_timestamp() AS refreshed_at FROM ${catalog}.${schema}.security_findings WHERE 1 = 0
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.check_results
COMMENT 'Result of every security check at the last refresh: status PASS (no finding) or FAIL, number of findings, affected workspaces, and the check metadata with best_practice_url / doc_url. One row per check.'
AS
SELECT
  c.check_id, c.category, c.category_order, c.severity, c.severity_order, c.severity_weight,
  c.title, c.description, c.recommendation, c.sat_reference, c.best_practice_url, c.doc_url,
  coalesce(f.findings, 0) AS findings,
  coalesce(f.workspaces, 0) AS affected_workspaces,
  CASE WHEN coalesce(f.findings, 0) = 0 THEN 'PASS' ELSE 'FAIL' END AS status,
  f.refreshed_at
FROM ${catalog}.${schema}.security_checks c
LEFT JOIN (
  SELECT check_id, count(*) AS findings, count(DISTINCT workspace_id) AS workspaces, max(refreshed_at) AS refreshed_at
  FROM ${catalog}.${schema}.security_findings_latest GROUP BY check_id
) f USING (check_id)
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.posture_score
COMMENT 'Security posture score per category and overall (category = ALL) at the last refresh. A check passes when it has no finding. score = weighted share of passing checks between 0 and 1 (HIGH = 5, MEDIUM = 3, LOW = 1); score_pct = score x 100. Also returns failing checks and findings by severity.'
AS
SELECT
  coalesce(category, 'ALL') AS category,
  coalesce(min(category_order), 0) AS category_order,
  count(*) AS checks,
  count_if(status = 'PASS') AS checks_passed,
  count_if(status = 'FAIL') AS checks_failed,
  round(sum(CASE WHEN status = 'PASS' THEN severity_weight ELSE 0 END) / sum(severity_weight), 3) AS score,
  round(100.0 * sum(CASE WHEN status = 'PASS' THEN severity_weight ELSE 0 END) / sum(severity_weight), 1) AS score_pct,
  count_if(status = 'FAIL' AND severity = 'HIGH') AS high_checks_failed,
  sum(CASE WHEN severity = 'HIGH' THEN findings ELSE 0 END) AS high_findings,
  sum(CASE WHEN severity = 'MEDIUM' THEN findings ELSE 0 END) AS medium_findings,
  sum(CASE WHEN severity = 'LOW' THEN findings ELSE 0 END) AS low_findings,
  sum(findings) AS total_findings
FROM ${catalog}.${schema}.check_results
GROUP BY ROLLUP (category)
;

CREATE TABLE IF NOT EXISTS ${catalog}.${schema}.posture_snapshots (
  snapshot_date DATE COMMENT 'Day the snapshot was taken',
  check_id STRING COMMENT 'Check identifier (see security_checks)',
  category STRING,
  severity STRING,
  title STRING,
  findings BIGINT COMMENT 'Number of findings for the check on snapshot_date'
)
COMMENT 'Daily history of findings per check, written by the Security Posture job (last run of the day wins). Used for posture trends: information_schema state has no history of its own.'
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.posture_trend
COMMENT 'Daily posture trend from posture_snapshots: overall score (0-1) and score_pct, failing checks and findings by severity per snapshot_date.'
AS
SELECT
  snapshot_date,
  round(sum(CASE WHEN findings = 0 THEN CASE severity WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 3 ELSE 1 END ELSE 0 END)
        / sum(CASE severity WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 3 ELSE 1 END), 3) AS score,
  round(100.0 * sum(CASE WHEN findings = 0 THEN CASE severity WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 3 ELSE 1 END ELSE 0 END)
        / sum(CASE severity WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 3 ELSE 1 END), 1) AS score_pct,
  count_if(findings > 0) AS checks_failed,
  sum(CASE WHEN severity = 'HIGH' THEN findings ELSE 0 END) AS high_findings,
  sum(CASE WHEN severity = 'MEDIUM' THEN findings ELSE 0 END) AS medium_findings,
  sum(CASE WHEN severity = 'LOW' THEN findings ELSE 0 END) AS low_findings
FROM ${catalog}.${schema}.posture_snapshots
GROUP BY snapshot_date
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.activity_kpis_daily
COMMENT 'Daily security activity KPIs per workspace, one row per (event_date, workspace, metric) with a readable metric_label and metric_order: sso_logins, failed_auth, ip_blocked, admin_grants, identity_changes, pats_created, pats_without_expiry, uc_grants, uc_revokes, broad_grants, acl_changes, access_denied, interactive_exports, automated_exports, secret_reads, secret_failures, policy_changes, policy_deletions, tag_changes, classification_tags_removed, risky_config_changes, sharing_changes, sharing_data_access, sharing_ip_denied, network_denials.'
AS
WITH m AS (
  SELECT event_date, workspace_id, workspace_name, 'sso_logins' AS metric, sum(events) AS value FROM ${catalog}.${schema}.auth_events_daily WHERE auth_category = 'SSO_BROWSER' GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'failed_auth' AS metric, count_if(NOT is_ip_blocked) AS value FROM ${catalog}.${schema}.failed_auth_events GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'ip_blocked' AS metric, count_if(is_ip_blocked) AS value FROM ${catalog}.${schema}.failed_auth_events GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'admin_grants' AS metric, count_if(is_privileged AND NOT is_removal) AS value FROM ${catalog}.${schema}.identity_changes GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'identity_changes' AS metric, count(*) AS value FROM ${catalog}.${schema}.identity_changes GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'pats_created' AS metric, count_if(action_name = 'generateDbToken') AS value FROM ${catalog}.${schema}.token_events GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'pats_without_expiry' AS metric, count_if(lifetime_bucket = 'No expiry') AS value FROM ${catalog}.${schema}.token_events GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'uc_grants' AS metric, count_if(change_type = 'GRANT') AS value FROM ${catalog}.${schema}.uc_permission_changes GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'uc_revokes' AS metric, count_if(change_type = 'REVOKE') AS value FROM ${catalog}.${schema}.uc_permission_changes GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'broad_grants' AS metric, count_if(change_type = 'GRANT' AND is_broad_principal) AS value FROM ${catalog}.${schema}.uc_permission_changes GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'acl_changes' AS metric, count(*) AS value FROM ${catalog}.${schema}.workspace_acl_changes GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'access_denied' AS metric, sum(attempts) AS value FROM ${catalog}.${schema}.access_denied_daily GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'interactive_exports' AS metric, sum(CASE WHEN is_interactive THEN events ELSE 0 END) AS value FROM ${catalog}.${schema}.data_export_daily GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'automated_exports' AS metric, sum(CASE WHEN is_interactive THEN 0 ELSE events END) AS value FROM ${catalog}.${schema}.data_export_daily GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'secret_reads' AS metric, sum(CASE WHEN action_name = 'getSecret' THEN events ELSE 0 END) AS value FROM ${catalog}.${schema}.secret_access_daily GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'secret_failures' AS metric, sum(failures) AS value FROM ${catalog}.${schema}.secret_access_daily GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'policy_changes' AS metric, count(*) AS value FROM ${catalog}.${schema}.policy_changes GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'policy_deletions' AS metric, count_if(is_deletion) AS value FROM ${catalog}.${schema}.policy_changes GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'tag_changes' AS metric, count(*) AS value FROM ${catalog}.${schema}.tag_changes GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'classification_tags_removed' AS metric, count_if(change_type = 'REMOVE' AND is_classification_tag) AS value FROM ${catalog}.${schema}.tag_changes GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'risky_config_changes' AS metric, count_if(is_risky_value) AS value FROM ${catalog}.${schema}.workspace_config_changes GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'sharing_changes' AS metric, sum(CASE WHEN activity_type = 'CHANGE' THEN events ELSE 0 END) AS value FROM ${catalog}.${schema}.delta_sharing_activity_daily GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'sharing_data_access' AS metric, sum(CASE WHEN activity_type = 'DATA_ACCESS' THEN events ELSE 0 END) AS value FROM ${catalog}.${schema}.delta_sharing_activity_daily GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'sharing_ip_denied' AS metric, sum(ip_denied_events) AS value FROM ${catalog}.${schema}.delta_sharing_activity_daily GROUP BY ALL
  UNION ALL SELECT event_date, workspace_id, workspace_name, 'network_denials' AS metric, sum(CASE WHEN upper(outcome) IN ('DENY', 'DENIED', 'DROP', 'BLOCK', 'BLOCKED', 'REJECT') THEN events ELSE 0 END) AS value FROM ${catalog}.${schema}.network_events_daily GROUP BY ALL
),
labels AS (
  SELECT * FROM VALUES
    ('sso_logins', 'SSO logins', 1),
    ('failed_auth', 'Failed authentications', 2),
    ('ip_blocked', 'IP access list blocks', 3),
    ('admin_grants', 'Admin rights granted', 4),
    ('identity_changes', 'Identity changes', 5),
    ('pats_created', 'PATs created', 6),
    ('pats_without_expiry', 'PATs without expiry', 7),
    ('uc_grants', 'UC grants', 8),
    ('uc_revokes', 'UC revokes', 9),
    ('broad_grants', 'Grants to all users', 10),
    ('acl_changes', 'Workspace ACL changes', 11),
    ('access_denied', 'Denied data access', 12),
    ('interactive_exports', 'Interactive exports', 13),
    ('automated_exports', 'Automated exports', 14),
    ('secret_reads', 'Secret reads', 15),
    ('secret_failures', 'Secret access failures', 16),
    ('policy_changes', 'Policy changes', 17),
    ('policy_deletions', 'Policies deleted', 18),
    ('tag_changes', 'Tag changes', 19),
    ('classification_tags_removed', 'Classification tags removed', 20),
    ('risky_config_changes', 'Risky setting changes', 21),
    ('sharing_changes', 'Delta Sharing changes', 22),
    ('sharing_data_access', 'Delta Sharing data requests', 23),
    ('sharing_ip_denied', 'Delta Sharing IP denials', 24),
    ('network_denials', 'Network denials', 25)
  AS t(metric, metric_label, metric_order)
)
SELECT m.event_date, m.workspace_id, m.workspace_name, m.metric, l.metric_label, l.metric_order, coalesce(m.value, 0) AS value
FROM m JOIN labels l USING (metric)
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.weekly_activity_kpis
COMMENT 'Security activity KPIs per ISO week (week_start = Monday) across all workspaces, one row per (week_start, metric). Use for week-over-week comparisons: the last complete week starts on date_trunc(WEEK, current_date()) - 7 days.'
AS
SELECT CAST(date_trunc('WEEK', event_date) AS DATE) AS week_start, metric, metric_label, metric_order, sum(value) AS value
FROM ${catalog}.${schema}.activity_kpis_daily
GROUP BY ALL
;
