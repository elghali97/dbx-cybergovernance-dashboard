-- =============================================================================
-- Security Posture — source views over Databricks system tables
-- Each src_<name> view defines the content of table <name>, materialised by refresh.py:
--   * state tables (Unity Catalog grants, owners, tags, policies, compute) are rebuilt every run
--   * activity tables (event_date column) are loaded incrementally (last 2 days re-processed)
-- Dashboards and Genie never read src_* views (they would scan system tables at query time).
-- refresh.py renders the catalog / schema placeholders and replaces each optional system table that is not
-- enabled or not granted (marked source:...) by an empty result with the same columns.
-- Statements are separated by a line containing only ";".
-- =============================================================================

-- ----------------------------------------------------------------------------- reference

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_workspaces
COMMENT 'Workspaces of the account (system.access.workspaces_latest). workspace_id 0 = account-level events (account console). Join on workspace_id to get workspace_name.'
AS
SELECT workspace_id, workspace_name, workspace_url, status, create_time FROM ${source:system.access.workspaces_latest} AS wl
UNION ALL
SELECT '0', 'Account console', CAST(NULL AS STRING), 'RUNNING', CAST(NULL AS TIMESTAMP)
;

-- ----------------------------------------------------------------------------- activity (incremental)

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_audit_security_events
COMMENT 'Security-relevant audit events, one row per event (from system.access.audit): identity and admin changes, token lifecycle, IP access list and workspace / account setting changes, failed authentication, Unity Catalog grants, tag assignments and ABAC policies, workspace object ACLs, cluster / serverless policies, global init scripts, Delta Sharing object changes and interactive data exports. High-volume successful activity (logins, reads, secret reads) is aggregated in the *_daily tables instead.'
AS
SELECT
  event_time, event_date, workspace_id, service_name, action_name,
  user_identity.email AS actor,
  identity_metadata.run_by AS run_by,
  source_ip_address, user_agent, request_params,
  response.status_code AS status_code,
  left(response.error_message, 1000) AS error_message,
  event_id
FROM system.access.audit
WHERE
  -- identities, admin rights, tokens, IP access lists, account settings
  (service_name = 'accounts' AND action_name IN (
      'add', 'delete', 'updateUser', 'activateUser', 'deactivateUser', 'setAdmin', 'removeAdmin',
      'createGroup', 'removeGroup', 'updateGroup', 'addPrincipalToGroup', 'addPrincipalsToGroup',
      'removePrincipalFromGroup', 'removePrincipalsFromGroup', 'changeDatabricksWorkspaceAcl',
      'changeDatabricksSqlAcl', 'accountUserResetPassword',
      'generateDbToken', 'revokeDbToken', 'garbageCollectDbToken', 'updateDbToken', 'changeDbTokenAcl',
      'createIpAccessList', 'updateIpAccessList', 'deleteIpAccessList', 'replaceIpAccessList',
      'setSetting', 'deleteSetting'))
  OR (service_name = 'workspace' AND action_name IN (
      'updatePermissionAssignment', 'deletePermissionAssignment', 'workspaceConfEdit', 'setSetting', 'deleteSetting'))
  OR service_name IN ('identityManagement', 'accountsAccessControl')
  OR (service_name = 'servicePrincipalCredentials' AND action_name IN ('create', 'delete'))
  -- failed authentication
  OR (service_name IN ('accounts', 'workspace') AND response.status_code >= 400 AND action_name IN (
      'tokenLogin', 'samlLogin', 'oidcTokenAuthorization', 'oidcBrowserLogin', 'jwtLogin', 'aadTokenLogin',
      'aadBrowserLogin', 'login', 'mfaLogin', 'certLogin', 'mintOAuthToken', 'mintOAuthAuthorizationCode',
      'IpAccessDenied', 'accountIpAclsValidationFailed'))
  -- Unity Catalog grants, tag assignments, ABAC policies, Delta Sharing objects
  OR (service_name = 'unityCatalog' AND action_name IN (
      'updatePermissions', 'UpdateTagSecurableAssignments', 'UpdateTagSubentityAssignments',
      'createPolicy', 'updatePolicy', 'deletePolicy',
      'createShare', 'updateShare', 'deleteShare', 'createRecipient', 'updateRecipient', 'deleteRecipient',
      'rotateRecipientToken', 'retrieveRecipientToken', 'updateSharePermissions'))
  OR (service_name = 'tagging' AND action_name IN ('createTagPolicy', 'updateTagPolicy', 'deleteTagPolicy'))
  OR (service_name IN ('clusterPolicies', 'serverlessPolicy', 'globalInitScripts') AND action_name IN ('create', 'edit', 'update', 'delete'))
  -- workspace object ACLs and secret scopes
  OR action_name IN ('changeWorkspaceAcl', 'changeClusterAcl', 'changeJobAcl', 'changeClusterPolicyAcl', 'changeEndpointAcls',
                     'changePermissions', 'changeInstancePoolAcl', 'changeInferenceEndpointAcl', 'changeAppsAcl',
                     'changeAppSpacesAcl', 'changeRegisteredModelAcl', 'changeIamRoleAcl', 'updateMLServingPermissions')
  OR (service_name = 'secrets' AND action_name IN ('putAcl', 'deleteAcl', 'createScope', 'deleteScope'))
  -- interactive data exports (automation such as CLI sync is only counted in data_export_daily)
  OR (service_name = 'databrickssql' AND action_name IN ('downloadQueryResult', 'downloadLargeQueryResult'))
  OR (service_name = 'notebook' AND action_name IN ('downloadPreviewResults', 'downloadLargeResults'))
  OR (service_name = 'aibiGenie' AND action_name IN ('genieDownloadVisualization', 'genieGenerateDownloadFullQueryResult'))
  OR (service_name = 'dashboards' AND action_name IN ('exportDashboard', 'downloadDashboardData'))
  OR (user_agent LIKE 'Mozilla%' AND (
        (service_name = 'workspace' AND action_name = 'workspaceExport')
     OR (service_name = 'filesystem' AND action_name = 'createDownloadUrl')
     OR (service_name = 'dbfs' AND action_name = 'getTemporaryDownloadUrls')))
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_auth_events_daily
COMMENT 'Daily authentication activity per workspace, principal and method, aggregated from system.access.audit. auth_category is SSO_BROWSER, PAT, OAUTH, IP_ACCESS_DENIED or the raw method. principal_type is USER, SERVICE_PRINCIPAL or OTHER. events = requests, failed_events = failed attempts, distinct_source_ips / source_ips (max 50) = client IPs seen that day.'
AS
WITH auth AS (
  SELECT
    a.event_date,
    a.workspace_id,
    coalesce(a.request_params.user, a.user_identity.email) AS principal,
    CASE
      WHEN a.action_name IN ('IpAccessDenied', 'accountIpAclsValidationFailed') THEN 'IP_ACCESS_DENIED'
      WHEN a.request_params.authenticationMethod LIKE '%PAT%' THEN 'PAT'
      WHEN a.request_params.authenticationMethod LIKE 'BROWSER%' OR a.action_name IN ('samlLogin', 'aadBrowserLogin', 'oidcBrowserLogin', 'login', 'mfaLogin') THEN 'SSO_BROWSER'
      WHEN a.request_params.authenticationMethod LIKE '%OIDC%' OR a.request_params.authenticationMethod LIKE '%OAUTH%'
           OR a.action_name IN ('oidcTokenAuthorization', 'mintOAuthToken', 'aadTokenLogin', 'jwtLogin') THEN 'OAUTH'
      ELSE coalesce(a.request_params.authenticationMethod, 'OTHER')
    END AS auth_category,
    a.request_params.authenticationMethod AS auth_method,
    coalesce(a.request_params.sourceIpAddress, a.source_ip_address) AS source_ip,
    a.response.status_code >= 400 AS is_failure
  FROM system.access.audit a
  WHERE a.service_name IN ('accounts', 'workspace')
    AND a.action_name IN (
      'tokenLogin', 'samlLogin', 'oidcTokenAuthorization', 'oidcBrowserLogin', 'jwtLogin',
      'aadTokenLogin', 'aadBrowserLogin', 'login', 'mfaLogin', 'certLogin', 'mintOAuthToken',
      'IpAccessDenied', 'accountIpAclsValidationFailed')
)
SELECT
  a.event_date,
  a.workspace_id,
  w.workspace_name,
  a.principal,
  CASE
    WHEN a.principal RLIKE '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN 'SERVICE_PRINCIPAL'
    WHEN a.principal LIKE '%@%' THEN 'USER'
    ELSE 'OTHER'
  END AS principal_type,
  a.auth_category,
  a.auth_method,
  count(*) AS events,
  count_if(a.is_failure) AS failed_events,
  count(DISTINCT a.source_ip) AS distinct_source_ips,
  slice(collect_set(a.source_ip), 1, 50) AS source_ips
FROM auth a
LEFT JOIN ${catalog}.${schema}.src_workspaces w ON w.workspace_id = a.workspace_id
GROUP BY ALL
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_access_denied_daily
COMMENT 'Daily denied data-access attempts in Unity Catalog and Databricks SQL (HTTP 401/403 or PERMISSION_DENIED), per principal, action and securable: who tried to access what and was refused. Useful to spot probing / privilege escalation attempts and missing grants.'
AS
SELECT
  a.event_date,
  a.workspace_id,
  w.workspace_name,
  coalesce(a.user_identity.email, a.identity_metadata.run_by) AS principal,
  a.service_name,
  a.action_name,
  coalesce(a.request_params.full_name_arg, a.request_params.securable_full_name, a.request_params.table_full_name,
           a.request_params.name_arg, a.request_params.full_name, a.request_params.name) AS securable_name,
  left(a.response.error_message, 300) AS error_message,
  count(*) AS attempts,
  max(a.event_time) AS last_attempt
FROM system.access.audit a
LEFT JOIN ${catalog}.${schema}.src_workspaces w ON w.workspace_id = a.workspace_id
WHERE a.service_name IN ('unityCatalog', 'databrickssql', 'sqlPermissions')
  AND (a.response.status_code IN (401, 403) OR a.response.error_message LIKE '%PERMISSION_DENIED%')
GROUP BY ALL
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_secret_access_daily
COMMENT 'Daily secrets activity per principal, action and secret scope (getSecret reads, writes, scope and ACL changes) from system.access.audit. failures = denied / failed calls (missing-secret lookups excluded).'
AS
SELECT
  a.event_date,
  a.workspace_id,
  w.workspace_name,
  coalesce(a.user_identity.email, a.identity_metadata.run_by) AS principal,
  CASE WHEN coalesce(a.user_identity.email, a.identity_metadata.run_by) RLIKE '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-' THEN 'SERVICE_PRINCIPAL'
       WHEN coalesce(a.user_identity.email, a.identity_metadata.run_by) LIKE '%@%' THEN 'USER' ELSE 'OTHER' END AS principal_type,
  a.action_name,
  a.request_params.scope AS secret_scope,
  count(*) AS events,
  count_if(coalesce(a.response.status_code, 200) >= 400 AND a.response.status_code <> 3002) AS failures
FROM system.access.audit a
LEFT JOIN ${catalog}.${schema}.src_workspaces w ON w.workspace_id = a.workspace_id
WHERE a.service_name = 'secrets'
GROUP BY ALL
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_data_export_daily
COMMENT 'Daily data exports and downloads per principal and channel (SQL / notebook results, Genie, dashboards, notebook exports, file downloads), interactive and automated. client_type is BROWSER, CLI_SDK or SERVICE_OR_UNKNOWN; is_interactive = TRUE for human-initiated downloads. Individual interactive events are in data_export_events.'
AS
WITH e AS (
  SELECT
    a.event_date,
    a.workspace_id,
    coalesce(a.user_identity.email, a.identity_metadata.run_by) AS principal,
    CASE
      WHEN a.service_name = 'databrickssql' THEN 'SQL_RESULT_DOWNLOAD'
      WHEN a.service_name = 'notebook' THEN 'NOTEBOOK_RESULT_DOWNLOAD'
      WHEN a.service_name = 'workspace' THEN 'WORKSPACE_EXPORT'
      WHEN a.service_name = 'aibiGenie' THEN 'GENIE_DOWNLOAD'
      WHEN a.service_name = 'dashboards' THEN 'DASHBOARD_EXPORT'
      ELSE 'FILE_DOWNLOAD'
    END AS export_channel,
    CASE
      WHEN a.user_agent LIKE 'Mozilla%' THEN 'BROWSER'
      WHEN a.user_agent RLIKE '^(cli|databricks-sdk|databricks-cli|python-requests|node|Apache-HttpClient|databricks-sat)' THEN 'CLI_SDK'
      ELSE 'SERVICE_OR_UNKNOWN'
    END AS client_type,
    a.user_agent LIKE 'Mozilla%' OR a.service_name IN ('databrickssql', 'notebook', 'aibiGenie', 'dashboards') AS is_interactive
  FROM system.access.audit a
  WHERE coalesce(a.response.status_code, 200) < 400
    AND ((a.service_name = 'databrickssql' AND a.action_name IN ('downloadQueryResult', 'downloadLargeQueryResult'))
      OR (a.service_name = 'notebook' AND a.action_name IN ('downloadPreviewResults', 'downloadLargeResults'))
      OR (a.service_name = 'workspace' AND a.action_name = 'workspaceExport')
      OR (a.service_name = 'aibiGenie' AND a.action_name IN ('genieDownloadVisualization', 'genieGenerateDownloadFullQueryResult'))
      OR (a.service_name = 'dashboards' AND a.action_name IN ('exportDashboard', 'downloadDashboardData'))
      OR (a.service_name = 'filesystem' AND a.action_name = 'createDownloadUrl')
      OR (a.service_name = 'dbfs' AND a.action_name = 'getTemporaryDownloadUrls'))
)
SELECT e.event_date, e.workspace_id, w.workspace_name, e.principal, e.export_channel, e.client_type, e.is_interactive,
       count(*) AS events
FROM e
LEFT JOIN ${catalog}.${schema}.src_workspaces w ON w.workspace_id = e.workspace_id
GROUP BY ALL
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_delta_sharing_activity_daily
COMMENT 'Daily Delta Sharing activity. activity_type DATA_ACCESS = recipients listing / reading shared data (principal = recipient), CHANGE = share / recipient changes and token rotation (principal = actor). ip_denied_events counts requests blocked by a recipient IP access list.'
AS
SELECT
  a.event_date,
  a.workspace_id,
  w.workspace_name,
  CASE WHEN a.action_name LIKE 'deltaSharing%' THEN 'DATA_ACCESS' ELSE 'CHANGE' END AS activity_type,
  a.action_name,
  coalesce(a.request_params.recipient_name, a.user_identity.email) AS principal,
  a.request_params.recipient_authentication_type AS recipient_authentication_type,
  coalesce(a.request_params.share_name, a.request_params.share,
           CASE WHEN a.action_name LIKE '%Share%' THEN a.request_params.name_arg END) AS share_name,
  coalesce(nullif(concat_ws('.', a.request_params.schema, a.request_params.name), ''),
           CASE WHEN a.action_name LIKE '%Recipient%' THEN coalesce(a.request_params.name_arg, a.request_params.name) END) AS object_name,
  count(*) AS events,
  count_if(a.response.status_code >= 400) AS failures,
  count_if(a.request_params.is_ip_access_denied = 'true') AS ip_denied_events
FROM system.access.audit a
LEFT JOIN ${catalog}.${schema}.src_workspaces w ON w.workspace_id = a.workspace_id
WHERE a.service_name = 'unityCatalog'
  AND (a.action_name LIKE 'deltaSharing%'
       OR a.action_name IN ('createShare', 'updateShare', 'deleteShare', 'createRecipient', 'updateRecipient', 'deleteRecipient',
                            'rotateRecipientToken', 'retrieveRecipientToken', 'updateSharePermissions'))
GROUP BY ALL
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_network_events_daily
COMMENT 'Daily network policy enforcement events: inbound requests evaluated by context-based ingress / IP rules (system.access.inbound_network) and serverless egress decisions (system.access.outbound_network). direction is INBOUND or OUTBOUND; outcome is the policy decision (DENY / DROP / ALLOW / DRY_RUN ...); target is the request path or the destination.'
AS
WITH n AS (
  SELECT CAST(event_time AS DATE) AS event_date, workspace_id, 'INBOUND' AS direction, policy_outcome AS outcome,
         rule_label AS rule_or_reason, request_path AS target, source.ip AS source_ip, authenticated_as AS principal
  FROM ${source:system.access.inbound_network} AS i
  UNION ALL
  SELECT CAST(event_time AS DATE), workspace_id, 'OUTBOUND', access_type,
         coalesce(storage_event.rejection_reason, network_source_type),
         coalesce(destination, dns_event.domain_name, storage_event.hostname), CAST(NULL AS STRING), CAST(NULL AS STRING)
  FROM ${source:system.access.outbound_network} AS o
)
SELECT n.event_date, n.workspace_id, w.workspace_name, n.direction, n.outcome, n.rule_or_reason, n.target, n.source_ip, n.principal,
       count(*) AS events
FROM n
LEFT JOIN ${catalog}.${schema}.src_workspaces w ON w.workspace_id = n.workspace_id
GROUP BY ALL
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_table_access_activity
COMMENT 'Daily reads and writes of Unity Catalog tables per principal and tool, from lineage (system.access.table_lineage). access_type is READ or WRITE; entity_type is the tool (NOTEBOOK, JOB, DBSQL_QUERY, DASHBOARD, PIPELINE ...). Join with sensitive_columns / tag_assignments to audit access to sensitive data.'
AS
SELECT
  l.event_date, l.workspace_id, w.workspace_name, l.created_by AS principal, l.entity_type,
  t.table_full_name, split_part(t.table_full_name, '.', 1) AS catalog_name,
  t.access_type,
  count(*) AS access_events,
  max(l.event_time) AS last_access_time
FROM ${source:system.access.table_lineage} AS l
LEFT JOIN ${catalog}.${schema}.src_workspaces w ON w.workspace_id = l.workspace_id
LATERAL VIEW inline(array(
  named_struct('table_full_name', l.source_table_full_name, 'access_type', 'READ'),
  named_struct('table_full_name', l.target_table_full_name, 'access_type', 'WRITE'))) t
WHERE t.table_full_name IS NOT NULL
GROUP BY ALL
;

-- ----------------------------------------------------------------------------- state (rebuilt every run)

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_uc_grants
COMMENT 'Current Unity Catalog privilege grants across all securable types (metastore, catalog, schema, table/view, volume, function, external location, storage credential, credential, connection). One row per (securable, grantee, privilege). is_direct = TRUE when granted on the securable itself (not inherited). grantee_type is USER, SERVICE_PRINCIPAL or GROUP. is_broad_principal flags grants to all users (account users / users); is_high_privilege flags ALL PRIVILEGES, MANAGE, MODIFY and CREATE-type privileges.'
AS
WITH g AS (
  SELECT 'METASTORE' AS securable_type, metastore_id AS securable_name, grantee, grantor, privilege_type, is_grantable, inherited_from FROM system.information_schema.metastore_privileges
  UNION ALL SELECT 'CATALOG', catalog_name, grantee, grantor, privilege_type, is_grantable, inherited_from FROM system.information_schema.catalog_privileges
  UNION ALL SELECT 'SCHEMA', concat_ws('.', catalog_name, schema_name), grantee, grantor, privilege_type, is_grantable, inherited_from FROM system.information_schema.schema_privileges
  UNION ALL SELECT 'TABLE', concat_ws('.', table_catalog, table_schema, table_name), grantee, grantor, privilege_type, is_grantable, inherited_from FROM system.information_schema.table_privileges
  UNION ALL SELECT 'VOLUME', concat_ws('.', volume_catalog, volume_schema, volume_name), grantee, grantor, privilege_type, is_grantable, inherited_from FROM system.information_schema.volume_privileges
  UNION ALL SELECT 'FUNCTION', concat_ws('.', routine_catalog, routine_schema, routine_name), grantee, grantor, privilege_type, is_grantable, inherited_from FROM system.information_schema.routine_privileges
  UNION ALL SELECT 'EXTERNAL_LOCATION', external_location_name, grantee, grantor, privilege_type, is_grantable, inherited_from FROM system.information_schema.external_location_privileges
  UNION ALL SELECT 'STORAGE_CREDENTIAL', storage_credential_name, grantee, grantor, privilege_type, is_grantable, inherited_from FROM system.information_schema.storage_credential_privileges
  UNION ALL SELECT 'CREDENTIAL', credential_name, grantee, grantor, privilege_type, is_grantable, inherited_from FROM system.information_schema.credential_privileges
  UNION ALL SELECT 'CONNECTION', connection_name, grantee, grantor, privilege_type, is_grantable, inherited_from FROM system.information_schema.connection_privileges
)
SELECT
  securable_type,
  securable_name,
  CASE WHEN securable_type IN ('CATALOG', 'SCHEMA', 'TABLE', 'VOLUME', 'FUNCTION') THEN split_part(securable_name, '.', 1) END AS catalog_name,
  grantee,
  CASE
    WHEN grantee RLIKE '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN 'SERVICE_PRINCIPAL'
    WHEN grantee LIKE '%@%' THEN 'USER'
    ELSE 'GROUP'
  END AS grantee_type,
  lower(grantee) IN ('account users', 'users', 'all account users', 'all users') AS is_broad_principal,
  privilege_type,
  privilege_type IN ('ALL PRIVILEGES', 'MANAGE', 'MODIFY', 'CREATE EXTERNAL LOCATION', 'CREATE STORAGE CREDENTIAL',
                     'CREATE CATALOG', 'CREATE SHARE', 'CREATE RECIPIENT', 'CREATE CONNECTION', 'WRITE FILES',
                     'CREATE MANAGED STORAGE', 'EXTERNAL USE SCHEMA', 'EXTERNAL USE LOCATION') AS is_high_privilege,
  is_grantable,
  coalesce(inherited_from, 'NONE') AS inherited_from,
  coalesce(inherited_from, 'NONE') = 'NONE' AS is_direct,
  grantor
FROM g
WHERE securable_type NOT IN ('CATALOG', 'SCHEMA', 'TABLE', 'VOLUME', 'FUNCTION')
   OR split_part(securable_name, '.', 1) NOT IN ('system', '__databricks_internal')
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_securable_owners
COMMENT 'Owner of every Unity Catalog securable (catalog, schema, table/view, volume, external location, storage credential, connection, share, recipient). owner_type is USER, SERVICE_PRINCIPAL or GROUP. Best practice: production securables are owned by groups or service principals, not individuals.'
AS
WITH o AS (
  SELECT 'CATALOG' AS securable_type, catalog_name AS securable_name, catalog_owner AS owner, created, created_by FROM system.information_schema.catalogs
  UNION ALL SELECT 'SCHEMA', concat_ws('.', catalog_name, schema_name), schema_owner, created, created_by FROM system.information_schema.schemata WHERE schema_name <> 'information_schema'
  UNION ALL SELECT CASE WHEN table_type LIKE '%VIEW%' THEN 'VIEW' ELSE 'TABLE' END, concat_ws('.', table_catalog, table_schema, table_name), table_owner, created, created_by FROM system.information_schema.tables WHERE table_schema <> 'information_schema'
  UNION ALL SELECT 'VOLUME', concat_ws('.', volume_catalog, volume_schema, volume_name), volume_owner, created, created_by FROM system.information_schema.volumes
  UNION ALL SELECT 'EXTERNAL_LOCATION', external_location_name, external_location_owner, created, created_by FROM system.information_schema.external_locations
  UNION ALL SELECT 'STORAGE_CREDENTIAL', storage_credential_name, storage_credential_owner, created, created_by FROM system.information_schema.storage_credentials
  UNION ALL SELECT 'CONNECTION', connection_name, connection_owner, created, created_by FROM system.information_schema.connections
  UNION ALL SELECT 'SHARE', share_name, share_owner, created, created_by FROM system.information_schema.shares
  UNION ALL SELECT 'RECIPIENT', recipient_name, recipient_owner, created, created_by FROM system.information_schema.recipients
)
SELECT
  securable_type,
  securable_name,
  CASE WHEN securable_type IN ('CATALOG', 'SCHEMA', 'TABLE', 'VIEW', 'VOLUME') THEN split_part(securable_name, '.', 1) END AS catalog_name,
  owner,
  CASE
    WHEN owner RLIKE '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN 'SERVICE_PRINCIPAL'
    WHEN owner LIKE '%@%' THEN 'USER'
    ELSE 'GROUP'
  END AS owner_type,
  created,
  created_by
FROM o
WHERE securable_type NOT IN ('CATALOG', 'SCHEMA', 'TABLE', 'VIEW', 'VOLUME')
   OR split_part(securable_name, '.', 1) NOT IN ('system', '__databricks_internal')
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_governed_tags
COMMENT 'Governed tags (account-level tag policies) currently defined: one row per governed tag key.'
AS
SELECT tag_key, governed_tag_id, last_changed
FROM (
  SELECT tag_key, id AS governed_tag_id, change_time AS last_changed, deleted_at
  FROM ${source:system.tags.governed_tags} AS gt
  QUALIFY row_number() OVER (PARTITION BY id ORDER BY change_time DESC) = 1
)
WHERE deleted_at IS NULL
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_tag_assignments
COMMENT 'All tag assignments on Unity Catalog securables (catalog, schema, table, column, volume). One row per (securable, tag). is_governed = TRUE when the tag key is a governed tag. column_name is set only for column-level tags.'
AS
WITH t AS (
  SELECT 'CATALOG' AS securable_type, catalog_name, CAST(NULL AS STRING) AS schema_name, CAST(NULL AS STRING) AS object_name, CAST(NULL AS STRING) AS column_name, tag_name, tag_value FROM system.information_schema.catalog_tags
  UNION ALL SELECT 'SCHEMA', catalog_name, schema_name, NULL, NULL, tag_name, tag_value FROM system.information_schema.schema_tags
  UNION ALL SELECT 'TABLE', catalog_name, schema_name, table_name, NULL, tag_name, tag_value FROM system.information_schema.table_tags
  UNION ALL SELECT 'COLUMN', catalog_name, schema_name, table_name, column_name, tag_name, tag_value FROM system.information_schema.column_tags
  UNION ALL SELECT 'VOLUME', catalog_name, schema_name, volume_name, NULL, tag_name, tag_value FROM system.information_schema.volume_tags
)
SELECT
  t.securable_type,
  concat_ws('.', t.catalog_name, t.schema_name, t.object_name) AS securable_name,
  t.catalog_name, t.schema_name, t.object_name, t.column_name,
  t.tag_name, t.tag_value,
  g.tag_key IS NOT NULL AS is_governed
FROM t
LEFT JOIN (SELECT DISTINCT tag_key FROM ${catalog}.${schema}.src_governed_tags) g ON g.tag_key = t.tag_name
WHERE t.catalog_name NOT IN ('system', '__databricks_internal')
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_abac_policies
COMMENT 'Attribute-based access control (ABAC) policies currently defined: row filter and column mask policies with their scope (catalog / schema / table), target principals, exceptions, tag conditions and governed tags used.'
AS
SELECT
  policy_id, policy_name, policy_type,
  on_securable_type,
  concat_ws('.', catalog_name, schema_name, securable_name) AS scope_name,
  catalog_name, schema_name, securable_name,
  for_securable_type,
  array_join(to_principals, ', ') AS to_principals,
  array_join(except_principals, ', ') AS except_principals,
  size(except_principals) AS except_principal_count,
  when_condition,
  array_join(match_columns, ', ') AS match_columns,
  array_join(transform(governed_tags, x -> concat(x.tag_key, coalesce(concat('=', x.tag_value), ''))), ', ') AS governed_tags,
  created_by
FROM system.information_schema.abac_policy_definitions
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_fine_grained_controls
COMMENT 'Column masks and row filters applied directly on tables (non-ABAC). One row per mask / filter with the function used.'
AS
SELECT 'COLUMN_MASK' AS control_type, table_catalog AS catalog_name, table_schema AS schema_name, table_name,
       concat_ws('.', table_catalog, table_schema, table_name) AS table_full_name,
       column_name AS target, mask_name AS function_name, using_columns
FROM system.information_schema.column_masks
UNION ALL
SELECT 'ROW_FILTER', table_catalog, table_schema, table_name,
       concat_ws('.', table_catalog, table_schema, table_name),
       target_columns, filter_name, NULL
FROM system.information_schema.row_filters
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_sensitive_columns
COMMENT 'Sensitive columns detected by Databricks Data Classification (system.data_classification.results) plus columns manually tagged with a classification tag (class.* / pii / sensitivity / data_classification ...). source is AUTO_CLASSIFICATION or MANUAL_TAG. is_masked = TRUE when the column has a column mask.'
AS
WITH auto AS (
  SELECT catalog_name, schema_name, table_name, column_name, class_tag AS classification, confidence,
         latest_detected_time AS detected_at, 'AUTO_CLASSIFICATION' AS source
  FROM ${source:system.data_classification.results} AS r
  WHERE coalesce(exclusion_state, '') NOT IN ('EXCLUDED')
),
manual AS (
  SELECT catalog_name, schema_name, table_name, column_name,
         CASE WHEN tag_name LIKE 'class.%' THEN tag_name ELSE concat(tag_name, coalesce(concat('=', nullif(tag_value, '')), '')) END AS classification,
         'MANUAL' AS confidence, CAST(NULL AS TIMESTAMP) AS detected_at, 'MANUAL_TAG' AS source
  FROM system.information_schema.column_tags
  WHERE lower(tag_name) LIKE 'class.%' OR lower(tag_name) IN ('pii', 'phi', 'pci', 'sensitive', 'sensitivity', 'data_classification', 'confidentiality')
),
u AS (SELECT * FROM auto UNION ALL SELECT * FROM manual)
SELECT
  u.*,
  concat_ws('.', u.catalog_name, u.schema_name, u.table_name) AS table_full_name,
  m.mask_name IS NOT NULL AS is_masked,
  m.mask_name
FROM u
LEFT JOIN system.information_schema.column_masks m
  ON m.table_catalog = u.catalog_name AND m.table_schema = u.schema_name AND m.table_name = u.table_name AND m.column_name = u.column_name
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_table_governance_coverage
COMMENT 'One row per table / view with its governance metadata coverage: owner and owner_type, description, table- and column-level tags (and tags inherited from schema / catalog), sensitive columns, column masks, row filters and whether an ABAC policy covers it. Use for "% of tables tagged / documented / protected" KPIs and gap lists.'
AS
WITH tbl AS (
  SELECT table_catalog, table_schema, table_name, table_type, table_owner, comment, created, last_altered, data_source_format
  FROM system.information_schema.tables
  WHERE table_schema <> 'information_schema' AND table_catalog NOT IN ('system', '__databricks_internal')
),
tt AS (SELECT catalog_name, schema_name, table_name, count(*) AS n FROM system.information_schema.table_tags GROUP BY ALL),
ct AS (SELECT catalog_name, schema_name, table_name, count(*) AS n, count(DISTINCT column_name) AS cols FROM system.information_schema.column_tags GROUP BY ALL),
st AS (SELECT catalog_name, schema_name, count(*) AS n FROM system.information_schema.schema_tags GROUP BY ALL),
cat AS (SELECT catalog_name, count(*) AS n FROM system.information_schema.catalog_tags GROUP BY ALL),
cm AS (SELECT table_catalog, table_schema, table_name, count(*) AS n FROM system.information_schema.column_masks GROUP BY ALL),
rf AS (SELECT table_catalog, table_schema, table_name, count(*) AS n FROM system.information_schema.row_filters GROUP BY ALL),
abac AS (SELECT DISTINCT catalog_name, schema_name, securable_name, on_securable_type FROM system.information_schema.abac_policy_definitions),
sens AS (SELECT catalog_name, schema_name, table_name, count(DISTINCT column_name) AS n FROM ${catalog}.${schema}.src_sensitive_columns GROUP BY ALL)
SELECT
  t.table_catalog AS catalog_name, t.table_schema AS schema_name, t.table_name,
  concat_ws('.', t.table_catalog, t.table_schema, t.table_name) AS table_full_name,
  t.table_type, t.data_source_format, t.table_owner,
  CASE WHEN t.table_owner RLIKE '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-' THEN 'SERVICE_PRINCIPAL' WHEN t.table_owner LIKE '%@%' THEN 'USER' ELSE 'GROUP' END AS owner_type,
  t.created, t.last_altered,
  t.comment IS NOT NULL AND trim(t.comment) <> '' AS has_comment,
  coalesce(tt.n, 0) AS table_tag_count,
  coalesce(ct.n, 0) AS column_tag_count,
  coalesce(ct.cols, 0) AS tagged_column_count,
  coalesce(st.n, 0) + coalesce(cat.n, 0) AS inherited_tag_count,
  coalesce(tt.n, 0) + coalesce(ct.n, 0) > 0 AS is_tagged,
  coalesce(tt.n, 0) + coalesce(ct.n, 0) + coalesce(st.n, 0) + coalesce(cat.n, 0) > 0 AS is_tagged_incl_inherited,
  coalesce(sens.n, 0) AS sensitive_column_count,
  coalesce(cm.n, 0) AS column_mask_count,
  coalesce(rf.n, 0) > 0 AS has_row_filter,
  (a_cat.catalog_name IS NOT NULL OR a_sch.catalog_name IS NOT NULL OR a_tbl.catalog_name IS NOT NULL) AS has_abac_policy_in_scope
FROM tbl t
LEFT JOIN tt ON tt.catalog_name = t.table_catalog AND tt.schema_name = t.table_schema AND tt.table_name = t.table_name
LEFT JOIN ct ON ct.catalog_name = t.table_catalog AND ct.schema_name = t.table_schema AND ct.table_name = t.table_name
LEFT JOIN st ON st.catalog_name = t.table_catalog AND st.schema_name = t.table_schema
LEFT JOIN cat ON cat.catalog_name = t.table_catalog
LEFT JOIN cm ON cm.table_catalog = t.table_catalog AND cm.table_schema = t.table_schema AND cm.table_name = t.table_name
LEFT JOIN rf ON rf.table_catalog = t.table_catalog AND rf.table_schema = t.table_schema AND rf.table_name = t.table_name
LEFT JOIN sens ON sens.catalog_name = t.table_catalog AND sens.schema_name = t.table_schema AND sens.table_name = t.table_name
LEFT JOIN (SELECT DISTINCT catalog_name FROM abac WHERE on_securable_type = 'CATALOG') a_cat ON a_cat.catalog_name = t.table_catalog
LEFT JOIN (SELECT DISTINCT catalog_name, schema_name FROM abac WHERE on_securable_type = 'SCHEMA') a_sch
  ON a_sch.catalog_name = t.table_catalog AND a_sch.schema_name = t.table_schema
LEFT JOIN (SELECT DISTINCT catalog_name, schema_name, securable_name FROM abac WHERE on_securable_type = 'TABLE') a_tbl
  ON a_tbl.catalog_name = t.table_catalog AND a_tbl.schema_name = t.table_schema AND a_tbl.securable_name = t.table_name
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_delta_sharing_posture
COMMENT 'Delta Sharing exposure: one row per recipient with authentication type (TOKEN = open sharing to non-Databricks, DATABRICKS = Databricks-to-Databricks), shares granted, IP allow-list ranges and activation-token expiry. has_ip_allowlist = FALSE and token_never_expires = TRUE are risks for TOKEN recipients.'
AS
WITH grants AS (SELECT recipient_name, count(DISTINCT share_name) AS shares, array_join(collect_set(share_name), ', ') AS share_names FROM system.information_schema.share_recipient_privileges GROUP BY 1),
ips AS (SELECT recipient_name, count(*) AS ranges FROM system.information_schema.recipient_allowed_ip_ranges GROUP BY 1),
tok AS (SELECT recipient_name, max(expiration_time) AS max_expiration, count(*) AS tokens, count_if(expiration_time IS NULL) AS tokens_without_expiry FROM system.information_schema.recipient_tokens GROUP BY 1)
SELECT
  r.recipient_name, r.authentication_type, r.recipient_owner, r.cloud, r.region, r.created, r.created_by,
  coalesce(g.shares, 0) AS shares_granted, g.share_names,
  coalesce(i.ranges, 0) AS ip_allowlist_ranges,
  coalesce(i.ranges, 0) > 0 AS has_ip_allowlist,
  coalesce(t.tokens, 0) AS tokens, t.max_expiration AS token_expiration,
  r.authentication_type = 'TOKEN' AND coalesce(t.tokens_without_expiry, 0) > 0 AS token_never_expires
FROM system.information_schema.recipients r
LEFT JOIN grants g USING (recipient_name)
LEFT JOIN ips i USING (recipient_name)
LEFT JOIN tok t USING (recipient_name)
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.src_compute_posture
COMMENT 'Current (non-deleted) clusters with security attributes: access mode (data_security_mode; NONE / legacy modes are not Unity Catalog secured), cluster policy, init scripts, Databricks Runtime version, auto-termination and instance profile. is_uc_secured = FALSE means the cluster bypasses Unity Catalog fine-grained governance. cluster_source UI / API = interactive clusters.'
AS
SELECT
  c.workspace_id, w.workspace_name, c.cluster_id, c.cluster_name, c.owned_by, c.cluster_source, c.create_time, c.change_time AS last_changed,
  coalesce(c.data_security_mode, 'UNKNOWN') AS access_mode,
  coalesce(c.data_security_mode, '') IN ('USER_ISOLATION', 'SINGLE_USER', 'DATA_SECURITY_MODE_STANDARD', 'DATA_SECURITY_MODE_DEDICATED',
                                         'DATA_SECURITY_MODE_AUTO', 'STANDARD', 'DEDICATED') AS is_uc_secured,
  c.policy_id, c.policy_id IS NOT NULL AS has_policy,
  size(coalesce(c.init_scripts, array())) AS init_script_count,
  c.dbr_version,
  try_cast(regexp_extract(c.dbr_version, '^(\\d+)\\.', 1) AS INT) AS dbr_major,
  c.auto_termination_minutes,
  c.aws_attributes.instance_profile_arn AS instance_profile_arn
FROM (
  SELECT * FROM ${source:system.compute.clusters} AS cl
  QUALIFY row_number() OVER (PARTITION BY workspace_id, cluster_id ORDER BY change_time DESC) = 1
) c
LEFT JOIN ${catalog}.${schema}.src_workspaces w ON w.workspace_id = c.workspace_id
WHERE c.delete_time IS NULL
;
