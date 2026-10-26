-- =============================================================================
-- Security Posture — live views for near real-time monitoring (Splunk dashboards and alerts, splunk/)
-- They read system.access.audit (and the network tables) at query time: nothing is materialised, data is as fresh as
-- the system tables (audit events arrive about 10 minutes after they happen). Always filter on event_date (partition
-- pruning) and event_time. Readers only need SELECT on this schema: the views run with the owner's rights.
-- =============================================================================

CREATE OR REPLACE VIEW ${catalog}.${schema}.live_security_events
COMMENT 'LIVE feed of security-relevant events, one row per audit event, read from system.access.audit at query time (about 10 minutes behind): authentication failures and IP blocks, identity / admin changes, PAT lifecycle, IP access list changes, Unity Catalog grants and revokes, workspace object ACL and secret changes, tag changes, policy changes, Delta Sharing changes, interactive data exports and workspace setting changes. category groups them; signal is HIGH (act now, successful changes only: admin granted, PAT without expiry, high privilege granted to all users, IP access list deleted, ABAC policy deleted, open-sharing token retrieved), MEDIUM (review) or INFO. target is the object affected, detail a short description. Always filter on event_date and event_time. The live_* topic views give the same events with full detail (one row per privilege, setting, tag).'
AS
-- One scan of the audit log (a UNION of the live_* topic views would scan it once per topic). The rules mirror the
-- topic views of 20_semantic.sql: keep both in sync.
WITH e AS (
  SELECT e.*,
    CASE
      WHEN e.service_name IN ('accounts', 'workspace') AND e.status_code >= 400 AND e.action_name IN ('IpAccessDenied', 'accountIpAclsValidationFailed')
        THEN 'IP access blocked'
      WHEN e.service_name IN ('accounts', 'workspace') AND e.status_code >= 400 AND e.action_name IN (
          'tokenLogin', 'samlLogin', 'oidcTokenAuthorization', 'oidcBrowserLogin', 'jwtLogin', 'aadTokenLogin',
          'aadBrowserLogin', 'login', 'mfaLogin', 'certLogin', 'mintOAuthToken', 'mintOAuthAuthorizationCode')
        THEN 'Authentication failure'
      WHEN e.service_name = 'accounts' AND e.action_name IN ('generateDbToken', 'revokeDbToken', 'garbageCollectDbToken', 'updateDbToken', 'changeDbTokenAcl')
        THEN 'Token'
      WHEN e.service_name = 'accounts' AND e.action_name IN ('createIpAccessList', 'updateIpAccessList', 'deleteIpAccessList', 'replaceIpAccessList')
        THEN 'IP access list'
      WHEN (e.service_name = 'workspace' AND e.action_name = 'workspaceConfEdit')
        OR (e.service_name IN ('workspace', 'accounts') AND e.action_name IN ('setSetting', 'deleteSetting')
            AND coalesce(e.request_params.settingTypeName, '') NOT RLIKE 'AclsInitializedForOrg$|^backfill')
        THEN 'Workspace setting'
      WHEN (e.service_name = 'accounts' AND e.action_name IN (
              'add', 'delete', 'updateUser', 'activateUser', 'deactivateUser', 'setAdmin', 'removeAdmin',
              'createGroup', 'removeGroup', 'updateGroup', 'addPrincipalToGroup', 'addPrincipalsToGroup',
              'removePrincipalFromGroup', 'removePrincipalsFromGroup', 'changeDatabricksWorkspaceAcl',
              'changeDatabricksSqlAcl', 'accountUserResetPassword'))
        OR (e.service_name = 'workspace' AND e.action_name IN ('updatePermissionAssignment', 'deletePermissionAssignment'))
        OR e.service_name IN ('identityManagement', 'accountsAccessControl')
        OR (e.service_name = 'servicePrincipalCredentials' AND e.action_name IN ('create', 'delete'))
        THEN 'Identity & admin'
      WHEN e.service_name = 'unityCatalog' AND e.action_name = 'updatePermissions' THEN 'Unity Catalog grant'
      WHEN e.service_name = 'unityCatalog' AND e.action_name IN ('UpdateTagSecurableAssignments', 'UpdateTagSubentityAssignments') THEN 'Tag'
      WHEN (e.service_name = 'unityCatalog' AND e.action_name IN ('createPolicy', 'updatePolicy', 'deletePolicy'))
        OR (e.service_name = 'tagging' AND e.action_name IN ('createTagPolicy', 'updateTagPolicy', 'deleteTagPolicy'))
        OR (e.service_name IN ('clusterPolicies', 'serverlessPolicy', 'globalInitScripts') AND e.action_name IN ('create', 'edit', 'update', 'delete'))
        THEN 'Policy'
      WHEN e.service_name = 'unityCatalog' AND e.action_name IN (
          'createShare', 'updateShare', 'deleteShare', 'createRecipient', 'updateRecipient', 'deleteRecipient',
          'rotateRecipientToken', 'retrieveRecipientToken', 'updateSharePermissions')
        THEN 'Delta Sharing'
      WHEN e.service_name = 'secrets' THEN 'Secret scope'
      WHEN e.action_name LIKE 'change%Acl%' OR e.action_name IN ('changePermissions', 'updateMLServingPermissions') THEN 'Object ACL'
      WHEN coalesce(e.status_code, 200) < 400 AND (
           (e.service_name = 'databrickssql' AND e.action_name IN ('downloadQueryResult', 'downloadLargeQueryResult'))
        OR (e.service_name = 'notebook' AND e.action_name IN ('downloadPreviewResults', 'downloadLargeResults'))
        OR (e.service_name = 'aibiGenie' AND e.action_name IN ('genieDownloadVisualization', 'genieGenerateDownloadFullQueryResult'))
        OR (e.service_name = 'dashboards' AND e.action_name IN ('exportDashboard', 'downloadDashboardData'))
        OR (e.service_name IN ('workspace', 'filesystem', 'dbfs') AND e.action_name IN ('workspaceExport', 'createDownloadUrl', 'getTemporaryDownloadUrls')))
        THEN 'Data export'
    END AS category,
    from_json(CASE WHEN e.action_name = 'updatePermissions' THEN e.request_params.changes END,
              'array<struct<principal:string,add:array<string>,remove:array<string>>>') AS grants,
    from_json(CASE WHEN e.action_name LIKE 'UpdateTag%' THEN e.request_params.changes END,
              'struct<add_tags:array<struct<key:string,value:string>>,remove:array<string>,remove_tags:array<struct<key:string,value:string>>>') AS tags,
    try_cast(e.request_params.tokenExpirationTime AS BIGINT) AS token_expiration_ms
  FROM ${catalog}.${schema}.src_audit_security_events e
),
c AS (
  SELECT e.*,
    -- as identity_changes.is_privileged / is_removal
    (e.action_name IN ('setAdmin', 'removeAdmin', 'updateRuleSet')
     OR (e.action_name IN ('updatePermissionAssignment', 'createWorkspaceAssignment', 'updateWorkspaceAssignment',
                           'updateWorkspaceAssignmentProxy', 'createWorkspaceAssignmentProxy')
         AND upper(coalesce(e.request_params.permissions, '')) LIKE '%ADMIN%')
     OR lower(coalesce(e.request_params.targetGroupName, '')) IN ('admins', 'account admins')) AS is_privileged,
    e.action_name IN ('removeAdmin', 'removePrincipalFromGroup', 'removePrincipalsFromGroup', 'deletePermissionAssignment',
                      'deleteGroupMembershipProxy', 'removeGroup', 'delete', 'deactivateUser', 'deleteGroupProxy',
                      'deleteServicePrincipalProxy') AS is_removal,
    exists(coalesce(e.grants, array()), g -> lower(g.principal) IN ('account users', 'users', 'all account users', 'all users')
           AND size(coalesce(g.add, array())) > 0) AS grants_to_all_users,
    exists(coalesce(e.grants, array()), g -> exists(coalesce(g.add, array()),
           p -> p IN ('ALL_PRIVILEGES', 'MANAGE', 'MODIFY') OR p LIKE 'CREATE%' OR p LIKE 'EXTERNAL_USE%')) AS grants_high_privilege
  FROM e
  WHERE e.category IS NOT NULL
)
SELECT
  c.event_time, c.event_date, c.workspace_id, w.workspace_name, c.category,
  CASE
    -- a refused change (HTTP >= 400) is only INFO; refused logins are the point of the authentication categories
    WHEN c.category NOT IN ('Authentication failure', 'IP access blocked') AND coalesce(c.status_code, 200) >= 400 THEN 'INFO'
    WHEN c.category = 'Identity & admin' AND c.is_privileged AND NOT c.is_removal THEN 'HIGH'
    WHEN c.category = 'Token' AND c.action_name = 'generateDbToken' AND coalesce(c.token_expiration_ms, 0) <= 0 THEN 'HIGH'
    WHEN c.category = 'Unity Catalog grant' AND c.grants_to_all_users AND c.grants_high_privilege THEN 'HIGH'
    WHEN c.category = 'IP access list' AND c.action_name = 'deleteIpAccessList' THEN 'HIGH'
    WHEN c.category = 'Policy' AND c.action_name = 'deletePolicy' THEN 'HIGH'
    WHEN c.category = 'Delta Sharing' AND c.action_name = 'retrieveRecipientToken' THEN 'HIGH'
    WHEN c.category IN ('Authentication failure', 'IP access blocked', 'IP access list', 'Workspace setting') THEN 'MEDIUM'
    WHEN c.category = 'Identity & admin' AND c.is_privileged THEN 'MEDIUM'
    WHEN c.category = 'Token' AND c.action_name = 'generateDbToken'
         AND (c.token_expiration_ms - unix_millis(c.event_time)) / 86400000.0 > 90 THEN 'MEDIUM'
    WHEN c.category = 'Unity Catalog grant' AND (c.grants_to_all_users OR exists(coalesce(c.grants, array()),
         g -> exists(coalesce(g.add, array()), p -> p IN ('ALL_PRIVILEGES', 'MANAGE')))) THEN 'MEDIUM'
    WHEN c.category = 'Tag' AND exists(concat(coalesce(c.tags.remove, array()), transform(coalesce(c.tags.remove_tags, array()), t -> t.key)),
         k -> lower(k) LIKE 'class.%' OR lower(k) IN ('pii', 'phi', 'pci', 'sensitive', 'sensitivity', 'data_classification', 'confidentiality')) THEN 'MEDIUM'
    WHEN c.category = 'Policy' AND (c.action_name IN ('deleteTagPolicy', 'delete') OR c.service_name = 'globalInitScripts') THEN 'MEDIUM'
    WHEN c.category = 'Delta Sharing' AND c.action_name IN ('createRecipient', 'rotateRecipientToken', 'updateSharePermissions') THEN 'MEDIUM'
    WHEN c.category IN ('Object ACL', 'Secret scope') AND lower(coalesce(c.request_params.targetGroupName, c.request_params.principal, '')) IN ('users', 'account users') THEN 'MEDIUM'
    ELSE 'INFO'
  END AS signal,
  CASE WHEN c.category IN ('Authentication failure', 'IP access blocked') THEN coalesce(c.request_params.user, c.actor)
       ELSE coalesce(c.actor, c.run_by) END AS actor,
  c.service_name, c.action_name,
  coalesce(
    c.request_params.securable_full_name, c.request_params.targetUserName, c.request_params.targetGroupName,
    c.request_params.aclChangeResourceName, c.request_params.settingTypeName, c.request_params.workspaceConfKeys,
    get_json_object(c.request_params.policy_info, '$.name'), c.request_params.ipAccessListId, c.request_params.scope,
    c.request_params.notebookFullPath, c.request_params.path, c.request_params.name, c.request_params.share,
    c.request_params.principal_id, c.request_params.tokenHash, c.request_params.queryId, c.request_params.dashboard_id,
    c.request_params.space_id, c.request_params.clusterId, c.request_params.jobId) AS target,
  left(coalesce(
    c.error_message,
    CASE WHEN c.grants IS NOT NULL THEN array_join(transform(c.grants, g -> concat(g.principal,
      CASE WHEN size(coalesce(g.add, array())) > 0 THEN concat(' +', array_join(g.add, ',')) ELSE '' END,
      CASE WHEN size(coalesce(g.remove, array())) > 0 THEN concat(' -', array_join(g.remove, ',')) ELSE '' END)), '; ') END,
    CASE WHEN c.tags IS NOT NULL THEN concat_ws('; ',
      array_join(transform(coalesce(c.tags.add_tags, array()), t -> concat('+', t.key, coalesce(concat('=', t.value), ''))), ', '),
      array_join(concat(coalesce(c.tags.remove, array()), transform(coalesce(c.tags.remove_tags, array()), t -> t.key)), ', ')) END,
    CASE WHEN c.category = 'Token' AND c.action_name = 'generateDbToken' THEN
      CASE WHEN coalesce(c.token_expiration_ms, 0) <= 0 THEN 'no expiry'
           ELSE concat('lifetime ', round((c.token_expiration_ms - unix_millis(c.event_time)) / 86400000.0), ' days') END END,
    nullif(concat_ws(' ', c.request_params.workspaceConfValues, c.request_params.settingValueForAudit,
                     c.request_params.permissions, c.request_params.aclPermissionSet, c.request_params.permission), '')), 300) AS detail,
  coalesce(c.request_params.sourceIpAddress, c.source_ip_address) AS source_ip,
  c.status_code,
  c.event_id
FROM c
LEFT JOIN ${catalog}.${schema}.workspaces w ON w.workspace_id = c.workspace_id
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.live_access_denied_events
COMMENT 'LIVE denied data-access attempts in Unity Catalog and Databricks SQL (HTTP 401 / 403 or PERMISSION_DENIED), one row per event, read from system.access.audit at query time: who tried to access what, from where, and was refused. Bursts from one principal suggest probing or privilege escalation attempts. Always filter on event_date and event_time.'
AS
SELECT
  a.event_time, a.event_date, a.workspace_id, w.workspace_name,
  coalesce(a.user_identity.email, a.identity_metadata.run_by) AS principal,
  a.service_name, a.action_name,
  coalesce(a.request_params.full_name_arg, a.request_params.securable_full_name, a.request_params.table_full_name,
           a.request_params.name_arg, a.request_params.full_name, a.request_params.name) AS securable_name,
  left(a.response.error_message, 300) AS error_message,
  a.source_ip_address AS source_ip,
  a.response.status_code AS status_code
FROM system.access.audit a
LEFT JOIN ${catalog}.${schema}.workspaces w ON w.workspace_id = a.workspace_id
WHERE a.service_name IN ('unityCatalog', 'databrickssql', 'sqlPermissions')
  AND (a.response.status_code IN (401, 403) OR a.response.error_message LIKE '%PERMISSION_DENIED%')
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.live_network_denials
COMMENT 'LIVE network policy denials, one row per event, read at query time: inbound requests refused by context-based ingress / IP rules (system.access.inbound_network) and serverless egress blocked (system.access.outbound_network). direction is INBOUND or OUTBOUND; target is the request path or the destination. Empty when these Preview tables are not enabled. Always filter on event_date and event_time.'
AS
WITH n AS (
  SELECT event_time, workspace_id, 'INBOUND' AS direction, policy_outcome AS outcome, rule_label AS rule_or_reason,
         request_path AS target, source.ip AS source_ip, authenticated_as AS principal
  FROM ${source:system.access.inbound_network} AS i
  UNION ALL
  SELECT event_time, workspace_id, 'OUTBOUND', access_type, coalesce(storage_event.rejection_reason, network_source_type),
         coalesce(destination, dns_event.domain_name, storage_event.hostname), CAST(NULL AS STRING), CAST(NULL AS STRING)
  FROM ${source:system.access.outbound_network} AS o
)
SELECT n.event_time, CAST(n.event_time AS DATE) AS event_date, n.workspace_id, w.workspace_name,
       n.direction, n.outcome, n.rule_or_reason, n.target, n.source_ip, n.principal
FROM n
LEFT JOIN ${catalog}.${schema}.workspaces w ON w.workspace_id = n.workspace_id
WHERE upper(n.outcome) IN ('DENY', 'DENIED', 'DROP', 'BLOCK', 'BLOCKED', 'REJECT')
;
