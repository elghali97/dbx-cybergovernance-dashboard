-- =============================================================================
-- Security Posture — semantic views over the materialised audit_security_events table
-- One view per security topic; every view exposes workspace_id + workspace_name and event_date.
-- =============================================================================

CREATE OR REPLACE VIEW ${catalog}.${schema}.failed_auth_events
COMMENT 'Individual failed authentication attempts at account and workspace level (status >= 400): IP access list denials, invalid / expired tokens, failed logins. One row per event with principal, source IP and error message.'
AS
SELECT
  e.event_time, e.event_date, e.workspace_id, w.workspace_name,
  coalesce(e.request_params.user, e.actor) AS principal,
  e.service_name, e.action_name,
  e.action_name IN ('IpAccessDenied', 'accountIpAclsValidationFailed') AS is_ip_blocked,
  coalesce(e.request_params.sourceIpAddress, e.source_ip_address) AS source_ip,
  e.request_params.path AS request_path,
  e.status_code, e.error_message, e.user_agent
FROM ${catalog}.${schema}.audit_security_events e
LEFT JOIN ${catalog}.${schema}.workspaces w ON w.workspace_id = e.workspace_id
WHERE e.service_name IN ('accounts', 'workspace')
  AND e.status_code >= 400
  AND e.action_name IN (
    'tokenLogin', 'samlLogin', 'oidcTokenAuthorization', 'oidcBrowserLogin', 'jwtLogin',
    'aadTokenLogin', 'aadBrowserLogin', 'login', 'mfaLogin', 'certLogin', 'mintOAuthToken',
    'mintOAuthAuthorizationCode', 'IpAccessDenied', 'accountIpAclsValidationFailed')
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.identity_changes
COMMENT 'Changes to users, groups, service principals, admin rights and workspace assignments (SCIM, admin console, account console). is_privileged = TRUE for admin grants / removals, admin-group membership changes and account role changes. target is the user / group / service principal affected; actor is who made the change.'
AS
SELECT
  e.event_time, e.event_date, e.workspace_id, w.workspace_name,
  e.actor,
  e.service_name, e.action_name,
  coalesce(
    e.request_params.targetUserName, e.request_params.targetGroupName, e.request_params.principal_id,
    e.request_params.targetUserId, e.request_params.target_user_id, e.request_params.principal) AS target,
  e.request_params.targetGroupName AS group_name,
  e.request_params.permissions AS assigned_permissions,
  e.request_params.endpoint AS change_channel,
  (
    e.action_name IN ('setAdmin', 'removeAdmin', 'updateRuleSet')
    OR (e.action_name IN ('updatePermissionAssignment', 'createWorkspaceAssignment', 'updateWorkspaceAssignment',
                          'updateWorkspaceAssignmentProxy', 'createWorkspaceAssignmentProxy')
        AND upper(coalesce(e.request_params.permissions, '')) LIKE '%ADMIN%')
    OR lower(coalesce(e.request_params.targetGroupName, '')) IN ('admins', 'account admins')
  ) AS is_privileged,
  e.action_name IN ('removeAdmin', 'removePrincipalFromGroup', 'removePrincipalsFromGroup', 'deletePermissionAssignment',
                    'deleteGroupMembershipProxy', 'removeGroup', 'delete', 'deactivateUser', 'deleteGroupProxy',
                    'deleteServicePrincipalProxy') AS is_removal,
  e.status_code,
  to_json(e.request_params) AS request_details
FROM ${catalog}.${schema}.audit_security_events e
LEFT JOIN ${catalog}.${schema}.workspaces w ON w.workspace_id = e.workspace_id
WHERE (e.service_name = 'accounts' AND e.action_name IN (
          'add', 'delete', 'updateUser', 'activateUser', 'deactivateUser', 'setAdmin', 'removeAdmin',
          'createGroup', 'removeGroup', 'updateGroup', 'addPrincipalToGroup', 'addPrincipalsToGroup',
          'removePrincipalFromGroup', 'removePrincipalsFromGroup', 'changeDatabricksWorkspaceAcl',
          'changeDatabricksSqlAcl', 'accountUserResetPassword'))
   OR (e.service_name = 'workspace' AND e.action_name IN ('updatePermissionAssignment', 'deletePermissionAssignment'))
   OR e.service_name IN ('identityManagement', 'accountsAccessControl')
   OR (e.service_name = 'servicePrincipalCredentials' AND e.action_name IN ('create', 'delete'))
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.token_events
COMMENT 'Personal access token (PAT) lifecycle: creation, revocation and expiry clean-up. lifetime_days is NULL when the token was created without an expiry (SAT high-severity finding). lifetime_bucket groups created tokens (No expiry / > 90 days / <= 90 days). token_scopes is set for scoped PATs.'
AS
WITH t AS (
  SELECT
    e.event_time, e.event_date, e.workspace_id, w.workspace_name,
    e.actor, e.action_name,
    e.request_params.tokenHash AS token_hash,
    e.request_params.tokenScopes AS token_scopes,
    try_cast(e.request_params.tokenExpirationTime AS BIGINT) AS expiration_ms,
    e.status_code
  FROM ${catalog}.${schema}.audit_security_events e
  LEFT JOIN ${catalog}.${schema}.workspaces w ON w.workspace_id = e.workspace_id
  WHERE e.service_name = 'accounts'
    AND e.action_name IN ('generateDbToken', 'revokeDbToken', 'garbageCollectDbToken', 'updateDbToken', 'changeDbTokenAcl')
)
SELECT
  event_time, event_date, workspace_id, workspace_name, actor, action_name, token_hash, token_scopes,
  CASE WHEN expiration_ms > 0 THEN timestamp_millis(expiration_ms) END AS expires_at,
  CASE WHEN expiration_ms > 0 THEN round((expiration_ms - unix_millis(event_time)) / 86400000.0, 1) END AS lifetime_days,
  CASE WHEN action_name <> 'generateDbToken' THEN NULL
       WHEN coalesce(expiration_ms, 0) <= 0 THEN 'No expiry'
       WHEN (expiration_ms - unix_millis(event_time)) / 86400000.0 > 90 THEN '> 90 days'
       ELSE '<= 90 days' END AS lifetime_bucket,
  status_code
FROM t
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.ip_access_list_changes
COMMENT 'Changes to workspace and account IP access lists (create / update / delete / replace).'
AS
SELECT
  e.event_time, e.event_date, e.workspace_id, w.workspace_name, e.actor, e.action_name,
  e.request_params.ipAccessListId AS ip_access_list_id, e.status_code,
  to_json(e.request_params) AS request_details
FROM ${catalog}.${schema}.audit_security_events e
LEFT JOIN ${catalog}.${schema}.workspaces w ON w.workspace_id = e.workspace_id
WHERE e.service_name = 'accounts'
  AND e.action_name IN ('createIpAccessList', 'updateIpAccessList', 'deleteIpAccessList', 'replaceIpAccessList')
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.uc_permission_changes
COMMENT 'Every Unity Catalog GRANT / REVOKE (unityCatalog.updatePermissions) exploded to one row per principal and privilege. change_type is GRANT or REVOKE; actor is who made the change; is_broad_principal flags grants to all users (account users / users).'
AS
WITH p AS (
  SELECT
    e.event_time, e.event_date, e.workspace_id, w.workspace_name, e.actor,
    upper(e.request_params.securable_type) AS securable_type,
    e.request_params.securable_full_name AS securable_name,
    e.status_code,
    from_json(e.request_params.changes, 'array<struct<principal:string,add:array<string>,remove:array<string>>>') AS changes
  FROM ${catalog}.${schema}.audit_security_events e
  LEFT JOIN ${catalog}.${schema}.workspaces w ON w.workspace_id = e.workspace_id
  WHERE e.service_name = 'unityCatalog' AND e.action_name = 'updatePermissions'
),
c AS (
  SELECT p.* EXCEPT (changes), ch.principal, ch.add, ch.remove
  FROM p LATERAL VIEW explode(changes) x AS ch
),
x AS (
  SELECT c.* EXCEPT (add, remove), 'GRANT' AS change_type, priv AS privilege FROM c LATERAL VIEW explode(coalesce(add, array())) t AS priv
  UNION ALL
  SELECT c.* EXCEPT (add, remove), 'REVOKE', priv FROM c LATERAL VIEW explode(coalesce(remove, array())) t AS priv
)
SELECT
  event_time, event_date, workspace_id, workspace_name, actor, securable_type, securable_name,
  split_part(securable_name, '.', 1) AS catalog_name,
  principal, change_type, privilege, status_code,
  lower(principal) IN ('account users', 'users', 'all account users', 'all users') AS is_broad_principal
FROM x
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.workspace_acl_changes
COMMENT 'Permission (ACL) changes on workspace objects: notebooks / folders / dashboards / Genie agents, clusters, jobs, SQL warehouses, cluster policies, instance pools, secret scopes, serving endpoints, apps, models, tokens and instance profiles. object_type is derived from the audit event; target_principal is the user / group / service principal whose access changed when available.'
AS
SELECT
  e.event_time, e.event_date, e.workspace_id, w.workspace_name, e.actor,
  e.service_name, e.action_name,
  CASE e.action_name
    WHEN 'changeWorkspaceAcl' THEN split_part(e.request_params.aclChangeResourceName, '/', 1)
    WHEN 'changeClusterAcl' THEN 'cluster'
    WHEN 'changeJobAcl' THEN 'job'
    WHEN 'changeClusterPolicyAcl' THEN 'cluster_policy'
    WHEN 'changeEndpointAcls' THEN 'sql_warehouse'
    WHEN 'changePermissions' THEN 'sql_object'
    WHEN 'changeInstancePoolAcl' THEN 'instance_pool'
    WHEN 'putAcl' THEN 'secret_scope'
    WHEN 'deleteAcl' THEN 'secret_scope'
    WHEN 'changeInferenceEndpointAcl' THEN 'serving_endpoint'
    WHEN 'updateMLServingPermissions' THEN 'serving_endpoint'
    WHEN 'changeAppsAcl' THEN 'app'
    WHEN 'changeAppSpacesAcl' THEN 'app_space'
    WHEN 'changeRegisteredModelAcl' THEN 'registered_model'
    WHEN 'changeIamRoleAcl' THEN 'instance_profile'
    WHEN 'changeDbTokenAcl' THEN 'token'
    ELSE e.service_name
  END AS object_type,
  coalesce(e.request_params.aclChangeResourceName, e.request_params.resourceId, e.request_params.scope,
           e.request_params.clusterId, e.request_params.jobId, e.request_params.endpointId, e.request_params.policyId) AS object_id,
  coalesce(e.request_params.targetUserName, e.request_params.targetGroupName, e.request_params.principal,
           e.request_params.targetUserId, e.request_params.targetServicePrincipalName) AS target_principal,
  coalesce(e.request_params.aclPermissionSet, e.request_params.permission) AS permission,
  lower(coalesce(e.request_params.targetGroupName, e.request_params.principal, '')) IN ('users', 'account users') AS is_broad_principal,
  e.status_code,
  to_json(e.request_params) AS request_details
FROM ${catalog}.${schema}.audit_security_events e
LEFT JOIN ${catalog}.${schema}.workspaces w ON w.workspace_id = e.workspace_id
WHERE e.action_name IN ('changeWorkspaceAcl', 'changeClusterAcl', 'changeJobAcl', 'changeClusterPolicyAcl', 'changeEndpointAcls',
                        'changePermissions', 'changeInstancePoolAcl', 'changeInferenceEndpointAcl', 'changeAppsAcl',
                        'changeAppSpacesAcl', 'changeRegisteredModelAcl', 'changeIamRoleAcl', 'changeDbTokenAcl',
                        'updateMLServingPermissions')
   OR (e.service_name = 'secrets' AND e.action_name IN ('putAcl', 'deleteAcl'))
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.tag_changes
COMMENT 'History of tag assignment changes on securables and columns (ADD / REMOVE), from Unity Catalog tag assignment audit events. One row per tag added or removed. is_classification_tag flags class.* / PII / sensitivity tags.'
AS
WITH e AS (
  SELECT a.event_time, a.event_date, a.workspace_id, w.workspace_name, a.actor,
         upper(a.request_params.securable_type) AS securable_type,
         a.request_params.securable_full_name AS securable_name,
         a.request_params.subentity_name AS column_name,
         from_json(a.request_params.changes, 'struct<add_tags:array<struct<key:string,value:string>>,remove:array<string>,remove_tags:array<struct<key:string,value:string>>>') AS ch,
         a.status_code
  FROM ${catalog}.${schema}.audit_security_events a
  LEFT JOIN ${catalog}.${schema}.workspaces w ON w.workspace_id = a.workspace_id
  WHERE a.service_name = 'unityCatalog' AND a.action_name IN ('UpdateTagSecurableAssignments', 'UpdateTagSubentityAssignments')
),
x AS (
  SELECT e.* EXCEPT (ch), 'ADD' AS change_type, t.key AS tag_name, t.value AS tag_value
  FROM e LATERAL VIEW explode(coalesce(ch.add_tags, array())) l AS t
  UNION ALL
  SELECT e.* EXCEPT (ch), 'REMOVE', k, CAST(NULL AS STRING)
  FROM e LATERAL VIEW explode(coalesce(ch.remove, array())) l AS k
  UNION ALL
  SELECT e.* EXCEPT (ch), 'REMOVE', t.key, t.value
  FROM e LATERAL VIEW explode(coalesce(ch.remove_tags, array())) l AS t
)
SELECT *,
  lower(tag_name) LIKE 'class.%' OR lower(tag_name) IN ('pii', 'phi', 'pci', 'sensitive', 'sensitivity', 'data_classification', 'confidentiality') AS is_classification_tag
FROM x
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.policy_changes
COMMENT 'Changes to security policies: ABAC policies (Unity Catalog create / update / deletePolicy), governed tag policies, cluster policies, serverless policies and global init scripts. policy_kind identifies which; is_deletion flags deletions.'
AS
SELECT
  e.event_time, e.event_date, e.workspace_id, w.workspace_name, e.actor,
  CASE
    WHEN e.service_name = 'unityCatalog' THEN 'ABAC_POLICY'
    WHEN e.service_name = 'tagging' THEN 'GOVERNED_TAG_POLICY'
    WHEN e.service_name = 'clusterPolicies' THEN 'CLUSTER_POLICY'
    WHEN e.service_name = 'serverlessPolicy' THEN 'SERVERLESS_POLICY'
    WHEN e.service_name = 'globalInitScripts' THEN 'GLOBAL_INIT_SCRIPT'
  END AS policy_kind,
  e.action_name,
  e.action_name IN ('deletePolicy', 'deleteTagPolicy', 'delete') AS is_deletion,
  coalesce(get_json_object(e.request_params.policy_info, '$.name'), e.request_params.name, e.request_params.policy_id,
           e.request_params.tag_key, e.request_params.key, e.request_params.policyId, e.request_params.script_id) AS policy_name,
  coalesce(get_json_object(e.request_params.policy_info, '$.policy_type'), e.request_params.policy_type) AS policy_type,
  coalesce(get_json_object(e.request_params.policy_info, '$.on_securable_fullname'), e.request_params.on_securable_fullname) AS scope_name,
  e.status_code,
  to_json(e.request_params) AS request_details
FROM ${catalog}.${schema}.audit_security_events e
LEFT JOIN ${catalog}.${schema}.workspaces w ON w.workspace_id = e.workspace_id
WHERE (e.service_name = 'unityCatalog' AND e.action_name IN ('createPolicy', 'updatePolicy', 'deletePolicy'))
   OR (e.service_name = 'tagging' AND e.action_name IN ('createTagPolicy', 'updateTagPolicy', 'deleteTagPolicy'))
   OR (e.service_name IN ('clusterPolicies', 'serverlessPolicy', 'globalInitScripts') AND e.action_name IN ('create', 'edit', 'update', 'delete'))
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.data_export_events
COMMENT 'Individual interactive (human-initiated) data exports and downloads: SQL / notebook result downloads, Genie and dashboard downloads, notebook exports and file downloads from the browser. export_channel groups the source. For volumes including automation see data_export_daily.'
AS
SELECT
  e.event_time, e.event_date, e.workspace_id, w.workspace_name,
  coalesce(e.actor, e.run_by) AS principal,
  e.service_name, e.action_name,
  CASE
    WHEN e.service_name = 'databrickssql' THEN 'SQL_RESULT_DOWNLOAD'
    WHEN e.service_name = 'notebook' THEN 'NOTEBOOK_RESULT_DOWNLOAD'
    WHEN e.service_name = 'workspace' THEN 'WORKSPACE_EXPORT'
    WHEN e.service_name = 'aibiGenie' THEN 'GENIE_DOWNLOAD'
    WHEN e.service_name = 'dashboards' THEN 'DASHBOARD_EXPORT'
    ELSE 'FILE_DOWNLOAD'
  END AS export_channel,
  coalesce(e.request_params.notebookFullPath, e.request_params.path, e.request_params.queryId, e.request_params.queryResultId,
           e.request_params.dashboard_id, e.request_params.space_id, e.request_params.notebookId) AS object_ref,
  coalesce(e.request_params.workspaceExportFormat, e.request_params.fileType, e.request_params.format) AS export_format,
  e.source_ip_address AS source_ip,
  e.status_code
FROM ${catalog}.${schema}.audit_security_events e
LEFT JOIN ${catalog}.${schema}.workspaces w ON w.workspace_id = e.workspace_id
WHERE coalesce(e.status_code, 200) < 400
  AND ((e.service_name = 'databrickssql' AND e.action_name IN ('downloadQueryResult', 'downloadLargeQueryResult'))
    OR (e.service_name = 'notebook' AND e.action_name IN ('downloadPreviewResults', 'downloadLargeResults'))
    OR (e.service_name = 'aibiGenie' AND e.action_name IN ('genieDownloadVisualization', 'genieGenerateDownloadFullQueryResult'))
    OR (e.service_name = 'dashboards' AND e.action_name IN ('exportDashboard', 'downloadDashboardData'))
    OR (e.service_name = 'workspace' AND e.action_name = 'workspaceExport')
    OR (e.service_name = 'filesystem' AND e.action_name = 'createDownloadUrl')
    OR (e.service_name = 'dbfs' AND e.action_name = 'getTemporaryDownloadUrls'))
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.workspace_config_changes
COMMENT 'Workspace and account security setting changes (workspaceConfEdit and settings API), one row per setting changed. is_security_relevant flags settings that matter for security (IP access lists, PAT tokens and lifetime, downloads / exports, DBFS browser, web terminal, verbose audit logs, user isolation ...). is_risky_value flags a change towards a less secure value.'
AS
WITH conf AS (
  SELECT e.event_time, e.event_date, e.workspace_id, e.actor, 'workspaceConf' AS source,
         k.col AS setting_name, element_at(split(e.request_params.workspaceConfValues, ','), k.pos + 1) AS setting_value,
         e.status_code
  FROM ${catalog}.${schema}.audit_security_events e
  LATERAL VIEW posexplode(split(e.request_params.workspaceConfKeys, ',')) k AS pos, col
  WHERE e.service_name = 'workspace' AND e.action_name = 'workspaceConfEdit'
  UNION ALL
  SELECT e.event_time, e.event_date, e.workspace_id, e.actor, 'settingsApi',
         coalesce(nullif(e.request_params.settingTypeName, ''), e.request_params.settingName),
         CASE WHEN e.action_name = 'deleteSetting' THEN '<deleted>' ELSE regexp_replace(e.request_params.settingValueForAudit, '"', '') END,
         e.status_code
  FROM ${catalog}.${schema}.audit_security_events e
  WHERE e.service_name IN ('workspace', 'accounts') AND e.action_name IN ('setSetting', 'deleteSetting')
    AND coalesce(e.request_params.settingTypeName, '') NOT RLIKE 'AclsInitializedForOrg$|^backfill'
)
SELECT c.event_time, c.event_date, c.workspace_id, w.workspace_name, c.actor, c.source, c.setting_name, c.setting_value, c.status_code,
  c.setting_name IN ('enableIpAccessLists', 'enableTokensConfig', 'maxTokenLifetimeDays', 'enableExportNotebook',
                     'enableNotebookTableClipboard', 'enableResultsDownloading', 'enableDbfsFileBrowser', 'enableWebTerminal',
                     'enableVerboseAuditLogs', 'enforceUserIsolation', 'enableDeprecatedGlobalInitScripts', 'enableUploadDataUis',
                     'storeInteractiveNotebookResultsInCustomerAccount', 'enableJobViewAcls', 'enforceClusterViewAcls',
                     'enableWorkspaceFilesystem', 'enableDeprecatedClusterNamedInitScripts', 'mlflowRunArtifactDownloadEnabled',
                     'enableFileStoreEndpoint', 'enableEnforceImdsV2', 'sqlResultsDownloading', 'restrictWorkspaceAdmins',
                     'disableLegacyDbfs', 'disableLegacyAccess', 'enhancedSecurityMonitoring', 'complianceSecurityProfile',
                     'automaticClusterUpdate', 'personalCompute')
    OR lower(c.setting_name) RLIKE 'token|ipaccess|download|export|audit|security|restrict|legacy|isolation|terminal' AS is_security_relevant,
  CASE
    WHEN c.setting_name IN ('enableIpAccessLists', 'enableVerboseAuditLogs', 'enforceUserIsolation', 'enableJobViewAcls',
                            'enforceClusterViewAcls', 'storeInteractiveNotebookResultsInCustomerAccount', 'enableEnforceImdsV2',
                            'restrictWorkspaceAdmins', 'disableLegacyDbfs', 'disableLegacyAccess', 'enhancedSecurityMonitoring',
                            'complianceSecurityProfile') THEN lower(c.setting_value) IN ('false', '<deleted>')
    WHEN c.setting_name IN ('enableExportNotebook', 'enableNotebookTableClipboard', 'enableResultsDownloading', 'enableDbfsFileBrowser',
                            'enableWebTerminal', 'enableDeprecatedGlobalInitScripts', 'enableUploadDataUis', 'enableFileStoreEndpoint',
                            'enableDeprecatedClusterNamedInitScripts', 'mlflowRunArtifactDownloadEnabled', 'sqlResultsDownloading')
      THEN lower(c.setting_value) = 'true'
    WHEN c.setting_name = 'maxTokenLifetimeDays' THEN coalesce(try_cast(c.setting_value AS INT), 0) = 0 OR try_cast(c.setting_value AS INT) > 90
    ELSE FALSE
  END AS is_risky_value
FROM conf c
LEFT JOIN ${catalog}.${schema}.workspaces w ON w.workspace_id = c.workspace_id
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.workspace_config_latest
COMMENT 'Last known value of each security setting per workspace, reconstructed from the most recent change in the audit log (within audit retention: settings never changed since then are not visible). Use for the configuration posture of each workspace.'
AS
SELECT workspace_id, workspace_name, setting_name, setting_value, event_time AS last_changed, actor AS last_changed_by,
       is_security_relevant, is_risky_value,
       CASE WHEN is_risky_value THEN 'Risky' ELSE 'OK' END AS setting_status
FROM ${catalog}.${schema}.workspace_config_changes
WHERE coalesce(status_code, 200) < 400
QUALIFY row_number() OVER (PARTITION BY workspace_id, setting_name ORDER BY event_time DESC) = 1
;
