-- =============================================================================
-- Security Posture — behavioural detections (Databricks Security Reference Architecture queries and alerts)
-- Rendered twice (SEMANTIC_VARIANTS in refresh.py): security_detections over the materialised hourly / daily tables
-- (dashboard, Genie, checks) and live_security_detections over the src_* views, read at query time (Splunk).
-- detection_rules holds the thresholds (created by both renderings, identical).
-- =============================================================================

CREATE OR REPLACE VIEW ${catalog}.${schema}.detection_rules
COMMENT 'Behavioural detection rules modelled on the Databricks Security Reference Architecture (SRA) queries and alerts: one row per rule with the activity of security_activity_hourly (or access_footprint_daily) it reads, the window (HOUR or DAY), the measure compared (events or distinct_objects), the threshold, severity and the SRA query it implements. Edit thresholds here.'
AS
SELECT * FROM VALUES
  ('FAILED_LOGIN_BURST', 'Repeated failed logins', 'FAILED_LOGIN', 'HOUR', 'events', 10, 'MEDIUM', 'repeated_failed_login_attempts',
   'Brute force or leaked / expired credentials: 10+ failed logins by one principal within an hour.'),
  ('IP_ACCESS_DENIED_BURST', 'Repeated IP access list failures', 'IP_ACCESS_DENIED', 'HOUR', 'events', 10, 'LOW', 'ip_access_list_failures',
   'Access attempted from an untrusted network: 10+ requests blocked by IP access lists within an hour.'),
  ('SECRET_ACCESS_BURST', 'Repeated access to secrets', 'SECRET_READ', 'HOUR', 'distinct_objects', 10, 'MEDIUM', 'repeated_access_to_secrets',
   'Credential theft: 10+ distinct secrets read by one principal within an hour.'),
  ('UC_DENIED_BURST', 'Repeated unauthorized Unity Catalog requests', 'UC_DENIED', 'HOUR', 'events', 26, 'MEDIUM', 'repeated_unauthorized_uc_requests',
   'Probing or privilege escalation: more than 25 Unity Catalog requests refused within an hour.'),
  ('UC_DATA_DENIED_BURST', 'Repeated unauthorized data access', 'UC_DATA_DENIED', 'HOUR', 'events', 16, 'MEDIUM', 'repeated_unauthorized_uc_data_requests',
   'Exfiltration attempt: more than 15 data access requests refused within an hour.'),
  ('PRIVILEGE_ESCALATION', 'Potential privilege escalation', 'PERMISSION_CHANGE', 'HOUR', 'events', 26, 'MEDIUM', 'potential_privilege_escalation',
   'More than 25 permission changes by one principal within an hour.'),
  ('DOWNLOAD_BURST', 'Data downloads burst', 'DOWNLOAD', 'HOUR', 'events', 21, 'MEDIUM', 'data_downloads_from_control_plane',
   'Possible exfiltration: more than 20 result downloads / exports by one principal within an hour.'),
  ('DESTRUCTIVE_BURST', 'Destructive activity burst', 'DESTRUCTIVE', 'DAY', 'events', 51, 'MEDIUM', 'destructive_activities',
   'Sabotage: more than 50 delete / trash operations by one principal in a day.'),
  ('READ_WRITE_BURST', 'High number of reads and writes', 'UC_DATA_READ+UC_DATA_WRITE', 'HOUR', 'distinct_objects', 21, 'LOW', 'high_number_of_read_writes',
   'Bulk copy: more than 20 securables read and more than 20 written by one principal within an hour.'),
  ('PRINT_STATEMENTS', 'Use of print statements', 'PRINT_STATEMENT', 'HOUR', 'events', 1, 'LOW', 'use_of_print_statements',
   'Commands printing data to the output (verbose audit logs): possible leakage of sensitive values into notebook results and logs.'),
  ('MULTI_WORKSPACE', 'Access to multiple workspaces', 'WORKSPACE_ACCESS', 'DAY', 'distinct_objects', 5, 'LOW', 'access_to_multiple_workspaces',
   'Lateral movement / blast radius: one principal active in 5+ workspaces in a day.')
AS t(detection_id, title, activity, time_window, measure, threshold, severity, sra_query, description)
;

CREATE OR REPLACE VIEW ${catalog}.${schema}.${live}security_detections
COMMENT '${live_note}Behavioural detections: one row per rule of detection_rules exceeded, per principal and window (hour or day), from security_activity_hourly and access_footprint_daily. window_start / window_end bound the window; events and distinct_objects are the measures, objects (up to 20) and sample the evidence, source_ips the client IPs, workspace_names the workspaces involved. severity, title, description and sra_query come from the rule.'
AS
WITH h AS (
  SELECT event_hour, event_date, workspace_id, workspace_name, principal, principal_type, activity, events, distinct_objects, objects,
         sample, source_ips
  FROM ${catalog}.${schema}.${hourly}
),
hourly AS (
  SELECT r.detection_id, h.event_date, h.event_hour AS window_start, h.event_hour + INTERVAL 1 HOUR AS window_end, h.principal,
         max(h.principal_type) AS principal_type, sum(h.events) AS events, sum(h.distinct_objects) AS distinct_objects,
         slice(array_distinct(flatten(collect_list(h.objects))), 1, 20) AS objects, max(h.sample) AS sample,
         slice(array_distinct(flatten(collect_list(h.source_ips))), 1, 10) AS source_ips,
         array_sort(collect_set(coalesce(h.workspace_name, h.workspace_id))) AS workspace_names
  FROM h JOIN ${catalog}.${schema}.detection_rules r ON r.activity = h.activity AND r.time_window = 'HOUR'
  GROUP BY ALL
  HAVING CASE max(r.measure) WHEN 'distinct_objects' THEN sum(h.distinct_objects) ELSE sum(h.events) END >= max(r.threshold)
),
daily AS (
  SELECT r.detection_id, h.event_date, CAST(h.event_date AS TIMESTAMP) AS window_start, CAST(h.event_date AS TIMESTAMP) + INTERVAL 1 DAY AS window_end,
         h.principal, max(h.principal_type) AS principal_type, sum(h.events) AS events, sum(h.distinct_objects) AS distinct_objects,
         slice(array_distinct(flatten(collect_list(h.objects))), 1, 20) AS objects, max(h.sample) AS sample,
         slice(array_distinct(flatten(collect_list(h.source_ips))), 1, 10) AS source_ips,
         array_sort(collect_set(coalesce(h.workspace_name, h.workspace_id))) AS workspace_names
  FROM h JOIN ${catalog}.${schema}.detection_rules r ON r.activity = h.activity AND r.time_window = 'DAY'
  GROUP BY ALL
  HAVING sum(h.events) >= max(r.threshold)
),
read_write AS (
  SELECT 'READ_WRITE_BURST' AS detection_id, event_date, event_hour AS window_start, event_hour + INTERVAL 1 HOUR AS window_end, principal,
         max(principal_type) AS principal_type, sum(events) AS events, sum(distinct_objects) AS distinct_objects,
         slice(array_distinct(flatten(collect_list(objects))), 1, 20) AS objects,
         concat(CAST(sum(CASE WHEN activity = 'UC_DATA_READ' THEN distinct_objects ELSE 0 END) AS STRING), ' securables read, ',
                CAST(sum(CASE WHEN activity = 'UC_DATA_WRITE' THEN distinct_objects ELSE 0 END) AS STRING), ' written') AS sample,
         slice(array_distinct(flatten(collect_list(source_ips))), 1, 10) AS source_ips,
         array_sort(collect_set(coalesce(workspace_name, workspace_id))) AS workspace_names
  FROM h WHERE activity IN ('UC_DATA_READ', 'UC_DATA_WRITE')
  GROUP BY event_date, event_hour, principal
  HAVING sum(CASE WHEN activity = 'UC_DATA_READ' THEN distinct_objects ELSE 0 END) > 20
     AND sum(CASE WHEN activity = 'UC_DATA_WRITE' THEN distinct_objects ELSE 0 END) > 20
),
multi_workspace AS (
  SELECT 'MULTI_WORKSPACE' AS detection_id, event_date, CAST(event_date AS TIMESTAMP) AS window_start,
         CAST(event_date AS TIMESTAMP) + INTERVAL 1 DAY AS window_end, principal, max(principal_type) AS principal_type,
         sum(events) AS events, count(DISTINCT workspace_id) AS distinct_objects,
         slice(array_sort(collect_set(coalesce(workspace_name, workspace_id))), 1, 20) AS objects,
         concat(CAST(count(DISTINCT workspace_id) AS STRING), ' workspaces') AS sample,
         slice(array_sort(collect_set(source_ip)), 1, 10) AS source_ips,
         slice(array_sort(collect_set(coalesce(workspace_name, workspace_id))), 1, 20) AS workspace_names
  FROM ${catalog}.${schema}.${footprint}
  WHERE workspace_id <> '0'
  GROUP BY event_date, principal
  HAVING count(DISTINCT workspace_id) >= (SELECT threshold FROM ${catalog}.${schema}.detection_rules WHERE detection_id = 'MULTI_WORKSPACE')
),
d AS (
  SELECT * FROM hourly UNION ALL SELECT * FROM daily UNION ALL SELECT * FROM read_write UNION ALL SELECT * FROM multi_workspace
)
SELECT d.detection_id, r.title, r.severity, CASE r.severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END AS severity_order,
       d.event_date, d.window_start, d.window_end, d.principal, d.principal_type, d.events, d.distinct_objects, d.objects, d.sample,
       d.source_ips, d.workspace_names, array_join(d.workspace_names, ', ') AS workspaces, r.threshold, r.measure, r.description, r.sra_query
FROM d JOIN ${catalog}.${schema}.detection_rules r USING (detection_id)
;
