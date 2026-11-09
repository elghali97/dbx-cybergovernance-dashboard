#!/usr/bin/env python3
"""Generate the Splunk app of the Security Posture bundle (splunk/databricks_security_posture).

Three Simple XML dashboards and three alerts, querying the bundle's schema through the `databricksquery` command of the
Databricks Add-on for Splunk (TA-Databricks, https://github.com/databrickslabs/splunk-integration):

  databricks_security_live.xml        near real-time activity: live_* views reading system.access.audit at query time
  databricks_security_detections.xml  one panel per SRA use case (detections, sensitive operations, IPs, data usage)
  databricks_security_posture.xml     posture score, checks and findings: tables refreshed by the bundle's job
  savedsearches.conf                  alerts on the live views (disabled until enabled in Splunk)

The committed app uses the defaults below. For a customer, generate it with their values and a ready-to-install
package:   python3 tools/build_splunk.py --account <add-on account> --schema <catalog>.<schema> --package
Each dashboard can also be pasted on its own (Dashboards > Create New Dashboard > Classic > Source): the settings are
the <init> tokens at the top of the XML.
"""
import argparse
import os
import re
import tarfile
from xml.sax.saxutils import escape

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
APP = "databricks_security_posture"
VERSION = "1.3.0"
DEFAULTS = {"account": "databricks", "schema": "security.security_posture", "warehouse_id": ""}

# Palette of the AI/BI dashboard: severity / signal colours are fixed and always shown with their label.
HIGH, MEDIUM, LOW, GOOD, INFO = "0xd03b3b", "0xec835a", "0xfab219", "0x0ca30c", "0x5c6470"
CATEGORICAL = ["0x2a78d6", "0xeb6834", "0x1baf7a", "0xeda100", "0xe87ba4", "0x008300", "0x6250d6", "0xe34948",
               "0x4fa3a5", "0xa0522d", "0x7f8c8d", "0xc71585", "0x2f4f4f"]
SIGNAL_COLORS = "{" + ",".join(f'"{k}":{v}' for k, v in (("HIGH", HIGH), ("MEDIUM", MEDIUM), ("INFO", INFO))) + "}"
SEVERITY_COLORS = "{" + ",".join(f'"{k}":{v}' for k, v in (("HIGH", HIGH), ("MEDIUM", MEDIUM), ("LOW", LOW), ("PASS", GOOD),
                                                            ("FAIL", HIGH))) + "}"
BEST_PRACTICES_URL = "https://www.databricks.com/trust/security-features/best-practices"
TOKEN = re.compile(r"\$[\w.]+(\|\w)?\$")


def short_list(array, n=3):
    """SQL: first n items of an array, then '+k more' (keeps table rows readable)."""
    return (f"concat(array_join(slice({array}, 1, {n}), ', '), "
            f"CASE WHEN size({array}) > {n} THEN concat(' +', CAST(size({array}) - {n} AS STRING), ' more') ELSE '' END)")
# Actor filter typed by the user -> SQL LIKE pattern ($actor_like$): $actor|s$ quotes it safely for SPL, then quotes and
# backslashes are removed (they would end the SQL string or the query argument), * becomes %, empty means everything.
ACTOR_SEARCH = r"""| makeresults | eval v=$actor|s$
| eval v=if(len(trim(v)) == 0, "%", replace(replace(v, "['\"\\\\]", ""), "\*", "%"))"""


def sql(text):
    """One-line SQL for the query="..." argument: no double quotes (they end the argument), no stray $ (token)."""
    text = " ".join(text.split())
    assert '"' not in text, f"double quote in SQL: {text[:80]}"
    assert "\\" not in text, f"backslash in SQL: {text[:80]}"
    assert "$" not in TOKEN.sub("", text), f"stray $ in SQL: {text[:80]}"
    return text


def dbq(query, spl=""):
    """SPL running a SQL statement through the add-on, then optional SPL."""
    return (f'| databricksquery account_name="$dbx_account$" $dbx_warehouse$ command_timeout=300 query="{sql(query)}"'
            + (f" {spl.strip()}" if spl else ""))


# ----------------------------------------------------------------------------- live dashboard
WINDOW = ("event_date >= CAST(timestamp_seconds($t_from$) AS DATE) "
          "AND event_time >= timestamp_seconds($t_from$) AND event_time < timestamp_seconds($t_to$)")


def live_filter(actor_column="actor", workspace=True):
    return (WINDOW + (" AND ('$ws$' = '*' OR workspace_name = '$ws$')" if workspace else "")
            + f" AND lower(coalesce({actor_column}, '')) LIKE lower('$actor_like$')")


LIVE_QUERIES = {
    "live_counts": f"""
        SELECT floor(unix_timestamp(event_time) / $t_span$) * $t_span$ AS bucket, category, signal,
               count(*) AS events, max(unix_timestamp(event_time)) AS last_event
        FROM $sp$.live_security_events
        WHERE {live_filter()} AND signal IN ($signals$)
        GROUP BY ALL""",
    # newest security event of the last day, ignoring the filters: how far behind the audit feed is
    "live_freshness": """
        SELECT max(unix_timestamp(event_time)) AS newest FROM $sp$.live_security_events
        WHERE event_date >= current_date() - 1 AND event_time >= current_timestamp() - INTERVAL 1 DAY""",
    "live_detections": f"""
        SELECT unix_timestamp(window_start) AS epoch, severity, title, principal, {short_list("workspace_names")} AS workspaces,
               events, distinct_objects, {short_list("objects")} AS objects, left(sample, 160) AS sample,
               {short_list("source_ips")} AS source_ips
        FROM $sp$.live_security_detections
        WHERE event_date >= CAST(timestamp_seconds($t_from$) AS DATE) AND window_end > timestamp_seconds($t_from$)
          AND window_start < timestamp_seconds($t_to$) AND detection_id <> 'PRINT_STATEMENTS'
          AND ('$ws$' = '*' OR array_contains(workspace_names, '$ws$')) AND lower(principal) LIKE lower('$actor_like$')
        ORDER BY severity_order, window_start DESC LIMIT 200""",
    "live_high": f"""
        SELECT unix_timestamp(event_time) AS epoch, workspace_name, category, actor, action_name, target, detail, source_ip
        FROM $sp$.live_security_events
        WHERE {live_filter()} AND signal = 'HIGH'
        ORDER BY event_time DESC LIMIT 200""",
    "live_events": f"""
        SELECT unix_timestamp(event_time) AS epoch, signal, category, workspace_name, actor, action_name, target, detail,
               source_ip, status_code
        FROM $sp$.live_security_events
        WHERE {live_filter()} AND signal IN ($signals$)
        ORDER BY event_time DESC LIMIT 500""",
    "live_actors": f"""
        SELECT actor, count_if(signal = 'HIGH') AS high, count_if(signal = 'MEDIUM') AS medium, count(*) AS events,
               array_join(slice(array_sort(collect_set(category)), 1, 6), ', ') AS categories,
               count(DISTINCT workspace_name) AS workspaces, max(unix_timestamp(event_time)) AS last_seen
        FROM $sp$.live_security_events
        WHERE {live_filter()} AND signal IN ($signals$) AND actor IS NOT NULL
        GROUP BY actor ORDER BY high DESC, medium DESC, events DESC LIMIT 15""",
    "live_ips": f"""
        SELECT source_ip, count(*) AS failures, count_if(category = 'IP access blocked') AS ip_blocks,
               count(DISTINCT actor) AS principals, array_join(slice(array_sort(collect_set(actor)), 1, 5), ', ') AS sample_principals,
               array_join(slice(array_sort(collect_set(detail)), 1, 3), ' | ') AS errors
        FROM $sp$.live_security_events
        WHERE {live_filter()} AND category IN ('Authentication failure', 'IP access blocked')
        GROUP BY source_ip ORDER BY failures DESC LIMIT 15""",
    "live_denied": f"""
        SELECT principal, count(*) AS attempts, count(DISTINCT securable_name) AS securables,
               array_join(slice(array_sort(collect_set(securable_name)), 1, 5), ', ') AS sample_securables,
               array_join(slice(array_sort(collect_set(action_name)), 1, 4), ', ') AS actions,
               max(unix_timestamp(event_time)) AS last_attempt
        FROM $sp$.live_access_denied_events
        WHERE {live_filter('principal')}
        GROUP BY principal ORDER BY attempts DESC LIMIT 15""",
    "live_network": f"""
        SELECT direction, target, outcome, count(*) AS denials, count(DISTINCT source_ip) AS source_ips,
               count(DISTINCT workspace_name) AS workspaces
        FROM $sp$.live_network_denials
        WHERE event_time >= timestamp_seconds($t_from$) AND event_time < timestamp_seconds($t_to$)
          AND ('$ws$' = '*' OR workspace_name = '$ws$')
        GROUP BY ALL ORDER BY denials DESC LIMIT 15""",
}

# Converts the time picker into epoch seconds for SQL ($t_from$ / $t_to$, at most 90 days back) and a chart bucket size.
TIME_SEARCH = """| makeresults | addinfo
| eval t_to=floor(if(isnum(info_max_time) AND info_max_time < now(), info_max_time, now()))
| eval t_from=floor(max(info_min_time, now() - 90 * 86400)), range=t_to - t_from
| eval t_span=case(range <= 7200, 60, range <= 43200, 300, range <= 172800, 900, range <= 691200, 3600, true(), 86400)
| eval t_span_label=case(t_span == 60, "1m", t_span == 300, "5m", t_span == 900, "15m", t_span == 3600, "1h", true(), "1d")"""


# ----------------------------------------------------------------------------- posture dashboard
POSTURE_QUERIES = {
    "posture_kpi": """
        SELECT s.score_pct, round(coalesce(t.score_pct, s.score_pct), 1) AS score_pct_7d_ago, s.checks, s.checks_failed,
               s.high_checks_failed, s.high_findings, s.medium_findings, s.low_findings, s.total_findings,
               round((unix_timestamp(current_timestamp()) - unix_timestamp(r.refreshed_at)) / 3600, 1) AS hours_since_refresh
        FROM $sp$.posture_score s
        CROSS JOIN (SELECT max(refreshed_at) AS refreshed_at FROM $sp$.security_findings_latest) r
        LEFT JOIN (SELECT score_pct FROM $sp$.posture_trend WHERE snapshot_date <= current_date() - 7
                   ORDER BY snapshot_date DESC LIMIT 1) t ON TRUE
        WHERE s.category = 'ALL'""",
    "posture_trend": """
        SELECT unix_timestamp(CAST(snapshot_date AS TIMESTAMP)) AS epoch, score_pct, high_findings, medium_findings, low_findings
        FROM $sp$.posture_trend WHERE snapshot_date > current_date() - 90 ORDER BY snapshot_date""",
    "posture_categories": """
        SELECT category, min(category_order) AS category_order,
               round(100 * sum(CASE WHEN status = 'PASS' THEN severity_weight ELSE 0 END) / sum(severity_weight), 1) AS score_pct,
               count(*) AS checks, count_if(status = 'FAIL') AS failing,
               count_if(status = 'FAIL' AND severity = 'HIGH') AS high_failing,
               count_if(status = 'FAIL' AND severity = 'MEDIUM') AS medium_failing,
               count_if(status = 'FAIL' AND severity = 'LOW') AS low_failing, sum(findings) AS findings
        FROM $sp$.check_results GROUP BY category ORDER BY category_order""",
    "posture_checks": """
        SELECT status, severity, check_id, category, title, findings, affected_workspaces, recommendation, sat_reference,
               best_practice_url, doc_url
        FROM $sp$.check_results
        WHERE ('$category$' = '*' OR category = '$category$')
        ORDER BY status = 'FAIL' DESC, severity_order, findings DESC, check_id""",
    "posture_findings": """
        SELECT severity, check_id, title, category, workspace_name, object_type, object_name, detail,
               unix_timestamp(detected_at) AS detected_epoch, recommendation, doc_url
        FROM $sp$.security_findings_latest
        WHERE ('$severity$' = '*' OR severity = '$severity$') AND ('$category$' = '*' OR category = '$category$')
        ORDER BY severity_order, check_id, detected_at DESC LIMIT 2000""",
    "posture_activity": """
        SELECT metric_label, metric_order,
               sum(CASE WHEN event_date > current_date() - 7 THEN value ELSE 0 END) AS last_7_days,
               sum(CASE WHEN event_date <= current_date() - 7 THEN value ELSE 0 END) AS previous_7_days
        FROM $sp$.activity_kpis_daily
        WHERE event_date > current_date() - 14
        GROUP BY metric_label, metric_order ORDER BY metric_order""",
}


# ----------------------------------------------------------------------------- detections dashboard
# Source switch: $src$ = "<schema>." reads the tables refreshed by the job (fast, up to 90 days), "<schema>.live_" the live
# views (audit log at query time, minutes behind, best for the last hours / days). Both have the same columns. The token
# carries the schema so that it is never empty (Simple XML treats an empty token as unset).
DAYS = ("event_date >= CAST(timestamp_seconds($t_from$) AS DATE) AND event_date <= CAST(timestamp_seconds($t_to$) AS DATE)")
DET_WS = "('$ws$' = '*' OR workspace_name = '$ws$')"
DETECTION_QUERIES = {
    "det_sensitive": f"""
        SELECT unix_timestamp(event_time) AS epoch, operation, severity, workspace_name, actor, action_name, target,
               left(detail, 200) AS detail, source_ip
        FROM $src$sensitive_operations
        WHERE {WINDOW} AND {DET_WS} AND lower(coalesce(actor, '')) LIKE lower('$actor_like$')
        ORDER BY event_time DESC LIMIT 5000""",
    "det_detections": f"""
        SELECT unix_timestamp(window_start) AS epoch, detection_id, title, severity, principal,
               {short_list("workspace_names")} AS workspaces, events, distinct_objects, {short_list("objects")} AS objects,
               left(sample, 160) AS sample, {short_list("source_ips")} AS source_ips, sra_query
        FROM $src$security_detections
        WHERE event_date >= CAST(timestamp_seconds($t_from$) AS DATE) AND window_end > timestamp_seconds($t_from$)
          AND window_start < timestamp_seconds($t_to$)
          AND ('$ws$' = '*' OR array_contains(workspace_names, '$ws$')) AND lower(principal) LIKE lower('$actor_like$')
        ORDER BY severity_order, window_start DESC LIMIT 5000""",
    "det_activity": f"""
        SELECT activity, principal, count(DISTINCT event_date) AS days, sum(events) AS events,
               {short_list("array_distinct(flatten(collect_list(objects)))", 4)} AS sample_objects,
               size(array_distinct(flatten(collect_list(objects)))) AS distinct_objects_seen,
               {short_list("array_sort(collect_set(workspace_name))")} AS workspaces,
               left(max(sample), 160) AS sample, max(unix_timestamp(event_hour)) AS last_seen
        FROM $src$security_activity_hourly
        WHERE event_date >= CAST(timestamp_seconds($t_from$) AS DATE) AND event_hour >= date_trunc('HOUR', timestamp_seconds($t_from$))
          AND event_hour < timestamp_seconds($t_to$) AND activity IN ('SECRET_READ', 'UC_DATA_DENIED', 'UC_DENIED', 'PRINT_STATEMENT')
          AND {DET_WS} AND lower(principal) LIKE lower('$actor_like$')
        GROUP BY activity, principal ORDER BY events DESC LIMIT 5000""",
    "det_ips": f"""
        SELECT source_ip, ip_range, access_level, count(DISTINCT principal) AS principals, sum(events) AS events,
               sum(data_access_events) AS data_access_events, sum(failed_events) AS failed_events,
               {short_list("array_sort(collect_set(principal))")} AS sample_principals,
               count(DISTINCT workspace_id) AS workspaces, max(unix_timestamp(CAST(event_date AS TIMESTAMP))) AS last_seen
        FROM $src$access_footprint_daily
        WHERE {DAYS} AND source_ip IS NOT NULL AND {DET_WS} AND lower(principal) LIKE lower('$actor_like$')
        GROUP BY source_ip, ip_range, access_level ORDER BY events DESC LIMIT 5000""",
    "det_workspaces": f"""
        SELECT principal, principal_type, count(DISTINCT workspace_id) AS workspaces, count(DISTINCT event_date) AS days,
               sum(events) AS events, {short_list("array_sort(collect_set(workspace_name))", 4)} AS sample_workspaces
        FROM $src$access_footprint_daily
        WHERE {DAYS} AND workspace_id <> '0' AND lower(principal) LIKE lower('$actor_like$')
        GROUP BY principal, principal_type HAVING count(DISTINCT workspace_id) > 1
        ORDER BY workspaces DESC, events DESC LIMIT 500""",
    "det_popular": f"""
        SELECT table_full_name, count(DISTINCT CASE WHEN access_type = 'READ' THEN principal END) AS readers,
               sum(CASE WHEN access_type = 'READ' THEN access_events ELSE 0 END) AS reads,
               count(DISTINCT CASE WHEN access_type = 'WRITE' THEN principal END) AS writers,
               sum(CASE WHEN access_type = 'WRITE' THEN access_events ELSE 0 END) AS writes,
               max(unix_timestamp(last_access_time)) AS last_access
        FROM $sp$.table_access_activity
        WHERE {DAYS} AND table_full_name NOT LIKE '__databricks_internal.%' AND {DET_WS}
        GROUP BY table_full_name ORDER BY reads DESC LIMIT 50""",
    "det_recipients": """
        SELECT recipient_name, shares_granted, share_names, token_expiration, recipient_owner,
               unix_timestamp(created) AS created_epoch
        FROM $sp$.delta_sharing_posture
        WHERE authentication_type = 'TOKEN' AND NOT has_ip_allowlist
        ORDER BY shares_granted DESC""",
}

# One panel per SRA use case: (sra name, title, base search, SPL post-process, fields, description)
TIME_FMT = '| eval {f}=strftime(tonumber({f}), "%Y-%m-%d %H:%M")'
SENSITIVE_FIELDS = ["time", "severity", "workspace_name", "actor", "target", "detail", "source_ip"]


def sens(operations):
    ops = " OR ".join(f'operation="{o}"' for o in operations)
    return f"| where {ops} " + TIME_FMT.format(f="epoch") + " | rename epoch as time"


def dets(rule_ids):
    ids = " OR ".join(f'detection_id="{r}"' for r in rule_ids)
    return f"| where {ids} " + TIME_FMT.format(f="epoch") + " | rename epoch as window_start"


DET_FIELDS = ["window_start", "principal", "workspaces", "events", "distinct_objects", "objects", "sample", "source_ips"]
ACT_FIELDS = ["principal", "events", "distinct_objects_seen", "sample_objects", "workspaces", "days", "last_seen"]


def act(activity):
    return f'| where activity="{activity}" ' + TIME_FMT.format(f="last_seen")


USE_CASES = [
    ("terms_of_service_changes", "Terms of Service changes", "det_sensitive", sens(["TERMS_OF_SERVICE"]), SENSITIVE_FIELDS,
     "accounts.acceptTos / sendTos (account level)."),
    ("account_settings_changes", "Account settings and account admin changes", "det_sensitive",
     sens(["ACCOUNT_SETTING", "ACCOUNT_ADMIN"]), SENSITIVE_FIELDS,
     "accounts.setSetting / deleteSetting at account level, setAccountAdmin, changeAccountOwner."),
    ("global_init_script_changes", "Global init script changes", "det_sensitive", sens(["GLOBAL_INIT_SCRIPT"]), SENSITIVE_FIELDS,
     "globalInitScripts.create / update / delete (name, enabled, script-SHA256)."),
    ("mount_point_creation", "DBFS mount point creation", "det_sensitive", sens(["DBFS_MOUNT"]), SENSITIVE_FIELDS,
     "dbfs.mount (mountPoint, source). Mounts bypass Unity Catalog."),
    ("repeated_access_to_secrets", "Repeated access to secrets", "det_detections", dets(["SECRET_ACCESS_BURST"]), DET_FIELDS,
     "10+ distinct secrets read by one principal in an hour (secrets.getSecret, scope/key)."),
    ("access_to_secrets", "Access to secrets (selected period)", "det_activity", act("SECRET_READ"), ACT_FIELDS,
     "Every principal reading secrets (secrets.getSecret): reads, secrets (scope/key) and workspaces."),
    ("access_to_multiple_workspaces", "Access to multiple workspaces", "det_workspaces", "| head 500",
     ["principal", "principal_type", "workspaces", "days", "events", "sample_workspaces"],
     "Principals active in more than one workspace (workspace = request_params.workspace_id for Unity Catalog events)."),
    ("use_of_print_statements", "Use of print statements", "det_activity", act("PRINT_STATEMENT"),
     ["principal", "events", "sample_objects", "sample", "workspaces", "last_seen"],
     "runCommand with print() in commandText: needs verbose audit logs on the workspace."),
    ("ip_addresses_used_to_access_databricks", "IP addresses used to access Databricks", "det_ips",
     "| stats sum(events) as requests sum(data_access_events) as data_access sum(failed_events) as failed max(principals) as principals "
     "values(access_level) as access first(sample_principals) as sample_principals max(last_seen) as last_seen by source_ip "
     "| sort - requests | eval last_seen=strftime(tonumber(last_seen), \"%Y-%m-%d\") | eval access=mvjoin(access, \", \")",
     ["source_ip", "access", "requests", "data_access", "failed", "principals", "sample_principals", "last_seen"],
     "Client IPs of all audit events (source_ip_address, port removed); events issued by Databricks compute carry no client IP."),
    ("ip_address_ranges_used_to_access_databricks", "IP address ranges (/24) used to access Databricks", "det_ips",
     "| stats sum(events) as requests dc(source_ip) as ips max(principals) as principals values(access_level) as access "
     "max(last_seen) as last_seen by ip_range | sort - requests | eval last_seen=strftime(tonumber(last_seen), \"%Y-%m-%d\") "
     "| eval access=mvjoin(access, \", \")",
     ["ip_range", "access", "ips", "requests", "principals", "last_seen"], "IPv4 /24 (IPv6 /48) networks of the client IPs."),
    ("repeated_unauthorized_uc_requests", "Repeated unauthorized Unity Catalog requests", "det_detections",
     dets(["UC_DENIED_BURST"]), DET_FIELDS, "More than 25 Unity Catalog requests refused (status 401 / 403) in an hour."),
    ("repeated_unauthorized_uc_data_requests", "Repeated unauthorized Unity Catalog data requests", "det_detections",
     dets(["UC_DATA_DENIED_BURST"]), DET_FIELDS,
     "More than 15 refused generateTemporaryTable/Volume/PathCredential or deltaSharingQueryTable requests in an hour."),
    ("unauthorized_uc_data_requests", "Unauthorized Unity Catalog data requests (selected period)", "det_activity",
     act("UC_DATA_DENIED"), ACT_FIELDS, "Every refused data access request (401 / 403) per principal."),
    ("delta_sharing_recipients_without_ip_acls", "Delta Sharing recipients created without IP access list", "det_sensitive",
     sens(["RECIPIENT_WITHOUT_IP_ACL"]), SENSITIVE_FIELDS,
     "unityCatalog.createRecipient / updateRecipient with authentication_type TOKEN and no ip_access_list."),
    ("delta_sharing_ip_access_list_failures", "Delta Sharing IP access list failures", "det_sensitive",
     sens(["SHARING_IP_DENIED"]), SENSITIVE_FIELDS, "deltaSharingQueryTable / QueryTableChanges with is_ip_access_denied = true."),
    ("delta_sharing_recipient_token_lifetime_change", "Delta Sharing recipient token lifetime change", "det_sensitive",
     sens(["RECIPIENT_TOKEN_LIFETIME"]), SENSITIVE_FIELDS,
     "unityCatalog.updateMetastore with delta_sharing_recipient_token_lifetime_in_seconds."),
    ("most_popular_data_products", "Most popular data products", "det_popular",
     '| eval last_access=strftime(tonumber(last_access), "%Y-%m-%d %H:%M")',
     ["table_full_name", "readers", "reads", "writers", "writes", "last_access"],
     "Reads and writes per table from lineage (system.access.table_lineage); refreshed tables only."),
    ("databricks_access_to_customer_workspaces", "Databricks support access to workspaces", "det_sensitive",
     sens(["DATABRICKS_SUPPORT_ACCESS"]), SENSITIVE_FIELDS, "databricksAccess: approver, reason and duration in the detail."),
    ("install_library_on_all_clusters", "Libraries installed on all clusters", "det_sensitive",
     sens(["LIBRARY_ON_ALL_CLUSTERS"]), SENSITIVE_FIELDS, "clusterLibraries.installLibraryOnAllClusters."),
    ("other_behavioural_detections", "Other behavioural detections", "det_detections",
     dets(["FAILED_LOGIN_BURST", "IP_ACCESS_DENIED_BURST", "PRIVILEGE_ESCALATION", "DOWNLOAD_BURST", "DESTRUCTIVE_BURST",
           "READ_WRITE_BURST", "MULTI_WORKSPACE"]),
     ["window_start", "title", "principal", "workspaces", "events", "distinct_objects", "objects", "sample"],
     "repeated_failed_login_attempts, ip_access_list_failures, potential_privilege_escalation, data_downloads_from_control_plane, "
     "destructive_activities, high_number_of_read_writes, access_to_multiple_workspaces (5+ per day)."),
    ("host_security_alerts", "Host security alerts (compliance security profile)", "det_sensitive",
     sens(["ANTIVIRUS_DETECTION", "HOST_INTRUSION_ALERT"]), SENSITIVE_FIELDS,
     "clamAVScanService-dataplane and capsule8-alerts-dataplane events (compliance security profile only)."),
]

# ----------------------------------------------------------------------------- Simple XML helpers
def opt(name, value):
    return f'<option name="{name}">{escape(str(value))}</option>'


def search(query=None, base=None, sid=None, refresh=None, extra=""):
    attrs = (f' id="{sid}"' if sid else "") + (f' base="{base}"' if base else "")
    body = f"<query><![CDATA[{query.strip()}]]></query>"
    if refresh:
        body += f"<refresh>{refresh}</refresh><refreshType>delay</refreshType>"
    return f"<search{attrs}>{body}{extra}</search>"


def single(title, base, spl, under, colors=None, ranges=None, unit=""):
    options = [opt("underLabel", under), opt("drilldown", "none"), opt("numberPrecision", "0"), opt("height", "110")]
    if colors:
        options += [opt("useColors", "1"), opt("colorBy", "value"), opt("colorMode", "block"),
                    opt("rangeColors", "[" + ",".join(f'"{c}"' for c in colors) + "]"),
                    opt("rangeValues", "[" + ",".join(str(r) for r in ranges) + "]")]
    if unit:
        options += [opt("unit", unit), opt("unitPosition", "after")]
    return f"<panel><title>{escape(title)}</title><single>{search(spl, base=base)}{''.join(options)}</single></panel>"


def chart(title, query, kind, options=(), base=None, height=300):
    o = [opt("charting.chart", kind), opt("height", height), opt("charting.legend.placement", "bottom"),
         opt("charting.seriesColors", "[" + ",".join(CATEGORICAL) + "]"), opt("charting.drilldown", "none")]
    o += [opt(k, v) for k, v in options]
    return f"<panel><title>{escape(title)}</title><chart>{search(query, base=base)}{''.join(o)}</chart></panel>"


def table(title, query, fields=None, formats="", drilldown="", count=10, base=None, description=""):
    o = [opt("count", count), opt("wrap", "true"), opt("rowNumbers", "false"),
         opt("drilldown", "cell" if drilldown else "none")]
    f = f"<fields>{escape(', '.join(fields))}</fields>" if fields else ""
    d = f"<drilldown>{drilldown}</drilldown>" if drilldown else ""
    desc = f"<description>{escape(description)}</description>" if description else ""
    return f"<panel><title>{escape(title)}</title>{desc}<table>{search(query, base=base)}{''.join(o)}{f}{formats}{d}</table></panel>"


def color_map(field, colors):
    return f'<format type="color" field="{field}"><colorPalette type="map">{colors}</colorPalette></format>'


def number_heat(field, color=HIGH):
    return (f'<format type="color" field="{field}"><colorPalette type="minMidMax" maxColor="{color.replace("0x", "#")}" '
            f'minColor="#FFFFFF"></colorPalette><scale type="minMidMax"></scale></format>')


def html(text):
    return f"<panel><html>{text}</html></panel>"


def row(*panels, depends=None):
    return f"<row{f' depends={chr(34)}{depends}{chr(34)}' if depends else ''}>{''.join(panels)}</row>"


def init_tokens(cfg):
    warehouse = f'warehouse_id="{cfg["warehouse_id"]}"' if cfg["warehouse_id"] else " "
    return ("<init>"
            "<!-- Settings: Databricks Add-on account, schema of the Security Posture bundle, optional SQL warehouse "
            "(default: the warehouse configured on the add-on account) -->"
            f'<set token="dbx_account">{escape(cfg["account"])}</set>'
            f'<set token="sp">{escape(cfg["schema"])}</set>'
            f"<set token=\"dbx_warehouse\">{escape(warehouse)}</set>"
            "</init>")


# ----------------------------------------------------------------------------- dashboards
def live_dashboard(cfg):
    q = {k: dbq(v) for k, v in LIVE_QUERIES.items()}
    refresh = "5m"
    actor_drill = ('<condition field="actor"><set token="form.actor">$click.value2$</set></condition>'
                   '<condition field="principal"><set token="form.actor">$click.value2$</set></condition>'
                   '<condition field="source_ip"><set token="form.actor">*</set></condition>'
                   '<condition field="*"></condition>')
    to_time = "| eval _time=tonumber(epoch) | fields - epoch"
    time_fmt = "| eval {f}=strftime(tonumber({f}), \"%Y-%m-%d %H:%M\")"
    fieldset = f"""
<fieldset submitButton="false" autoRun="true">
  <input type="time" token="time" searchWhenChanged="true">
    <label>Time range (max 90 days)</label>
    <default><earliest>-4h@m</earliest><latest>now</latest></default>
  </input>
  <input type="dropdown" token="ws" searchWhenChanged="true">
    <label>Workspace</label>
    <choice value="*">All workspaces</choice>
    <default>*</default>
    <fieldForLabel>workspace_name</fieldForLabel>
    <fieldForValue>workspace_name</fieldForValue>
    {search(dbq("SELECT DISTINCT workspace_name FROM $sp$.workspaces WHERE workspace_name IS NOT NULL ORDER BY 1"))}
  </input>
  <input type="multiselect" token="signals" searchWhenChanged="true">
    <label>Signal</label>
    <choice value="HIGH">HIGH</choice><choice value="MEDIUM">MEDIUM</choice><choice value="INFO">INFO</choice>
    <default>HIGH,MEDIUM,INFO</default>
    <valuePrefix>'</valuePrefix><valueSuffix>'</valueSuffix><delimiter>,</delimiter>
  </input>
  <input type="text" token="actor" searchWhenChanged="true">
    <label>Actor / principal (* wildcard)</label>
    <default>*</default>
  </input>
</fieldset>"""
    time_search, actor_search_xml = window_search(), actor_search()
    counts = search(q["live_counts"], sid="counts", refresh=refresh)
    freshness = search(q["live_freshness"], sid="freshness", refresh=refresh)
    kpis = row(
        single("Security events", "counts", "| stats count as n, sum(events) as v | fillnull value=0 v | fields v", "selected signals"),
        single("HIGH signals", "counts", '| stats count as n, sum(eval(if(signal="HIGH", events, 0))) as v | fillnull value=0 v | fields v',
               "act now", [GOOD, HIGH], [0]),
        single("Failed authentications", "counts",
               '| stats count as n, sum(eval(if(category="Authentication failure", events, 0))) as v | fillnull value=0 v | fields v', "logins / tokens refused"),
        single("IP access blocks", "counts",
               '| stats count as n, sum(eval(if(category="IP access blocked", events, 0))) as v | fillnull value=0 v | fields v', "requests from blocked IPs"),
        single("Identity & admin changes", "counts",
               '| stats count as n, sum(eval(if(category="Identity & admin", events, 0))) as v | fillnull value=0 v | fields v', "users, groups, admin rights"),
        single("Interactive exports", "counts",
               '| stats count as n, sum(eval(if(category="Data export", events, 0))) as v | fillnull value=0 v | fields v', "downloads by people"),
        single("Audit feed delay", "freshness",
               "| eval v=round((now() - tonumber(newest)) / 60) | fields v",
               "minutes since the newest audit event", [GOOD, LOW, HIGH], [30, 120], "min"),
    )
    xml = f"""<form version="1.1" theme="dark" hideEdit="false">
  <label>Databricks Security - Live activity</label>
  <description>Near real-time security activity across Databricks workspaces, read from system.access.audit when the dashboard refreshes (every {refresh}; audit events arrive about 10 minutes after they happen). Click an actor to filter on it. Source: the live_* views of the Databricks Security Posture bundle.</description>
  {init_tokens(cfg)}
  {time_search}
  {actor_search_xml}
  {counts}
  {freshness}
  {fieldset}
  {kpis}
  {row(
      chart("Security events over time by category",
            f"| eval _time=tonumber(bucket) | timechart span=$t_span_label$ sum(events) by category limit=15 useother=f",
            "column", [("charting.chart.stackMode", "stacked"), ("charting.axisTitleX.visibility", "collapsed"),
                       ("charting.axisTitleY.text", "events")], base="counts"),
      chart("Events by category and signal",
            '| stats sum(events) as events by category signal | xyseries category signal events | fillnull value=0 '
            '| table category HIGH MEDIUM INFO',
            "bar", [("charting.chart.stackMode", "stacked"), ("charting.fieldColors", SIGNAL_COLORS),
                    ("charting.axisTitleX.visibility", "collapsed"), ("charting.axisTitleY.visibility", "collapsed")],
            base="counts"))}
  {row(table("HIGH signals - act now", q["live_high"] + " " + to_time + " | eval detail=substr(detail, 1, 160)",
             ["_time", "workspace_name", "category", "actor", "action_name", "target", "detail", "source_ip"],
             drilldown=actor_drill, count=10,
             description="Admin rights granted, PAT without expiry, high privilege granted to all users, IP access list deleted, "
                         "ABAC policy deleted, open-sharing token retrieved. Ignores the signal filter."))}
  {row(table("Behavioural detections (SRA rules)", q["live_detections"] + " " + time_fmt.format(f="epoch")
             + " | rename epoch as window_start",
             ["window_start", "severity", "title", "principal", "workspaces", "events", "distinct_objects", "objects", "sample",
              "source_ips"],
             formats=color_map("severity", SEVERITY_COLORS), drilldown=actor_drill, count=8,
             description="Repeated failed logins, secret reads, refused requests, permission changes, deletions, downloads, "
                         "read / writes and access to 5+ workspaces above the detection_rules thresholds."))}
  {row(table("Latest security events", q["live_events"] + " " + to_time + " | eval detail=substr(detail, 1, 160)",
             ["_time", "signal", "category", "workspace_name", "actor", "action_name", "target", "detail", "source_ip",
              "status_code"],
             formats=color_map("signal", SIGNAL_COLORS), drilldown=actor_drill, count=15,
             description="Most recent 500 events matching the filters. Click an actor to investigate it."))}
  {row(table("Most active actors", q["live_actors"] + " " + time_fmt.format(f="last_seen"),
             ["actor", "high", "medium", "events", "categories", "workspaces", "last_seen"],
             formats=number_heat("high") + number_heat("medium", MEDIUM), drilldown=actor_drill),
       table("Failing source IPs", q["live_ips"],
             ["source_ip", "failures", "ip_blocks", "principals", "sample_principals", "errors"],
             formats=number_heat("failures")))}
  {row(table("Denied data access", q["live_denied"] + " " + time_fmt.format(f="last_attempt"),
             ["principal", "attempts", "securables", "sample_securables", "actions", "last_attempt"],
             formats=number_heat("attempts"), drilldown=actor_drill,
             description="Unity Catalog / SQL requests refused (401 / 403): bursts suggest probing or missing grants."),
       table("Network policy denials", q["live_network"],
             ["direction", "target", "outcome", "denials", "source_ips", "workspaces"],
             formats=number_heat("denials"),
             description="Context-based ingress and serverless egress denials (empty if these system tables are not enabled)."))}
</form>"""
    return xml


def window_search():
    """Search converting the time picker into $t_from$ / $t_to$ (epoch seconds, at most 90 days) and a chart bucket."""
    return (f'<search id="window"><query><![CDATA[{TIME_SEARCH}]]></query>'
            "<earliest>$time.earliest$</earliest><latest>$time.latest$</latest>"
            "<done><set token=\"t_from\">$result.t_from$</set><set token=\"t_to\">$result.t_to$</set>"
            "<set token=\"t_span\">$result.t_span$</set><set token=\"t_span_label\">$result.t_span_label$</set></done>"
            "</search>")


def actor_search():
    """Search turning the actor input into a safe SQL LIKE pattern ($actor_like$)."""
    return (f"<search><query><![CDATA[{ACTOR_SEARCH}]]></query>"
            '<done><set token="actor_like">$result.v$</set></done></search>')


SOURCE_SEARCH = """| makeresults | eval v="$sp$." . if("$source$" == "live", "live_", "")"""


def detections_dashboard(cfg):
    q = {k: dbq(v) for k, v in DETECTION_QUERIES.items()}
    actor_drill = ('<condition field="principal"><set token="form.actor">$click.value2$</set></condition>'
                   '<condition field="actor"><set token="form.actor">$click.value2$</set></condition>'
                   '<condition field="*"></condition>')
    bases = "".join(search(q[k], sid=k) for k in ("det_sensitive", "det_detections", "det_activity", "det_ips", "det_workspaces"))
    fieldset = f"""
<fieldset submitButton="false" autoRun="true">
  <input type="time" token="time" searchWhenChanged="true">
    <label>Time range (max 90 days)</label>
    <default><earliest>-7d@d</earliest><latest>now</latest></default>
  </input>
  <input type="dropdown" token="source" searchWhenChanged="true">
    <label>Source</label>
    <choice value="tables">Refreshed tables (fast, up to 90 days)</choice>
    <choice value="live">Live audit log (minutes behind, slower)</choice>
    <default>tables</default>
  </input>
  <input type="dropdown" token="ws" searchWhenChanged="true">
    <label>Workspace</label>
    <choice value="*">All workspaces</choice>
    <default>*</default>
    <fieldForLabel>workspace_name</fieldForLabel>
    <fieldForValue>workspace_name</fieldForValue>
    {search(dbq("SELECT DISTINCT workspace_name FROM $sp$.workspaces WHERE workspace_name IS NOT NULL ORDER BY 1"))}
  </input>
  <input type="text" token="actor" searchWhenChanged="true">
    <label>Principal (* wildcard)</label>
    <default>*</default>
  </input>
</fieldset>"""
    source_search = (f"<search><query><![CDATA[{SOURCE_SEARCH}]]></query>"
                     '<done><set token="src">$result.v$</set></done></search>')
    kpis = row(
        single("Behavioural detections", "det_detections", '| where detection_id!="PRINT_STATEMENTS" | stats count as v',
               "SRA rules exceeded"),
        single("HIGH / MEDIUM detections", "det_detections",
               '| stats count(eval(severity="HIGH" OR severity="MEDIUM")) as v', "to review", [GOOD, MEDIUM], [0]),
        single("Sensitive operations", "det_sensitive", "| stats count as v", "ToS, settings, init scripts, mounts ..."),
        single("HIGH sensitive operations", "det_sensitive", '| stats count(eval(severity="HIGH")) as v', "act now",
               [GOOD, HIGH], [0]),
        single("Source IPs", "det_ips", "| stats dc(source_ip) as v", "client IPs seen"),
        single("Principals in 2+ workspaces", "det_workspaces", "| stats count as v", "see access_to_multiple_workspaces"),
    )
    panels = []
    for name, title, base, spl, fields, description in USE_CASES:
        formats = color_map("severity", SEVERITY_COLORS) if "severity" in fields else ""
        drill = actor_drill if ("principal" in fields or "actor" in fields) else ""
        # an empty panel says so explicitly (validation of a use case = "no event in the period", not a blank box)
        empty = f' | appendpipe [| stats count | where count=0 | eval {fields[0]}="No event in the selected period" | fields - count]'
        panels.append(table(f"{name} — {title}", spl + empty, fields, formats=formats, drilldown=drill, count=6, base=base,
                            description=description))
    panels.append(table("Open-sharing recipients without IP access list (current)",
                        q["det_recipients"] + ' | eval created=strftime(tonumber(created_epoch), "%Y-%m-%d") | fields - created_epoch',
                        ["recipient_name", "shares_granted", "share_names", "token_expiration", "recipient_owner", "created"],
                        count=6, description="Current state (system.information_schema): TOKEN recipients with no IP access list."))
    rows = "".join(row(*panels[i:i + 2]) for i in range(0, len(panels), 2))
    return f"""<form version="1.1" theme="dark" hideEdit="false">
  <label>Databricks Security - Threat detections</label>
  <description>One panel per Databricks Security Reference Architecture (SRA) use case, from Databricks system tables: sensitive operations, behavioural detections (thresholds in the detection_rules view of the bundle), secrets, workspaces, IP addresses and ranges, unauthorized Unity Catalog requests, Delta Sharing and data usage. Source: refreshed tables (every 6 hours, up to 90 days) or the live audit log. Click a principal to filter on it.</description>
  {init_tokens(cfg)}
  {window_search()}
  {actor_search()}
  {source_search}
  {bases}
  {fieldset}
  {kpis}
  {rows}
</form>"""


def posture_dashboard(cfg):
    q = {k: dbq(v) for k, v in POSTURE_QUERIES.items()}
    link = '<condition field="{f}"><link target="_blank">$row.{u}|n$</link></condition>'
    checks_drill = (link.format(f="title", u="best_practice_url") + link.format(f="recommendation", u="doc_url")
                    + '<condition field="*"></condition>')
    findings_drill = link.format(f="recommendation", u="doc_url") + '<condition field="*"></condition>'
    fieldset = f"""
<fieldset submitButton="false" autoRun="true">
  <input type="dropdown" token="category" searchWhenChanged="true">
    <label>Category</label>
    <choice value="*">All categories</choice>
    <default>*</default>
    <fieldForLabel>category</fieldForLabel>
    <fieldForValue>category</fieldForValue>
    {search(dbq("SELECT category FROM $sp$.check_results GROUP BY category ORDER BY min(category_order)"))}
  </input>
  <input type="dropdown" token="severity" searchWhenChanged="true">
    <label>Finding severity</label>
    <choice value="*">All</choice><choice value="HIGH">HIGH</choice><choice value="MEDIUM">MEDIUM</choice><choice value="LOW">LOW</choice>
    <default>*</default>
  </input>
</fieldset>"""
    kpi = search(q["posture_kpi"], sid="kpi", refresh="30m")
    xml = f"""<form version="1.1" theme="dark" hideEdit="false">
  <label>Databricks Security - Posture</label>
  <description>Security posture of the Databricks estate: 44 checks modelled on the Security Analysis Tool and the Security Reference Architecture, scored and refreshed by the Databricks Security Posture job (every 6 hours by default). Click a check title for the Databricks security best practice, a recommendation for the remediation documentation.</description>
  {init_tokens(cfg)}
  {kpi}
  {fieldset}
  {row(
      single("Posture score", "kpi", "| fields score_pct", "weighted share of passing checks", [HIGH, INFO, GOOD], [50, 80], "%"),
      single("Change vs 7 days ago", "kpi", "| eval v=round(score_pct - score_pct_7d_ago, 1) | fields v", "score points",
             [HIGH, INFO, GOOD], [-0.05, 0.05]),
      single("Checks failing", "kpi", "| eval v=checks_failed | fields v", "checks with findings", [GOOD, MEDIUM], [0]),
      single("HIGH findings", "kpi", "| fields high_findings", "failing objects", [GOOD, HIGH], [0]),
      single("MEDIUM findings", "kpi", "| fields medium_findings", "failing objects", [GOOD, MEDIUM], [0]),
      single("Data age", "kpi", "| fields hours_since_refresh", "hours since the last refresh", [GOOD, LOW, HIGH], [8, 24], "h"))}
  {row(
      chart("Posture score trend", q["posture_trend"] + ' | eval _time=tonumber(epoch) | timechart span=1d max(score_pct) as "Score %"',
            "line", [("charting.axisY.minimumNumber", "0"), ("charting.axisY.maximumNumber", "100"),
                     ("charting.axisTitleX.visibility", "collapsed"), ("charting.seriesColors", "[0x2a78d6]")]),
      chart("Findings by severity over time",
            q["posture_trend"] + " | eval _time=tonumber(epoch) | timechart span=1d max(high_findings) as HIGH "
            "max(medium_findings) as MEDIUM max(low_findings) as LOW",
            "column", [("charting.chart.stackMode", "stacked"), ("charting.fieldColors", SEVERITY_COLORS),
                       ("charting.axisTitleX.visibility", "collapsed")]))}
  {row(table("Category scorecard", q["posture_categories"],
             ["category", "score_pct", "checks", "failing", "high_failing", "medium_failing", "low_failing", "findings"],
             formats=number_heat("high_failing") + number_heat("medium_failing", MEDIUM), count=10))}
  {row(table("Security checks", q["posture_checks"],
             ["status", "severity", "check_id", "category", "title", "findings", "affected_workspaces", "recommendation",
              "sat_reference"],
             formats=color_map("status", SEVERITY_COLORS) + color_map("severity", SEVERITY_COLORS),
             drilldown=checks_drill, count=32,
             description="Click a title: Databricks security best practice. Click a recommendation: remediation documentation."))}
  {row(table("Findings", q["posture_findings"] + ' | eval detected_at=strftime(tonumber(detected_epoch), "%Y-%m-%d %H:%M")',
             ["severity", "check_id", "title", "workspace_name", "object_type", "object_name", "detail", "detected_at",
              "recommendation"],
             formats=color_map("severity", SEVERITY_COLORS), drilldown=findings_drill, count=20,
             description="Every failing object at the last refresh, filtered by category and severity."))}
  {row(table("Security activity: last 7 days vs previous 7 days", q["posture_activity"]
             + " | eval change=last_7_days - previous_7_days",
             ["metric_label", "last_7_days", "previous_7_days", "change"], count=30),
       html(f'<h3>Go further</h3><ul><li><a href="{BEST_PRACTICES_URL}" target="_blank">Databricks security best practices</a></li>'
            '<li><a href="databricks_security_live">Live activity dashboard</a></li>'
            '<li><a href="databricks_security_detections">Threat detections dashboard</a></li>'
            "<li>Ask questions in natural language: the <b>Security Posture Analyst</b> Genie agent in Databricks.</li></ul>"))}
</form>"""
    return xml


# ----------------------------------------------------------------------------- alerts
ALERT_WINDOW = ("event_date >= CAST(current_timestamp() - INTERVAL 1 DAY AS DATE) "
                "AND event_time >= current_timestamp() - INTERVAL {minutes} MINUTES")
# (name, description, SQL, suppression fields, suppression period). The thresholds of the behavioural detections are the
# detection_rules view of the bundle: one alert covers every rule (one result per detection, field detection_id), so the
# audit log is read once per run instead of once per rule. Route or split on detection_id / operation in Splunk.
ALERTS = [
    ("Databricks - HIGH security signal",
     "Every HIGH signal of the live feed: admin rights granted, PAT without expiry, high privilege granted to all users, "
     "IP access list deleted, ABAC policy deleted, open-sharing token retrieved or recipient without IP access list, account "
     "admin change, host security alert. One alert per event.",
     f"""SELECT event_id, unix_timestamp(event_time) AS epoch, workspace_name, category, actor, action_name, target, detail, source_ip
         FROM $sp$.live_security_events WHERE {ALERT_WINDOW.format(minutes=45)} AND signal = 'HIGH'""",
     "event_id", "2h"),
    ("Databricks - Behavioural detection (SRA)",
     "One alert per principal and window above a detection rule (detection_rules): repeated failed logins, IP access list "
     "failures, repeated access to secrets, repeated unauthorized Unity Catalog / data requests, potential privilege "
     "escalation, download / destructive / read-write bursts, access to 5+ workspaces. Field detection_id names the rule.",
     """SELECT concat(detection_id, '|', principal, '|', CAST(unix_timestamp(window_start) AS STRING)) AS alert_key, detection_id,
                title, severity, principal, workspaces, events, distinct_objects, array_join(slice(objects, 1, 10), ', ') AS objects,
                sample, array_join(source_ips, ', ') AS source_ips, sra_query, unix_timestamp(window_start) AS epoch
         FROM $sp$.live_security_detections
         WHERE event_date >= current_date() - 1 AND window_end >= current_timestamp() - INTERVAL 75 MINUTES
           AND detection_id <> 'PRINT_STATEMENTS'""",
     "alert_key", "24h"),
    ("Databricks - Sensitive operation",
     "One alert per sensitive operation: Terms of Service, account settings and admins, Databricks support access, global "
     "init scripts, DBFS mounts, libraries on all clusters, open-sharing recipients without IP access list, recipient token "
     "lifetime, IP-denied sharing queries, host security alerts. Field operation names the type.",
     f"""SELECT event_id, operation, severity, workspace_name, actor, target, detail, source_ip, unix_timestamp(event_time) AS epoch
         FROM $sp$.live_sensitive_operations WHERE {ALERT_WINDOW.format(minutes=45)}""",
     "event_id", "2h"),
]


def savedsearches(cfg):
    warehouse = f' warehouse_id="{cfg["warehouse_id"]}"' if cfg["warehouse_id"] else ""
    out = ["# Generated by tools/build_splunk.py - alerts on the live views of the Databricks Security Posture bundle.",
           "# Disabled by default: enable them in Settings > Searches, reports, and alerts, and add an action (email, ...).",
           "# Every 15 minutes over the last 45-60 minutes (audit events arrive ~10 minutes late); suppression on the listed",
           "# fields avoids alerting twice on the same event / principal.", ""]
    for name, description, query, suppress, period in ALERTS:
        spl = (f'| databricksquery account_name="{cfg["account"]}"{warehouse} command_timeout=300 '
               f'query="{sql(query.replace("$sp$", cfg["schema"]))}" | eval _time=tonumber(epoch) | fields - epoch')
        out += [f"[{name}]", f"description = {description}", f"search = {spl}", "disabled = 1",
                "cron_schedule = */15 * * * *", "enableSched = 1", "dispatch.earliest_time = -1h", "dispatch.latest_time = now",
                "counttype = number of events", "relation = greater than", "quantity = 0",
                "alert.track = 1", "alert.severity = 4" if "HIGH" in name or "Sensitive" in name else "alert.severity = 3",
                "alert.digest_mode = 0", "alert.suppress = 1", f"alert.suppress.fields = {suppress}",
                f"alert.suppress.period = {period}", "action.email.useNSSubject = 1", ""]
    return "\n".join(out)


# ----------------------------------------------------------------------------- app
def app_files(cfg):
    return {
        "default/app.conf": f"""# Generated by tools/build_splunk.py
[install]
is_configured = 1

[launcher]
author = Databricks field engineering
description = Databricks security posture, threat detections (SRA use cases) and near real-time security activity, from Databricks system tables through the Databricks Add-on for Splunk (TA-Databricks).
version = {VERSION}

[ui]
is_visible = 1
label = Databricks Security Posture

[package]
id = {APP}
check_for_updates = 0
""",
        "default/data/ui/nav/default.xml": """<nav search_view="search" color="#d03b3b">
  <view name="databricks_security_live" default="true" />
  <view name="databricks_security_detections" />
  <view name="databricks_security_posture" />
  <view name="search" />
  <a href="alerts">Alerts</a>
</nav>
""",
        "default/data/ui/views/databricks_security_live.xml": live_dashboard(cfg),
        "default/data/ui/views/databricks_security_detections.xml": detections_dashboard(cfg),
        "default/data/ui/views/databricks_security_posture.xml": posture_dashboard(cfg),
        "default/savedsearches.conf": savedsearches(cfg),
        "metadata/default.meta": """# Dashboards and alerts are readable by every role; only admins can edit them.
[]
access = read : [ * ], write : [ admin ]
export = none
""",
        "README.txt": f"""Databricks Security Posture for Splunk {VERSION}

Requires the Databricks Add-on for Splunk (TA-Databricks) with an account named "{cfg['account']}" and the
Databricks Security Posture bundle deployed in {cfg['schema']}.
Documentation: docs/splunk.md of the Databricks Security Posture repository.
""",
    }


def pretty(xml_text):
    """Indented XML, identical on every Python version (minidom's toprettyxml changed attribute order and text layout
    across versions, which would make the CI staleness check fail). Parsing also validates the XML."""
    from xml.dom import minidom, Node

    def attrs(node):
        return "".join(f' {k}="{escape(v, {chr(34): "&quot;"})}"' for k, v in node.attributes.items())

    def inline(node):
        if node.nodeType == Node.TEXT_NODE:
            return escape(node.data)
        if node.nodeType == Node.CDATA_SECTION_NODE:
            return f"<![CDATA[{node.data}]]>"
        if node.nodeType == Node.COMMENT_NODE:
            return f"<!--{node.data}-->"
        inner = "".join(inline(c) for c in node.childNodes)
        return f"<{node.tagName}{attrs(node)}>{inner}</{node.tagName}>" if inner else f"<{node.tagName}{attrs(node)}/>"

    def block(node, depth):
        pad = "  " * depth
        kids = [c for c in node.childNodes if not (c.nodeType == Node.TEXT_NODE and not c.data.strip())]
        mixed = any(c.nodeType == Node.TEXT_NODE for c in kids)
        if node.nodeType != Node.ELEMENT_NODE or mixed or not any(c.nodeType == Node.ELEMENT_NODE for c in kids):
            return [pad + (inline(node).strip() if node.nodeType == Node.ELEMENT_NODE else inline(node))]
        return ([f"{pad}<{node.tagName}{attrs(node)}>"] + [l for c in kids for l in block(c, depth + 1)]
                + [f"{pad}</{node.tagName}>"])

    return "\n".join(block(minidom.parseString(xml_text).documentElement, 0)) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--account", default=DEFAULTS["account"], help="Databricks Add-on for Splunk account name")
    parser.add_argument("--schema", default=DEFAULTS["schema"], help="<catalog>.<schema> of the Security Posture bundle")
    parser.add_argument("--warehouse-id", default=DEFAULTS["warehouse_id"],
                        help="SQL warehouse id (default: the warehouse configured on the add-on account)")
    parser.add_argument("--out", default=None, help="output folder (default: splunk/ of the repo, or dist/ with --package)")
    parser.add_argument("--package", action="store_true", help=f"also write <out>/{APP}-{VERSION}.tar.gz for Install app from file")
    args = parser.parse_args()
    for value in (args.account, args.schema, args.warehouse_id):
        assert re.fullmatch(r"[\w.\-]*", value), f"invalid value: {value!r}"
    cfg = {"account": args.account, "schema": args.schema, "warehouse_id": args.warehouse_id}
    out = args.out or os.path.join(ROOT, "dist" if args.package else "splunk")
    app_dir = os.path.join(out, APP)
    for rel, content in app_files(cfg).items():
        path = os.path.join(app_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(pretty(content) if rel.endswith(".xml") else content)
    print(f"wrote {app_dir}: 3 dashboards, {len(ALERTS)} alerts (account {args.account}, schema {args.schema})")
    if args.package:
        package = os.path.join(out, f"{APP}-{VERSION}.tar.gz")
        with tarfile.open(package, "w:gz") as tar:
            tar.add(app_dir, arcname=APP)
        print(f"wrote {package}: Splunk > Apps > Manage Apps > Install app from file")


if __name__ == "__main__":
    main()
