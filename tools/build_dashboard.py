#!/usr/bin/env python3
"""Generate the AI/BI dashboard of the Security Posture bundle.

Writes src/dashboards/security_posture.lvdash.json, the dashboard template published by the refresh job
(src/publish.py), which sets the datasets' catalog / schema and the "Ask Genie" agent id (${genie_space_id}).

Conventions (AI/BI dashboard spec): 12-column GRID_V1 layout; counter / table / filter widgets are spec
version 2, charts version 3; datasets use bare object names (the job sets each dataset's catalog / schema).
Counters only SUM / MAX numeric columns of datasets pre-aggregated by their filter dimensions, so they follow
page filters, draw a sparkline and stay cheap. Severity colours are pinned and always paired with a label.
"""
import json
import os
import re

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
OUT_JSON = os.path.join(ROOT, "src", "dashboards", "security_posture.lvdash.json")
GENIE_ID_REF = "${genie_space_id}"
BEST_PRACTICES_URL = "https://www.databricks.com/trust/security-features/best-practices"

# Status palette (fixed): critical / serious / warning / good.
HIGH, MEDIUM, LOW, GOOD = "#d03b3b", "#ec835a", "#fab219", "#0ca30c"
SEVERITY_MAPPINGS = [{"value": "HIGH", "color": HIGH}, {"value": "MEDIUM", "color": MEDIUM}, {"value": "LOW", "color": LOW}]
SEVERITY_ORDER = {"by": "custom-order", "orderedValues": ["HIGH", "MEDIUM", "LOW"]}
THEME = {
    "canvasBackgroundColor": {"light": "#F5F6F8", "dark": "#121417"},
    "widgetBackgroundColor": {"light": "#FFFFFF", "dark": "#1B1E23"},
    "widgetBorderColor": {"light": "#FFFFFF", "dark": "#1B1E23"},
    "fontColor": {"light": "#0B0B0B", "dark": "#F0EFEC"},
    "selectionColor": {"light": "#2A78D6", "dark": "#3987E5"},
    "visualizationColors": ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"],
    "widgetHeaderAlignment": "LEFT",
    "fontFamily": "Inter",
    "widgetCornerRadius": 8,
}
CATEGORIES = [  # (category, icon, what it covers) in category_order
    ("Identity & Access", "🔐", "Admins, PATs, OAuth, failed logins, IP blocks"),
    ("Access Control", "🗝️", "Unity Catalog grants and ownership"),
    ("Data Protection", "🛡️", "Sensitive data, exports, secrets"),
    ("Tags & Metadata", "🏷️", "Tag and description coverage, classification"),
    ("Policies", "📜", "ABAC, cluster policies, init scripts"),
    ("Delta Sharing", "🔗", "Open-sharing recipients and tokens"),
    ("Compute", "🖥️", "Access modes, compute policies, runtimes"),
    ("Audit & Network", "🌐", "Audit logging, IP access lists, network policies"),
]
CATEGORY_ORDER = {"by": "custom-order", "orderedValues": [c for c, _, _ in CATEGORIES]}


def _case(col, mapping):
    return "CASE " + col + " " + " ".join(f"WHEN '{k}' THEN '{v}'" for k, v in mapping.items()) + " END"


CATEGORY_LABEL = _case("category", {c: f"{i} {c}" for c, i, _ in CATEGORIES})
CATEGORY_SCOPE = _case("category", {c: d for c, _, d in CATEGORIES})


def kpi_pivot(metrics):
    """Dataset SQL pivoting activity_kpis_daily: one row per (event_date, workspace_name), one column per metric."""
    cols = ",\n  ".join(f"sum(CASE WHEN metric = '{m}' THEN value ELSE 0 END) AS {m}" for m in metrics)
    return f"""
        SELECT event_date, workspace_name,
          {cols}
        FROM activity_kpis_daily
        WHERE metric IN ({", ".join(f"'{m}'" for m in metrics)})
        GROUP BY event_date, workspace_name"""


# ----------------------------------------------------------------------------- datasets
DATASETS = {
    # Posture overview
    "ov_kpi": ("Posture KPIs", """
        SELECT s.score, coalesce(t.score, s.score) AS score_7d_ago, s.checks, s.checks_failed, s.high_checks_failed,
               s.high_findings, s.medium_findings, s.low_findings, s.total_findings,
               round((unix_timestamp(current_timestamp()) - unix_timestamp(r.refreshed_at)) / 3600, 1) AS hours_since_refresh
        FROM posture_score s
        CROSS JOIN (SELECT max(refreshed_at) AS refreshed_at FROM security_findings_latest) r
        LEFT JOIN (SELECT score FROM posture_trend WHERE snapshot_date <= current_date() - 7
                   ORDER BY snapshot_date DESC LIMIT 1) t ON TRUE
        WHERE s.category = 'ALL'"""),
    "ov_category": ("Category scorecard", f"""
        SELECT {CATEGORY_LABEL} AS category_label, {CATEGORY_SCOPE} AS scope, category, min(category_order) AS category_order,
               round(sum(CASE WHEN status = 'PASS' THEN severity_weight ELSE 0 END) / sum(severity_weight), 3) AS score,
               count(*) AS checks,
               count_if(status = 'FAIL') AS checks_failed,
               count_if(status = 'FAIL' AND severity = 'HIGH') AS high_failed,
               count_if(status = 'FAIL' AND severity = 'MEDIUM') AS medium_failed,
               count_if(status = 'FAIL' AND severity = 'LOW') AS low_failed,
               sum(findings) AS findings
        FROM check_results
        GROUP BY category
        ORDER BY category_order"""),
    "ov_checks": ("Check results", """
        SELECT CASE WHEN status = 'PASS' THEN '✅ Pass' ELSE '⚠️ Fail' END AS status_label, status,
               severity, severity_order, check_id, category, category_order, title, description, findings, affected_workspaces,
               recommendation, sat_reference, best_practice_url, doc_url
        FROM check_results
        ORDER BY status = 'FAIL' DESC, severity_order, findings DESC, check_id"""),
    "ov_trend": ("Posture trend", "SELECT snapshot_date, score, score_pct, checks_failed, high_findings, medium_findings, low_findings FROM posture_trend ORDER BY snapshot_date"),
    "ov_activity": ("Activity last 7 days vs previous 7 days", """
        SELECT metric_label, metric_order,
               sum(CASE WHEN event_date > current_date() - 7 THEN value ELSE 0 END) AS last_7_days,
               sum(CASE WHEN event_date <= current_date() - 7 THEN value ELSE 0 END) AS previous_7_days,
               sum(CASE WHEN event_date > current_date() - 7 THEN value ELSE 0 END)
                 - sum(CASE WHEN event_date <= current_date() - 7 THEN value ELSE 0 END) AS change
        FROM activity_kpis_daily
        WHERE event_date > current_date() - 14
        GROUP BY metric_label, metric_order
        ORDER BY metric_order"""),
    "ov_activity_daily": ("Key activity per day (30 days)", """
        SELECT event_date, metric_label, sum(value) AS value
        FROM activity_kpis_daily
        WHERE event_date > current_date() - 30
          AND metric IN ('admin_grants', 'broad_grants', 'failed_auth', 'interactive_exports', 'policy_changes', 'risky_config_changes')
        GROUP BY event_date, metric_label
        ORDER BY event_date"""),
    # Findings explorer
    "fx_findings": ("Findings (latest refresh)", """
        SELECT severity, severity_order, check_id, concat(check_id, ' · ', title) AS check_label, title, category, workspace_name,
               object_type, object_name, detail, detected_at, recommendation, best_practice_url, doc_url, refreshed_at
        FROM security_findings_latest
        ORDER BY severity_order, check_id, detected_at DESC"""),
    # Identity & access
    "ia_daily": ("Identity KPIs per day", kpi_pivot(["sso_logins", "failed_auth", "ip_blocked", "admin_grants", "pats_created", "pats_without_expiry"])),
    "ia_auth": ("Authentication per day", "SELECT event_date, workspace_name, principal, principal_type, auth_category, events, failed_events FROM auth_events_daily"),
    "ia_failed": ("Failed authentication", """
        SELECT event_time, event_date, workspace_name, principal, action_name, is_ip_blocked,
               CASE WHEN is_ip_blocked THEN 'IP access list block' ELSE action_name END AS failure_type,
               source_ip, error_message
        FROM failed_auth_events"""),
    "ia_top_ips": ("Top failing source IPs (30 days)", """
        SELECT source_ip, sum(CASE WHEN is_ip_blocked THEN 1 ELSE 0 END) AS ip_blocks, sum(CASE WHEN is_ip_blocked THEN 0 ELSE 1 END) AS auth_failures,
               count(*) AS failures
        FROM failed_auth_events WHERE event_date > current_date() - 30 AND source_ip IS NOT NULL
        GROUP BY source_ip ORDER BY failures DESC LIMIT 15"""),
    "ia_top_pat_users": ("Top human PAT users (30 days)", """
        SELECT principal, sum(events) AS requests
        FROM auth_events_daily WHERE event_date > current_date() - 30 AND auth_category = 'PAT' AND principal_type = 'USER'
        GROUP BY principal ORDER BY requests DESC LIMIT 15"""),
    "ia_identity": ("Identity & admin changes", """
        SELECT event_time, event_date, workspace_name, actor, action_name, target, group_name, assigned_permissions,
               CASE WHEN is_privileged THEN '⚠️ Privileged' ELSE 'Standard' END AS change_class, status_code
        FROM identity_changes
        ORDER BY event_time DESC"""),
    "ia_tokens": ("PAT creations", """
        SELECT event_time, event_date, workspace_name, actor, lifetime_bucket, lifetime_days, expires_at, token_scopes
        FROM token_events WHERE action_name = 'generateDbToken'
        ORDER BY event_time DESC"""),
    # Data access control
    "ac_state": ("Access control state by catalog", """
        WITH g AS (
          SELECT coalesce(catalog_name, '(metastore objects)') AS catalog_name, count(*) AS direct_grants,
                 count_if(is_broad_principal) AS broad_grants, count_if(is_high_privilege) AS high_privilege_grants,
                 count_if(grantee_type = 'USER') AS user_grants
          FROM uc_grants WHERE is_direct GROUP BY 1),
        o AS (
          SELECT coalesce(catalog_name, '(metastore objects)') AS catalog_name, count(*) AS securables, count_if(owner_type = 'USER') AS user_owned
          FROM securable_owners GROUP BY 1)
        SELECT catalog_name, coalesce(direct_grants, 0) AS direct_grants, coalesce(broad_grants, 0) AS broad_grants,
               coalesce(high_privilege_grants, 0) AS high_privilege_grants, coalesce(user_grants, 0) AS user_grants,
               coalesce(securables, 0) AS securables, coalesce(user_owned, 0) AS user_owned
        FROM g FULL OUTER JOIN o USING (catalog_name)"""),
    "ac_daily": ("Access control KPIs per day", kpi_pivot(["uc_grants", "uc_revokes", "broad_grants", "acl_changes", "access_denied"])),
    "ac_grants": ("Current direct grants", """
        SELECT securable_type, securable_name, coalesce(catalog_name, '(metastore objects)') AS catalog_name, grantee, grantee_type,
               privilege_type, CASE WHEN is_broad_principal THEN '⚠️ All users' ELSE 'Scoped' END AS audience,
               CASE WHEN is_high_privilege THEN '⚠️ High' ELSE 'Standard' END AS privilege_level, grantor
        FROM uc_grants WHERE is_direct
        ORDER BY is_broad_principal DESC, is_high_privilege DESC, securable_type, securable_name"""),
    "ac_top_grantees": ("Top grantees", """
        SELECT grantee, grantee_type, count(*) AS grants FROM uc_grants WHERE is_direct
        GROUP BY grantee, grantee_type ORDER BY grants DESC LIMIT 15"""),
    "ac_owners": ("Securable owners", """
        SELECT securable_type, securable_name, coalesce(catalog_name, '(metastore objects)') AS catalog_name, owner, owner_type, created
        FROM securable_owners"""),
    "ac_changes": ("UC permission changes", """
        SELECT event_time, event_date, workspace_name, actor, change_type, privilege, principal, securable_type, securable_name,
               coalesce(catalog_name, '(metastore objects)') AS catalog_name,
               CASE WHEN is_broad_principal THEN '⚠️ All users' ELSE 'Scoped' END AS audience
        FROM uc_permission_changes WHERE coalesce(status_code, 200) < 400
        ORDER BY event_time DESC"""),
    "ac_acl": ("Workspace ACL changes", """
        SELECT event_time, event_date, workspace_name, actor, object_type, object_id, target_principal, permission
        FROM workspace_acl_changes ORDER BY event_time DESC"""),
    "ac_denied": ("Denied data access", """
        SELECT event_date, workspace_name, principal, action_name, securable_name, error_message, attempts, last_attempt
        FROM access_denied_daily ORDER BY attempts DESC"""),
    # Policies & data protection
    "po_state": ("Protection state", """
        SELECT (SELECT count(*) FROM abac_policies) AS abac_policies,
               (SELECT count_if(control_type = 'COLUMN_MASK') FROM fine_grained_controls) AS column_masks,
               (SELECT count_if(control_type = 'ROW_FILTER') FROM fine_grained_controls) AS row_filters,
               (SELECT count(*) FROM sensitive_columns) AS sensitive_columns,
               (SELECT count(*) FROM security_findings_latest WHERE check_id = 'DP-01') AS unprotected_sensitive"""),
    "po_abac": ("ABAC policies", "SELECT policy_name, policy_type, on_securable_type, scope_name, catalog_name, to_principals, except_principals, when_condition, governed_tags, created_by FROM abac_policies ORDER BY scope_name, policy_name"),
    "po_fgc": ("Column masks & row filters", "SELECT control_type, catalog_name, table_full_name, target, function_name FROM fine_grained_controls ORDER BY table_full_name"),
    "po_sensitive": ("Sensitive columns", """
        SELECT s.catalog_name, s.table_full_name, s.column_name, s.classification, s.confidence, s.source, s.mask_name,
               CASE WHEN s.is_masked OR coalesce(c.has_abac_policy_in_scope, FALSE) THEN '✅ Protected' ELSE '⚠️ Unprotected' END AS protection_status
        FROM sensitive_columns s LEFT JOIN table_governance_coverage c ON c.table_full_name = s.table_full_name
        ORDER BY protection_status DESC, s.table_full_name, s.column_name"""),
    "po_changes": ("Policy changes", """
        SELECT event_time, event_date, workspace_name, actor, policy_kind, action_name, policy_name, policy_type, scope_name,
               CASE WHEN is_deletion THEN '⚠️ Deleted' ELSE 'Created / updated' END AS change_class
        FROM policy_changes ORDER BY event_time DESC"""),
    # Tags & metadata
    "tg_coverage": ("Table governance coverage", """
        SELECT catalog_name, schema_name, table_full_name, table_owner, owner_type,
               CASE WHEN is_tagged_incl_inherited THEN 1 ELSE 0 END AS tagged,
               CASE WHEN has_comment THEN 1 ELSE 0 END AS documented,
               CASE WHEN is_tagged_incl_inherited THEN 'Tagged' ELSE 'Untagged' END AS tag_status,
               CASE WHEN has_comment THEN 'Documented' ELSE 'No description' END AS doc_status,
               sensitive_column_count
        FROM table_governance_coverage"""),
    "tg_gaps": ("Popular tables missing tags or descriptions", """
        WITH usage AS (
          SELECT table_full_name, count(DISTINCT principal) AS readers_30d, sum(access_events) AS reads_30d
          FROM table_access_activity WHERE access_type = 'READ' AND event_date > current_date() - 30 GROUP BY 1)
        SELECT c.catalog_name, c.table_full_name, c.table_owner, u.readers_30d, u.reads_30d, c.sensitive_column_count,
               CASE WHEN c.is_tagged_incl_inherited THEN '✅ Tagged' ELSE '⚠️ Untagged' END AS tag_status,
               CASE WHEN c.has_comment THEN '✅ Documented' ELSE '⚠️ No description' END AS doc_status
        FROM table_governance_coverage c JOIN usage u USING (table_full_name)
        WHERE NOT c.is_tagged_incl_inherited OR NOT c.has_comment
        ORDER BY u.readers_30d DESC, u.reads_30d DESC"""),
    "tg_state": ("Tag inventory", """
        SELECT (SELECT count(*) FROM governed_tags) AS governed_tags,
               (SELECT count(*) FROM tag_assignments) AS tag_assignments,
               (SELECT count_if(is_governed) FROM tag_assignments) AS governed_assignments"""),
    "tg_top_tags": ("Most used tag keys", """
        SELECT tag_name, securable_type, count(*) AS assignments FROM tag_assignments
        WHERE tag_name IN (SELECT tag_name FROM tag_assignments GROUP BY tag_name ORDER BY count(*) DESC LIMIT 12)
        GROUP BY tag_name, securable_type"""),
    "tg_changes": ("Tag changes", """
        SELECT event_time, event_date, workspace_name, actor, change_type, tag_name, tag_value, securable_type, securable_name, column_name,
               CASE WHEN is_classification_tag THEN '⚠️ Classification' ELSE 'Other' END AS tag_class
        FROM tag_changes WHERE coalesce(status_code, 200) < 400
        ORDER BY event_time DESC"""),
    # Data activity & sharing
    "ex_daily": ("Data activity KPIs per day", kpi_pivot(["interactive_exports", "automated_exports", "secret_reads", "secret_failures", "sharing_data_access", "sharing_ip_denied"])),
    "ex_export_daily": ("Interactive exports per day", "SELECT event_date, workspace_name, principal, export_channel, client_type, events FROM data_export_daily WHERE is_interactive"),
    "ex_top_exporters": ("Top interactive exporters (30 days)", """
        SELECT principal, export_channel, sum(events) AS exports FROM data_export_daily
        WHERE is_interactive AND event_date > current_date() - 30
          AND principal IN (SELECT principal FROM data_export_daily WHERE is_interactive AND event_date > current_date() - 30
                            GROUP BY principal ORDER BY sum(events) DESC LIMIT 15)
        GROUP BY principal, export_channel"""),
    "ex_exports": ("Interactive export events", """
        SELECT event_time, event_date, workspace_name, principal, export_channel, action_name, object_ref, export_format, source_ip
        FROM data_export_events ORDER BY event_time DESC"""),
    "ex_secrets": ("Secret access per day", "SELECT event_date, workspace_name, principal, principal_type, action_name, secret_scope, events, failures FROM secret_access_daily ORDER BY events DESC"),
    "ex_sharing": ("Delta Sharing recipients", """
        SELECT recipient_name, authentication_type, shares_granted, share_names, ip_allowlist_ranges, token_expiration, recipient_owner,
               CASE WHEN authentication_type = 'TOKEN' THEN 1 ELSE 0 END AS open_recipient,
               CASE WHEN authentication_type = 'TOKEN' AND NOT has_ip_allowlist THEN 1 ELSE 0 END AS open_without_ip_list,
               CASE WHEN authentication_type <> 'TOKEN' THEN 'Databricks-to-Databricks'
                    WHEN has_ip_allowlist THEN '✅ Open, IP restricted' ELSE '⚠️ Open, no IP list' END AS exposure
        FROM delta_sharing_posture ORDER BY open_without_ip_list DESC, shares_granted DESC"""),
    "ex_sharing_act": ("Delta Sharing activity", """
        SELECT event_date, workspace_name, activity_type, action_name, principal, recipient_authentication_type, share_name, object_name,
               events, failures, ip_denied_events
        FROM delta_sharing_activity_daily ORDER BY event_date DESC, events DESC"""),
    # Compute, network & configuration
    "cn_compute": ("Interactive clusters", """
        SELECT workspace_name, cluster_id, cluster_name, owned_by, access_mode, dbr_version, init_script_count, last_changed,
               CASE WHEN is_uc_secured THEN '✅ Yes' ELSE '⚠️ No' END AS uc_secured,
               CASE WHEN has_policy THEN '✅ Yes' ELSE '⚠️ No' END AS policy,
               CASE WHEN is_uc_secured THEN 0 ELSE 1 END AS not_uc_secured,
               CASE WHEN has_policy THEN 0 ELSE 1 END AS without_policy,
               CASE WHEN dbr_major < 13 THEN 1 ELSE 0 END AS old_runtime
        FROM compute_posture WHERE cluster_source IN ('UI', 'API')"""),
    "cn_network": ("Network policy events", """
        SELECT event_date, workspace_name, direction, outcome, rule_or_reason, target, events,
               CASE WHEN upper(outcome) IN ('DENY', 'DENIED', 'DROP', 'BLOCK', 'BLOCKED', 'REJECT') THEN events ELSE 0 END AS denied_events
        FROM network_events_daily"""),
    "cn_top_denied": ("Top denied network targets (30 days)", """
        SELECT target, direction, sum(events) AS denials FROM network_events_daily
        WHERE event_date > current_date() - 30 AND upper(outcome) IN ('DENY', 'DENIED', 'DROP', 'BLOCK', 'BLOCKED', 'REJECT')
        GROUP BY target, direction ORDER BY denials DESC LIMIT 15"""),
    "cn_config": ("Workspace security settings (last known)", """
        SELECT workspace_name, setting_name, setting_value, last_changed, last_changed_by,
               CASE WHEN is_risky_value THEN '⚠️ Risky' ELSE '✅ OK' END AS setting_status,
               CASE WHEN is_risky_value THEN 1 ELSE 0 END AS risky
        FROM workspace_config_latest WHERE is_security_relevant
        ORDER BY is_risky_value DESC, setting_name"""),
    "cn_config_changes": ("Workspace security setting changes", """
        SELECT event_time, event_date, workspace_name, actor, setting_name, setting_value,
               CASE WHEN is_risky_value THEN '⚠️ Risky' ELSE '✅ OK' END AS setting_status
        FROM workspace_config_changes WHERE is_security_relevant AND coalesce(status_code, 200) < 400
        ORDER BY event_time DESC"""),
}


def dataset(name):
    display, sql = DATASETS[name]
    lines = re.sub(r"\n\s{8}", "\n", sql.strip()).split("\n")
    return {"name": name, "displayName": display, "queryLines": [l + "\n" for l in lines[:-1]] + [lines[-1]]}


# ----------------------------------------------------------------------------- widgets
_seq = {"n": 0}


def _wname(prefix):
    _seq["n"] += 1
    return f"{prefix}_{_seq['n']:03d}"


def field(expr):
    """'col' -> plain field; 'sum(col)' / 'max(col)' / 'min(col)' / 'avg(col)' / 'count(col)' / 'countdistinct(col)'
    -> aggregate; 'daily(col)' / 'weekly(col)' -> DATE_TRUNC."""
    m = re.match(r"^(sum|count|countdistinct|max|min|avg|daily|weekly)\((\w+)\)$", expr)
    if not m:
        return {"name": expr, "expression": f"`{expr}`"}
    fn, col = m.groups()
    sql = {"countdistinct": f"COUNT(DISTINCT `{col}`)", "daily": f'DATE_TRUNC("DAY", `{col}`)',
           "weekly": f'DATE_TRUNC("WEEK", `{col}`)'}.get(fn, f"{fn.upper()}(`{col}`)")
    return {"name": expr, "expression": sql}


def query(ds, fields, disaggregated=False):
    return [{"name": "main_query", "query": {"datasetName": ds, "fields": [field(f) for f in fields], "disaggregated": disaggregated}}]


def frame(title, description=None):
    f = {"showTitle": True, "title": title}
    if description:
        f.update(description=description, showDescription=True)
    return f


def text(*lines):
    return {"name": _wname("text"), "multilineTextboxSpec": {"lines": [l + "\n" for l in lines]}}


def rule(operator, value, color):
    return {"condition": {"operator": operator, "operand": {"type": "data-value", "value": str(value)}}, "color": color}


def alert_if_positive(color=HIGH):
    """Counter colour: red (or given colour) when > 0, green when 0."""
    return [rule(">", 0, color), rule("==", 0, GOOD)]


def counter(ds, value, title, description=None, fmt="count", style=None, target=None, period=None, template=None, row=False):
    formats = {
        "count": {"type": "number", "abbreviation": "compact", "decimalPlaces": {"type": "max", "places": 1}},
        "percent": {"type": "number-percent", "decimalPlaces": {"type": "max", "places": 1}},
        "plain": {"type": "number-plain", "decimalPlaces": {"type": "max", "places": 1}},
    }
    fields = [value] + [f for f in (target, period) if f] + re.findall(r"\{\{(\w+)\}\}", template or "")
    enc = {"value": {"fieldName": value, "displayName": title, "format": formats[fmt]}}
    if template:
        enc["value"]["formatTemplate"] = template
    if style:
        enc["value"]["style"] = {"rules": style}
    if target:
        enc["target"] = {"fieldName": target, "displayName": "vs 7 days ago"}
    if period:
        enc["period"] = {"fieldName": period}
    return {"name": _wname("kpi"), "queries": query(ds, list(dict.fromkeys(fields)), disaggregated=row),
            "spec": {"version": 2, "widgetType": "counter", "frame": frame(title, description), "encodings": enc}}


def daily_counter(ds, col, title, description=None, style=None):
    """Counter over a per-day dataset: total for the filtered period + daily sparkline."""
    return counter(ds, f"sum({col})", title, description, style=style, period="daily(event_date)")


def _color(col, title, mappings=None, order=None):
    scale = {"type": "categorical"}
    if mappings:
        scale["mappings"] = mappings
    if order:
        scale["sort"] = order
    return {"fieldName": col, "displayName": title, "scale": scale}


def bar(ds, x, y, title, x_title, y_title, color=None, color_title=None, mappings=None, color_order=None,
        x_order=None, description=None, labels=False):
    fields = [x, y] + ([color] if color and color != x else [])
    enc = {"x": {"fieldName": x, "displayName": x_title, "scale": {"type": "categorical", "sort": x_order or {"by": "y-reversed"}}},
           "y": {"fieldName": y, "displayName": y_title, "scale": {"type": "quantitative"}}}
    if color:
        enc["color"] = _color(color, color_title or color, mappings, color_order)
    if labels:
        enc["label"] = {"show": True}
    return {"name": _wname("bar"), "queries": query(ds, fields),
            "spec": {"version": 3, "widgetType": "bar", "frame": frame(title, description), "encodings": enc}}


def line(ds, x, ys, title, x_title, y_title, color=None, color_title=None, description=None, temporal=True):
    """ys: one field, or a list of (field, display name) for several series."""
    if isinstance(ys, str):
        y_enc, y_fields = {"fieldName": ys, "displayName": y_title, "scale": {"type": "quantitative"}}, [ys]
    else:
        y_enc = {"scale": {"type": "quantitative"}, "fields": [{"fieldName": f, "displayName": d} for f, d in ys]}
        y_fields = [f for f, _ in ys]
    enc = {"x": {"fieldName": x, "displayName": x_title, "scale": {"type": "temporal" if temporal else "categorical"}}, "y": y_enc}
    if color:
        enc["color"] = _color(color, color_title or color)
    return {"name": _wname("line"), "queries": query(ds, [x] + y_fields + ([color] if color else [])),
            "spec": {"version": 3, "widgetType": "line", "frame": frame(title, description), "encodings": enc}}


def pie(ds, cat, val, title, cat_title, val_title, mappings=None, order=None):
    return {"name": _wname("pie"), "queries": query(ds, [cat, val]),
            "spec": {"version": 3, "widgetType": "pie", "frame": frame(title),
                     "encodings": {"angle": {"fieldName": val, "displayName": val_title, "scale": {"type": "quantitative"}},
                                   "color": _color(cat, cat_title, mappings, order), "label": {"show": True}}}}


def chip(value, bg, fg="#FFFFFF"):
    return {"condition": {"operator": "==", "operand": {"type": "data-value", "value": value}}, "backgroundColor": bg, "foregroundColor": fg}


SEVERITY_STYLE = {"type": "basic", "rules": [chip("HIGH", HIGH), chip("MEDIUM", MEDIUM, "#0B0B0B"), chip("LOW", LOW, "#0B0B0B")]}
STATUS_STYLE = {"type": "basic", "rules": [chip("⚠️ Fail", HIGH), chip("✅ Pass", GOOD)]}


def flag_style(*bad_values):
    return {"type": "basic", "rules": [chip(v, HIGH) for v in bad_values]}


def col(name, title=None, link=None, tooltip=None, style=None, fmt=None):
    """Table column. link / tooltip are templates: {{@}} = cell value, {{other_column}} = another column of the row."""
    c = {"fieldName": name, "displayName": title or name.replace("_", " ").capitalize()}
    if link:
        c["link"] = {"templatedURL": link}
    if tooltip:
        c["tooltip"] = {"templatedText": tooltip}
    if style:
        c["style"] = style
    if fmt:
        c["format"] = fmt
    return c


def table(ds, columns, title, description=None):
    """columns: names or col(...) dicts. Fields referenced by link / tooltip templates are queried too."""
    columns = [col(c) if isinstance(c, str) else c for c in columns]
    names = [c["fieldName"] for c in columns]
    for c in columns:
        for tpl in (c.get("link", {}).get("templatedURL", ""), c.get("tooltip", {}).get("templatedText", "")):
            names += [n for n in re.findall(r"\{\{(\w+)\}\}", tpl) if n != "@"]
    return {"name": _wname("table"), "queries": query(ds, list(dict.fromkeys(names)), disaggregated=True),
            "spec": {"version": 2, "widgetType": "table", "frame": frame(title, description), "encodings": {"columns": columns}}}


def _filter(kind, title, column, datasets):
    name = _wname("filter")
    queries = [{"name": f"{name}_{ds}", "query": {"datasetName": ds, "fields": [{"name": column, "expression": f"`{column}`"}],
                                                   "disaggregated": False}} for ds in datasets]
    return {"name": name, "queries": queries,
            "spec": {"version": 2, "widgetType": kind, "frame": {"showTitle": True, "title": title},
                     "encodings": {"fields": [{"fieldName": column, "displayName": title, "queryName": q["name"]} for q in queries]}}}


def multi_filter(title, column, datasets):
    return _filter("filter-multi-select", title, column, datasets)


def date_filter(title, column, datasets):
    return _filter("filter-date-range-picker", title, column, datasets)


# ----------------------------------------------------------------------------- layout
class Page:
    def __init__(self, name, title):
        self.name, self.title, self.layout, self.y = name, title, [], 0

    def row(self, height, *widgets):
        """widgets: (widget, width) pairs; a row must fill the 12-column grid."""
        x = 0
        for w, width in widgets:
            self.layout.append({"widget": w, "position": {"x": x, "y": self.y, "width": width, "height": height}})
            x += width
        assert x == 12, f"row on page {self.name} is {x} columns wide, expected 12"
        self.y += height
        return self

    def to_json(self):
        return {"name": self.name, "displayName": self.title, "pageType": "PAGE_TYPE_CANVAS", "layoutVersion": "GRID_V1", "layout": self.layout}


def header(title, subtitle):
    return text(f"## {title}", "", subtitle)


def section(title, subtitle=None):
    return text(f"### {title}", *([""] + [subtitle] if subtitle else []))


def build():
    pages = []

    # 1. Posture overview ----------------------------------------------------------------------
    p = Page("overview", "Posture overview")
    p.row(2, (header("🛡️ Databricks Security Posture",
                     "Access control, policies, tags and security configuration of the Databricks estate, computed only from "
                     f"**system tables**. Checks follow the [Databricks Security Best Practices]({BEST_PRACTICES_URL}) and the Security "
                     "Analysis Tool (SAT). Click a check to open its best practice, and its recommendation for the documentation."), 12))
    p.row(3, (counter("ov_kpi", "score", "Posture score", "Weighted share of passing checks (HIGH 5, MEDIUM 3, LOW 1), vs 7 days ago",
                      fmt="percent", style=[rule(">=", 0.8, GOOD), rule("<", 0.5, HIGH)], target="score_7d_ago", row=True), 3),
             (counter("ov_kpi", "checks_failed", "Checks failing", "Checks with at least one finding", template="{{@formatted}} of {{checks}}",
                      style=alert_if_positive(MEDIUM), row=True), 3),
             (counter("ov_kpi", "high_findings", "HIGH findings", style=alert_if_positive(), row=True), 2),
             (counter("ov_kpi", "medium_findings", "MEDIUM findings", style=alert_if_positive(MEDIUM), row=True), 2),
             (counter("ov_kpi", "hours_since_refresh", "Data age", "Since the last Security Posture refresh",
                      fmt="plain", template="{{@formatted}} h", row=True), 2))
    p.row(6, (bar("ov_checks", "category", "sum(findings)", "Findings by category and severity", "Category", "Findings",
                  color="severity", color_title="Severity", mappings=SEVERITY_MAPPINGS, color_order=SEVERITY_ORDER,
                  x_order=CATEGORY_ORDER), 6),
             (line("ov_trend", "snapshot_date", "score_pct", "Posture score trend", "Snapshot date", "Score (%)",
                   description="Daily snapshot written by the refresh job"), 6))
    p.row(1, (section("Posture by category"), 12))
    p.row(6, (table("ov_category", [
        col("category_label", "Category", tooltip="{{scope}}"),
        col("score", "Score", fmt={"type": "number-percent", "decimalPlaces": {"type": "max", "places": 0}},
            style={"type": "basic", "rules": [
                {"condition": {"operator": ">=", "operand": {"type": "data-value", "value": "0.8"}}, "backgroundColor": GOOD, "foregroundColor": "#FFFFFF"},
                {"condition": {"operator": "<", "operand": {"type": "data-value", "value": "0.5"}}, "backgroundColor": HIGH, "foregroundColor": "#FFFFFF"}]}),
        col("checks", "Checks"), col("checks_failed", "Failing"),
        col("high_failed", "HIGH failing", style={"type": "basic", "rules": [
            {"condition": {"operator": ">", "operand": {"type": "data-value", "value": "0"}}, "backgroundColor": HIGH, "foregroundColor": "#FFFFFF"}]}),
        col("medium_failed", "MEDIUM failing", style={"type": "basic", "rules": [
            {"condition": {"operator": ">", "operand": {"type": "data-value", "value": "0"}}, "backgroundColor": MEDIUM, "foregroundColor": "#0B0B0B"}]}),
        col("low_failed", "LOW failing", style={"type": "basic", "rules": [
            {"condition": {"operator": ">", "operand": {"type": "data-value", "value": "0"}}, "backgroundColor": LOW, "foregroundColor": "#0B0B0B"}]}),
        col("findings", "Findings"), col("scope", "Covers"),
    ], "Category scorecard", "Score = weighted share of passing checks in the category"), 12))
    p.row(1, (section("All checks"), 12))
    p.row(12, (table("ov_checks", [
        col("status_label", "Status", style=STATUS_STYLE),
        col("severity", "Severity", style=SEVERITY_STYLE),
        col("check_id", "ID"),
        col("category", "Category"),
        col("title", "Check (best practice ↗)", link="{{best_practice_url}}", tooltip="{{description}}"),
        col("findings", "Findings"),
        col("affected_workspaces", "Workspaces"),
        col("recommendation", "Recommendation (documentation ↗)", link="{{doc_url}}"),
        col("sat_reference", "SAT ref"),
    ], "Security checks", "Check title → Databricks security best practice; recommendation → documentation of the remediation"), 12))
    p.row(1, (section("Activity: last 7 days vs previous 7 days"), 12))
    p.row(8, (table("ov_activity", [col("metric_label", "Metric"), col("last_7_days", "Last 7 days"),
                                    col("previous_7_days", "Previous 7 days"),
                                    col("change", "Change", style={"type": "basic", "rules": [
                                        {"condition": {"operator": ">", "operand": {"type": "data-value", "value": "0"}}, "foregroundColor": HIGH}]})],
                    "Security activity", "All workspaces; increases are highlighted"), 5),
             (line("ov_activity_daily", "event_date", "sum(value)", "Key security activity per day (30 days)", "Date", "Events",
                   color="metric_label", color_title="Metric"), 7))
    pages.append(p)

    # 2. Findings explorer ---------------------------------------------------------------------
    p = Page("findings", "Findings explorer")
    p.row(2, (header("🔎 Findings explorer", "Every failing object of every check at the last refresh. Filter by severity, category, check or workspace."), 12))
    p.row(2, (multi_filter("Severity", "severity", ["fx_findings"]), 3),
             (multi_filter("Category", "category", ["fx_findings"]), 3),
             (multi_filter("Check", "check_label", ["fx_findings"]), 3),
             (multi_filter("Workspace", "workspace_name", ["fx_findings"]), 3))
    p.row(7, (bar("fx_findings", "check_label", "count(check_id)", "Findings per check", "Check", "Findings",
                  color="severity", color_title="Severity", mappings=SEVERITY_MAPPINGS, color_order=SEVERITY_ORDER), 8),
             (pie("fx_findings", "severity", "count(check_id)", "Findings by severity", "Severity", "Findings",
                  mappings=SEVERITY_MAPPINGS, order=SEVERITY_ORDER), 4))
    p.row(14, (table("fx_findings", [
        col("severity", "Severity", style=SEVERITY_STYLE), col("check_id", "ID"),
        col("title", "Check (best practice ↗)", link="{{best_practice_url}}"),
        col("workspace_name", "Workspace"), col("object_type", "Object type"), col("object_name", "Object"), col("detail", "Evidence"),
        col("detected_at", "Detected"), col("recommendation", "Recommendation (documentation ↗)", link="{{doc_url}}"),
    ], "Findings"), 12))
    pages.append(p)

    # 3. Identity & authentication -------------------------------------------------------------
    ia = ["ia_daily", "ia_auth", "ia_failed", "ia_identity", "ia_tokens"]
    p = Page("identity", "Identity & authentication")
    p.row(2, (header("🔐 Identity & authentication", "Logins, personal access tokens, failed authentication, admin and group changes."), 6),
             (date_filter("Date", "event_date", ia), 3), (multi_filter("Workspace", "workspace_name", ia), 3))
    p.row(3, (daily_counter("ia_daily", "sso_logins", "SSO logins"), 2),
             (daily_counter("ia_daily", "failed_auth", "Failed authentications"), 2),
             (daily_counter("ia_daily", "ip_blocked", "IP access list blocks"), 2),
             (daily_counter("ia_daily", "admin_grants", "Admin rights granted", style=alert_if_positive(MEDIUM)), 2),
             (daily_counter("ia_daily", "pats_created", "PATs created"), 2),
             (daily_counter("ia_daily", "pats_without_expiry", "PATs without expiry", style=alert_if_positive()), 2))
    p.row(6, (line("ia_auth", "daily(event_date)", "sum(events)", "Authentication by method", "Date", "Requests",
                   color="auth_category", color_title="Method"), 6),
             (bar("ia_failed", "failure_type", "count(event_time)", "Failed authentication by type", "Type", "Failures"), 6))
    p.row(6, (bar("ia_top_ips", "source_ip", "sum(failures)", "Top failing source IPs", "Source IP", "Failures",
                  description="Last 30 days, all workspaces"), 4),
             (bar("ia_top_pat_users", "principal", "sum(requests)", "Top human PAT users", "User", "Requests",
                  description="Last 30 days, all workspaces — candidates for OAuth"), 4),
             (bar("ia_tokens", "lifetime_bucket", "count(event_time)", "PATs created by lifetime", "Lifetime", "Tokens",
                  x_order={"by": "custom-order", "orderedValues": ["No expiry", "> 90 days", "<= 90 days"]}, labels=True), 4))
    p.row(7, (table("ia_identity", [col("event_time", "Time"), col("workspace_name", "Workspace"), col("actor", "Actor"),
                                    col("action_name", "Action"), col("target", "Target"), col("group_name", "Group"),
                                    col("assigned_permissions", "Permissions"),
                                    col("change_class", "Class", style=flag_style("⚠️ Privileged"))],
                    "Identity, group & admin changes"), 12))
    p.row(7, (table("ia_failed", [col("event_time", "Time"), col("workspace_name", "Workspace"), col("principal", "Principal"),
                                  col("failure_type", "Type"), col("source_ip", "Source IP"), col("error_message", "Error")],
                    "Failed authentication events"), 6),
             (table("ia_tokens", [col("event_time", "Created"), col("workspace_name", "Workspace"), col("actor", "Owner"),
                                  col("lifetime_bucket", "Lifetime", style=flag_style("No expiry")), col("expires_at", "Expires"),
                                  col("token_scopes", "Scopes")], "PAT creations"), 6))
    pages.append(p)

    # 4. Data access control -------------------------------------------------------------------
    p = Page("access", "Data access control")
    p.row(2, (header("🗝️ Data access control", "Unity Catalog grants, ownership, permission changes and denied access."), 6),
             (multi_filter("Catalog", "catalog_name", ["ac_state", "ac_grants", "ac_owners", "ac_changes"]), 2),
             (date_filter("Date (activity)", "event_date", ["ac_daily", "ac_changes", "ac_acl", "ac_denied"]), 2),
             (multi_filter("Workspace", "workspace_name", ["ac_daily", "ac_changes", "ac_acl", "ac_denied"]), 2))
    p.row(3, (counter("ac_state", "sum(direct_grants)", "Direct grants", "Current, selected catalogs"), 2),
             (counter("ac_state", "sum(broad_grants)", "Grants to all users", "account users / users", style=alert_if_positive(MEDIUM)), 2),
             (counter("ac_state", "sum(high_privilege_grants)", "High-privilege grants", "ALL PRIVILEGES, MANAGE, MODIFY, CREATE ..."), 2),
             (counter("ac_state", "sum(user_owned)", "Owned by individuals", "Securables owned by a user", style=alert_if_positive(MEDIUM)), 2),
             (daily_counter("ac_daily", "uc_grants", "Grants (period)"), 2),
             (daily_counter("ac_daily", "access_denied", "Denied data access"), 2))
    p.row(6, (bar("ac_grants", "securable_type", "count(grantee)", "Direct grants by securable and grantee type", "Securable", "Grants",
                  color="grantee_type", color_title="Grantee type"), 6),
             (bar("ac_top_grantees", "grantee", "sum(grants)", "Top grantees", "Grantee", "Direct grants", color="grantee_type",
                  color_title="Grantee type", description="All catalogs"), 6))
    p.row(6, (line("ac_daily", "event_date", [("sum(uc_grants)", "Grants"), ("sum(uc_revokes)", "Revokes"), ("sum(broad_grants)", "Grants to all users")],
                   "Unity Catalog grants and revokes per day", "Date", "Changes"), 6),
             (bar("ac_owners", "securable_type", "count(securable_name)", "Securable ownership", "Securable", "Securables",
                  color="owner_type", color_title="Owner type"), 6))
    p.row(7, (table("ac_grants", [col("securable_type", "Securable type"), col("securable_name", "Securable"), col("grantee", "Grantee"),
                                  col("grantee_type", "Grantee type"), col("privilege_type", "Privilege"),
                                  col("audience", "Audience", style=flag_style("⚠️ All users")),
                                  col("privilege_level", "Level", style=flag_style("⚠️ High")), col("grantor", "Granted by")],
                    "Current direct grants", "Broad and high-privilege grants first"), 12))
    p.row(7, (table("ac_changes", [col("event_time", "Time"), col("workspace_name", "Workspace"), col("actor", "Actor"),
                                   col("change_type", "Change"), col("privilege", "Privilege"), col("principal", "Principal"),
                                   col("audience", "Audience", style=flag_style("⚠️ All users")),
                                   col("securable_type", "Securable type"), col("securable_name", "Securable")],
                    "Unity Catalog permission changes"), 12))
    p.row(7, (table("ac_denied", [col("event_date", "Date"), col("workspace_name", "Workspace"), col("principal", "Principal"),
                                  col("securable_name", "Securable"), col("attempts", "Attempts"), col("error_message", "Error")],
                    "Denied data access"), 6),
             (table("ac_acl", [col("event_time", "Time"), col("workspace_name", "Workspace"), col("actor", "Actor"), col("object_type", "Object"),
                               col("object_id", "Object id"), col("target_principal", "Principal"), col("permission", "Permission")],
                    "Workspace object ACL changes"), 6))
    pages.append(p)

    # 5. Policies & data protection ------------------------------------------------------------
    p = Page("protection", "Policies & data protection")
    p.row(2, (header("🛡️ Policies & data protection", "ABAC policies, column masks, row filters, sensitive data coverage and policy history."), 6),
             (multi_filter("Catalog", "catalog_name", ["po_abac", "po_fgc", "po_sensitive"]), 3),
             (date_filter("Date (changes)", "event_date", ["po_changes"]), 3))
    p.row(3, (counter("po_state", "abac_policies", "ABAC policies", row=True), 2),
             (counter("po_state", "column_masks", "Column masks", row=True), 2),
             (counter("po_state", "row_filters", "Row filters", row=True), 2),
             (counter("po_state", "sensitive_columns", "Sensitive columns", "Auto-classified or tagged", row=True), 2),
             (counter("po_state", "unprotected_sensitive", "Unprotected sensitive", "No mask, no ABAC policy in scope",
                      style=alert_if_positive(), row=True), 2),
             (counter("po_changes", "count(event_time)", "Policy changes", "Selected period"), 2))
    p.row(6, (bar("po_sensitive", "classification", "count(column_name)", "Sensitive columns by classification", "Classification", "Columns",
                  color="protection_status", color_title="Protection",
                  mappings=[{"value": "⚠️ Unprotected", "color": HIGH}, {"value": "✅ Protected", "color": GOOD}]), 6),
             (bar("po_changes", "policy_kind", "count(event_time)", "Policy changes by kind", "Policy kind", "Changes",
                  color="change_class", color_title="Change", mappings=[{"value": "⚠️ Deleted", "color": HIGH}]), 6))
    p.row(6, (table("po_abac", [col("policy_name", "Policy"), col("policy_type", "Type"), col("on_securable_type", "On"), col("scope_name", "Scope"),
                                col("to_principals", "Applies to"), col("except_principals", "Except"), col("when_condition", "When"),
                                col("governed_tags", "Governed tags")], "ABAC policies"), 12))
    p.row(7, (table("po_sensitive", [col("protection_status", "Protection", style=flag_style("⚠️ Unprotected")), col("table_full_name", "Table"),
                                     col("column_name", "Column"), col("classification", "Classification"), col("source", "Source"),
                                     col("mask_name", "Mask")], "Sensitive columns"), 6),
             (table("po_fgc", [col("control_type", "Control"), col("table_full_name", "Table"), col("target", "Column(s)"),
                               col("function_name", "Function")], "Column masks & row filters"), 6))
    p.row(6, (table("po_changes", [col("event_time", "Time"), col("workspace_name", "Workspace"), col("actor", "Actor"),
                                   col("policy_kind", "Kind"), col("change_class", "Change", style=flag_style("⚠️ Deleted")),
                                   col("policy_name", "Policy"), col("policy_type", "Type"), col("scope_name", "Scope")],
                    "Policy change history"), 12))
    pages.append(p)

    # 6. Tags & metadata -----------------------------------------------------------------------
    p = Page("tags", "Tags & metadata")
    p.row(2, (header("🏷️ Tags & metadata", "Governed tags, tag assignments, tagging and documentation gaps (Governance Hub *Tags* view)."), 6),
             (multi_filter("Catalog", "catalog_name", ["tg_coverage", "tg_gaps"]), 3),
             (date_filter("Date (changes)", "event_date", ["tg_changes"]), 3))
    p.row(3, (counter("tg_coverage", "count(table_full_name)", "Tables & views"), 2),
             (counter("tg_coverage", "sum(tagged)", "Tagged", "Incl. tags inherited from schema / catalog"), 2),
             (counter("tg_coverage", "sum(documented)", "Documented", "With a description"), 2),
             (counter("tg_state", "governed_tags", "Governed tags", row=True), 2),
             (counter("tg_state", "tag_assignments", "Tag assignments", row=True), 2),
             (counter("tg_changes", "count(event_time)", "Tag changes", "Selected period"), 2))
    p.row(6, (bar("tg_coverage", "catalog_name", "count(table_full_name)", "Tagging coverage by catalog", "Catalog", "Tables",
                  color="tag_status", color_title="Tags", mappings=[{"value": "Untagged", "color": MEDIUM}, {"value": "Tagged", "color": GOOD}]), 6),
             (bar("tg_top_tags", "tag_name", "sum(assignments)", "Most used tag keys", "Tag", "Assignments",
                  color="securable_type", color_title="Level", description="Top 12 keys, all catalogs"), 6))
    p.row(6, (line("tg_changes", "daily(event_date)", "count(event_time)", "Tag changes per day", "Date", "Changes",
                   color="change_type", color_title="Change"), 6),
             (bar("tg_coverage", "catalog_name", "count(table_full_name)", "Documentation coverage by catalog", "Catalog", "Tables",
                  color="doc_status", color_title="Description",
                  mappings=[{"value": "No description", "color": MEDIUM}, {"value": "Documented", "color": GOOD}]), 6))
    p.row(7, (table("tg_gaps", [col("table_full_name", "Table"), col("table_owner", "Owner"), col("readers_30d", "Readers (30d)"),
                                col("reads_30d", "Reads (30d)"), col("tag_status", "Tags", style=flag_style("⚠️ Untagged")),
                                col("doc_status", "Description", style=flag_style("⚠️ No description")),
                                col("sensitive_column_count", "Sensitive columns")],
                    "Popular tables missing tags or descriptions", "Most-read tables first (Governance Hub recommendation)"), 12))
    p.row(6, (table("tg_changes", [col("event_time", "Time"), col("actor", "Actor"), col("change_type", "Change"), col("tag_name", "Tag"),
                                   col("tag_value", "Value"), col("tag_class", "Class", style=flag_style("⚠️ Classification")),
                                   col("securable_type", "Securable type"), col("securable_name", "Securable"), col("column_name", "Column")],
                    "Tag change history"), 12))
    pages.append(p)

    # 7. Data activity & sharing ---------------------------------------------------------------
    ex = ["ex_daily", "ex_export_daily", "ex_exports", "ex_secrets", "ex_sharing_act"]
    p = Page("activity", "Data activity & sharing")
    p.row(2, (header("📤 Data activity, exfiltration & sharing", "Downloads and exports, secrets usage and Delta Sharing exposure."), 6),
             (date_filter("Date", "event_date", ex), 3), (multi_filter("Workspace", "workspace_name", ex), 3))
    p.row(3, (daily_counter("ex_daily", "interactive_exports", "Interactive exports", "Downloads / exports by people"), 2),
             (daily_counter("ex_daily", "automated_exports", "Automated exports", "CLI, SDK and services"), 2),
             (daily_counter("ex_daily", "secret_reads", "Secret reads"), 2),
             (daily_counter("ex_daily", "secret_failures", "Secret access failures", style=alert_if_positive(MEDIUM)), 2),
             (counter("ex_sharing", "sum(open_recipient)", "Open-sharing recipients", "Token-based, outside Databricks"), 2),
             (counter("ex_sharing", "sum(open_without_ip_list)", "Open recipients w/o IP list", style=alert_if_positive()), 2))
    p.row(6, (line("ex_export_daily", "event_date", "sum(events)", "Interactive exports per day by channel", "Date", "Exports",
                   color="export_channel", color_title="Channel"), 6),
             (bar("ex_top_exporters", "principal", "sum(exports)", "Top interactive exporters", "Principal", "Exports",
                  color="export_channel", color_title="Channel", description="Last 30 days, all workspaces"), 6))
    p.row(7, (table("ex_exports", [col("event_time", "Time"), col("workspace_name", "Workspace"), col("principal", "Principal"),
                                   col("export_channel", "Channel"), col("action_name", "Action"), col("object_ref", "Object"),
                                   col("export_format", "Format"), col("source_ip", "Source IP")], "Interactive export events"), 12))
    p.row(6, (table("ex_sharing", [col("recipient_name", "Recipient"), col("exposure", "Exposure", style=flag_style("⚠️ Open, no IP list")),
                                   col("shares_granted", "Shares"), col("share_names", "Share names"), col("ip_allowlist_ranges", "IP ranges"),
                                   col("token_expiration", "Token expires"), col("recipient_owner", "Owner")], "Delta Sharing recipients"), 6),
             (table("ex_secrets", [col("event_date", "Date"), col("workspace_name", "Workspace"), col("principal", "Principal"),
                                   col("action_name", "Action"), col("secret_scope", "Scope"), col("events", "Events"), col("failures", "Failures")],
                    "Secret access"), 6))
    p.row(6, (table("ex_sharing_act", [col("event_date", "Date"), col("activity_type", "Activity"), col("action_name", "Action"),
                                       col("principal", "Recipient / actor"), col("share_name", "Share"), col("object_name", "Object"),
                                       col("events", "Events"), col("ip_denied_events", "IP denied")], "Delta Sharing activity"), 12))
    pages.append(p)

    # 8. Compute, network & configuration ------------------------------------------------------
    cn = ["cn_compute", "cn_network", "cn_config", "cn_config_changes"]
    p = Page("platform", "Compute, network & config")
    p.row(2, (header("🌐 Compute, network & workspace configuration",
                     "Cluster access modes and policies, network policy denials and workspace security settings."), 6),
             (date_filter("Date (network & changes)", "event_date", ["cn_network", "cn_config_changes"]), 3),
             (multi_filter("Workspace", "workspace_name", cn), 3))
    p.row(3, (counter("cn_compute", "count(cluster_id)", "Interactive clusters"), 2),
             (counter("cn_compute", "sum(not_uc_secured)", "Not UC-secured", "No isolation / legacy access mode", style=alert_if_positive()), 2),
             (counter("cn_compute", "sum(without_policy)", "Without compute policy", style=alert_if_positive(LOW)), 2),
             (counter("cn_compute", "sum(old_runtime)", "Runtime < 13", style=alert_if_positive(MEDIUM)), 2),
             (counter("cn_network", "sum(denied_events)", "Network denials"), 2),
             (counter("cn_config", "sum(risky)", "Risky settings", "Last known value per workspace", style=alert_if_positive()), 2))
    p.row(6, (bar("cn_compute", "access_mode", "count(cluster_id)", "Interactive clusters by access mode", "Access mode", "Clusters"), 4),
             (bar("cn_top_denied", "target", "sum(denials)", "Top denied network targets", "Target", "Denials", color="direction",
                  color_title="Direction", description="Last 30 days"), 4),
             (bar("cn_config", "setting_name", "count(setting_value)", "Security settings by status", "Setting", "Workspaces",
                  color="setting_status", color_title="Status",
                  mappings=[{"value": "⚠️ Risky", "color": HIGH}, {"value": "✅ OK", "color": GOOD}]), 4))
    p.row(7, (table("cn_config", [col("setting_status", "Status", style=flag_style("⚠️ Risky")), col("workspace_name", "Workspace"),
                                  col("setting_name", "Setting"), col("setting_value", "Value"), col("last_changed", "Changed"),
                                  col("last_changed_by", "By")], "Workspace security settings (last known value)",
                    "Reconstructed from audit log changes within retention"), 6),
             (table("cn_config_changes", [col("event_time", "Time"), col("workspace_name", "Workspace"), col("actor", "Actor"),
                                          col("setting_name", "Setting"), col("setting_value", "Value"),
                                          col("setting_status", "Status", style=flag_style("⚠️ Risky"))], "Security setting changes"), 6))
    p.row(7, (table("cn_compute", [col("workspace_name", "Workspace"), col("cluster_name", "Cluster"), col("owned_by", "Owner"),
                                   col("access_mode", "Access mode"), col("uc_secured", "UC secured", style=flag_style("⚠️ No")),
                                   col("policy", "Policy", style=flag_style("⚠️ No")), col("dbr_version", "Runtime"),
                                   col("init_script_count", "Init scripts")], "Interactive clusters"), 12))
    pages.append(p)

    used = sorted({q["query"]["datasetName"] for pg in pages for l in pg.layout for q in l["widget"].get("queries", [])})
    unused = sorted(set(DATASETS) - set(used))
    assert not unused, f"unused datasets: {unused}"
    return {"datasets": [dataset(n) for n in used], "pages": [pg.to_json() for pg in pages],
            "uiSettings": {"theme": THEME, "genieSpace": {"isEnabled": True, "overrideId": GENIE_ID_REF, "enablementMode": "ENABLED"}}}


def main():
    d = build()
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    widgets = sum(len(p["layout"]) for p in d["pages"])
    print(f"wrote {OUT_JSON}: {len(d['datasets'])} datasets, {widgets} widgets, {len(d['pages'])} pages")


if __name__ == "__main__":
    main()
