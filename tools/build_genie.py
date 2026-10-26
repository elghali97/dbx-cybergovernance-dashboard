#!/usr/bin/env python3
"""Generate resources/genie_space.yml (bundle GenieSpace resource) with the serialized space inline.

Table identifiers and SQL use ${var.catalog}.${var.schema} so the bundle interpolates them per target.
"""
import hashlib
import json
import os

OUT = os.path.join(os.path.dirname(__file__), "..", "resources", "genie_space.yml")
FQ = "${var.catalog}.${var.schema}"

TABLES = [  # Genie agents take at most 30 tables / views
    "security_findings_latest", "check_results", "posture_score", "posture_trend", "activity_kpis_daily", "weekly_activity_kpis",
    "auth_events_daily", "failed_auth_events", "identity_changes", "token_events",
    "uc_grants", "securable_owners", "uc_permission_changes", "workspace_acl_changes", "access_denied_daily",
    "abac_policies", "sensitive_columns", "table_governance_coverage", "tag_assignments", "tag_changes", "policy_changes",
    "data_export_events", "secret_access_daily", "table_access_activity", "delta_sharing_posture", "delta_sharing_activity_daily",
    "network_events_daily", "workspace_config_latest", "workspace_config_changes", "compute_posture",
]

INSTRUCTIONS = """You are the Databricks security posture analyst for the Cybersecurity team. All data comes from Databricks system tables (audit logs, Unity Catalog information_schema, lineage, compute and network tables) and is refreshed several times a day by the Security Posture job. The same data powers the "Databricks Security Posture" dashboard.

Periods:
- "This week" = the current ISO week starting Monday (date_trunc('WEEK', current_date())). "Last week" = the previous complete Monday-Sunday week. If no period is given for activity questions, use the last 7 days and say so.
- weekly_activity_kpis gives one value per ISO week and metric (all workspaces); activity_kpis_daily gives the same metrics per day and workspace.

Posture:
- Current findings are in security_findings_latest (one row per failing check and object; mention refreshed_at). check_results gives every check with status PASS / FAIL, findings and the check metadata. posture_score gives the score per category and overall (category = 'ALL'); score is between 0 and 1, score_pct between 0 and 100. posture_trend gives the daily history.
- Severity order is HIGH > MEDIUM > LOW: sort findings by severity_order then detected_at descending.
- When you recommend an action, quote the recommendation and give the documentation link (doc_url) and the best-practice link (best_practice_url) of the check. sat_reference is the closest Security Analysis Tool check id.

Access and identities:
- grantee_type / owner_type / principal_type is USER (email), SERVICE_PRINCIPAL (application id UUID) or GROUP. is_broad_principal = TRUE means the grant targets every user (account users / users) and is a risk.
- For "who has access to <table>": use uc_grants where securable_name is the full table name OR its schema (catalog.schema) OR its catalog, because privileges are inherited; add the owner from securable_owners and explain the inheritance.
- For "who accessed / read <table>": use table_access_activity (lineage-based reads and writes per principal and day).
- identity_changes.is_privileged flags admin grants; exclude is_removal = TRUE when asked about grants.

Data protection:
- A sensitive column (sensitive_columns) is protected when is_masked = TRUE or its table has has_abac_policy_in_scope = TRUE in table_governance_coverage.
- data_export_events contains only interactive (human) downloads and exports.

Rules:
- Event tables and views have event_date: always filter on it.
- workspace_config_latest is reconstructed from audit log changes: say "last known value", not "current value".
- Never speculate beyond the data and never infer intent (for example compromise) from counts alone; if a query returns no rows, say that no evidence was found in system tables for the period."""

EXAMPLES = [
    ("Summarise our security posture for last week",
     f"WITH w AS (SELECT CAST(date_trunc('WEEK', current_date()) AS DATE) - 7 AS last_week)\n"
     f"SELECT s.category, s.score_pct, s.checks_failed, s.high_findings, s.medium_findings, s.low_findings,\n"
     f"       (SELECT score_pct FROM {FQ}.posture_trend t, w WHERE t.snapshot_date <= w.last_week ORDER BY t.snapshot_date DESC LIMIT 1) AS overall_score_pct_a_week_ago\n"
     f"FROM {FQ}.posture_score s\n"
     f"ORDER BY s.category = 'ALL' DESC, s.score_pct"),
    ("List the HIGH severity findings and what to do about them",
     f"SELECT check_id, title, workspace_name, object_type, object_name, detail, recommendation, doc_url, best_practice_url, refreshed_at\n"
     f"FROM {FQ}.security_findings_latest\nWHERE severity = 'HIGH'\nORDER BY check_id, detected_at DESC"),
    ("Which checks are failing?",
     f"SELECT check_id, category, severity, title, findings, affected_workspaces, recommendation, doc_url\n"
     f"FROM {FQ}.check_results\nWHERE status = 'FAIL'\nORDER BY severity_order, findings DESC"),
    ("How did security activity change last week compared with the week before?",
     f"WITH w AS (SELECT CAST(date_trunc('WEEK', current_date()) AS DATE) - 7 AS last_week)\n"
     f"SELECT k.metric_label,\n"
     f"       sum(CASE WHEN k.week_start = w.last_week THEN k.value ELSE 0 END) AS last_week,\n"
     f"       sum(CASE WHEN k.week_start = w.last_week - 7 THEN k.value ELSE 0 END) AS week_before\n"
     f"FROM {FQ}.weekly_activity_kpis k, w\nGROUP BY k.metric_label, k.metric_order\nORDER BY k.metric_order"),
    ("Who was granted admin rights in the last 7 days?",
     f"SELECT event_time, workspace_name, actor, action_name, target, group_name, assigned_permissions\n"
     f"FROM {FQ}.identity_changes\nWHERE is_privileged AND NOT is_removal AND event_date >= current_date() - 7\nORDER BY event_time DESC"),
    ("Which grants were given to all users in the last 30 days?",
     f"SELECT event_time, workspace_name, actor, securable_type, securable_name, privilege, principal\n"
     f"FROM {FQ}.uc_permission_changes\n"
     f"WHERE change_type = 'GRANT' AND is_broad_principal AND event_date >= current_date() - 30 AND coalesce(status_code, 200) < 400\n"
     f"ORDER BY event_time DESC"),
    ("Who has access to main.finance.transactions?",
     f"SELECT g.securable_type AS granted_on, g.securable_name, g.grantee, g.grantee_type, g.privilege_type\n"
     f"FROM {FQ}.uc_grants g\n"
     f"WHERE g.is_direct AND g.securable_name IN ('main.finance.transactions', 'main.finance', 'main')\n"
     f"UNION ALL\n"
     f"SELECT 'OWNER', securable_name, owner, owner_type, 'OWNER'\n"
     f"FROM {FQ}.securable_owners WHERE securable_name = 'main.finance.transactions'"),
    ("Which sensitive columns are not protected by a mask or an ABAC policy?",
     f"SELECT s.table_full_name, s.column_name, s.classification, s.source, c.table_owner\n"
     f"FROM {FQ}.sensitive_columns s\n"
     f"LEFT JOIN {FQ}.table_governance_coverage c ON c.table_full_name = s.table_full_name\n"
     f"WHERE NOT s.is_masked AND NOT coalesce(c.has_abac_policy_in_scope, FALSE)\n"
     f"ORDER BY s.table_full_name, s.column_name"),
    ("Who exported or downloaded the most data this week?",
     f"SELECT principal, workspace_name, export_channel, count(*) AS exports, max(event_time) AS last_export\n"
     f"FROM {FQ}.data_export_events\n"
     f"WHERE event_date >= date_trunc('WEEK', current_date())\n"
     f"GROUP BY principal, workspace_name, export_channel\nORDER BY exports DESC\nLIMIT 20"),
    ("Which security policies, classification tags or risky settings changed last week, and who changed them?",
     f"WITH w AS (SELECT CAST(date_trunc('WEEK', current_date()) AS DATE) - 7 AS d)\n"
     f"SELECT 'Policy' AS change, event_time, workspace_name, actor, concat(policy_kind, ' ', action_name, ' ', coalesce(policy_name, '')) AS what\n"
     f"FROM {FQ}.policy_changes, w WHERE event_date >= w.d AND event_date < w.d + 7\n"
     f"UNION ALL\n"
     f"SELECT 'Classification tag', event_time, workspace_name, actor, concat(change_type, ' ', tag_name, ' on ', securable_name)\n"
     f"FROM {FQ}.tag_changes, w WHERE is_classification_tag AND event_date >= w.d AND event_date < w.d + 7\n"
     f"UNION ALL\n"
     f"SELECT 'Risky setting', event_time, workspace_name, actor, concat(setting_name, ' = ', setting_value)\n"
     f"FROM {FQ}.workspace_config_changes, w WHERE is_risky_value AND event_date >= w.d AND event_date < w.d + 7\n"
     f"ORDER BY event_time DESC"),
    ("Which human users still authenticate with personal access tokens?",
     f"SELECT principal, workspace_name, sum(events) AS pat_requests, max(event_date) AS last_seen\n"
     f"FROM {FQ}.auth_events_daily\n"
     f"WHERE auth_category = 'PAT' AND principal_type = 'USER' AND event_date >= current_date() - 30\n"
     f"GROUP BY principal, workspace_name\nORDER BY pat_requests DESC"),
]

SAMPLE_QUESTIONS = [
    "Summarise our security posture for last week",
    "List the HIGH severity findings and what to do about them",
    "Who was granted admin rights in the last 7 days?",
    "Which sensitive columns are not protected by a mask or an ABAC policy?",
    "Who exported or downloaded the most data this week?",
    "Who has access to <catalog.schema.table>?",
]


def _id(key):
    return hashlib.md5(key.encode()).hexdigest()


def serialized_space():
    return {
        "version": 2,
        "config": {"sample_questions": sorted(
            [{"id": _id("q" + q), "question": [q]} for q in SAMPLE_QUESTIONS], key=lambda x: x["id"])},
        "data_sources": {"tables": [{"identifier": f"{FQ}.{t}"} for t in sorted(TABLES)]},
        "instructions": {
            "text_instructions": [{"id": _id("instructions"), "content": [l + "\n" for l in INSTRUCTIONS.split("\n")]}],
            "example_question_sqls": sorted(
                [{"id": _id("e" + q), "question": [q], "sql": [l + "\n" for l in sql.split("\n")]} for q, sql in EXAMPLES],
                key=lambda x: x["id"]),
        },
    }


def main():
    body = json.dumps(serialized_space(), indent=2)
    indented = "\n".join("        " + l for l in body.split("\n"))
    yml = f"""# Generated by tools/build_genie.py - do not edit by hand.
resources:
  genie_spaces:
    security_posture_genie:
      title: "Security Posture Analyst"
      description: "Ask questions about Databricks access control, policies, tags, identities and security findings. Data from system tables only."
      warehouse_id: ${{var.warehouse_id}}
      serialized_space: |
{indented}
      permissions:
        - level: CAN_RUN
          group_name: ${{var.security_group}}
"""
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT, "w").write(yml)
    print(f"wrote {OUT}: {len(TABLES)} tables, {len(EXAMPLES)} example SQLs")


if __name__ == "__main__":
    main()
