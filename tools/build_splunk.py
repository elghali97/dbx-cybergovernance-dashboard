#!/usr/bin/env python3
"""Generate the Splunk app of the Security Posture bundle (splunk/databricks_security_posture).

Two Simple XML dashboards and four alerts, querying the bundle's schema through the `databricksquery` command of the
Databricks Add-on for Splunk (TA-Databricks, https://github.com/databrickslabs/splunk-integration):

  databricks_security_live.xml     near real-time activity: live_* views reading system.access.audit at query time
  databricks_security_posture.xml  posture score, checks and findings: tables refreshed by the bundle's job
  savedsearches.conf               alerts on the live views (disabled until enabled in Splunk)

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
VERSION = "1.2.0"
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
    time_search = (f'<search id="window"><query><![CDATA[{TIME_SEARCH}]]></query>'
                   "<earliest>$time.earliest$</earliest><latest>$time.latest$</latest>"
                   "<done><set token=\"t_from\">$result.t_from$</set><set token=\"t_to\">$result.t_to$</set>"
                   "<set token=\"t_span\">$result.t_span$</set><set token=\"t_span_label\">$result.t_span_label$</set></done>"
                   "</search>")
    actor_search = (f"<search><query><![CDATA[{ACTOR_SEARCH}]]></query>"
                    '<done><set token="actor_like">$result.v$</set></done></search>')
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
  {actor_search}
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
  <description>Security posture of the Databricks estate: 32 checks modelled on the Security Analysis Tool, scored and refreshed by the Databricks Security Posture job (every 6 hours by default). Click a check title for the Databricks security best practice, a recommendation for the remediation documentation.</description>
  {init_tokens(cfg)}
  {kpi}
  {fieldset}
  {row(
      single("Posture score", "kpi", "| fields score_pct", "weighted share of passing checks", [HIGH, INFO, GOOD], [50, 80], "%"),
      single("Change vs 7 days ago", "kpi", "| eval v=round(score_pct - score_pct_7d_ago, 1) | fields v", "score points",
             [HIGH, INFO, GOOD], [-0.05, 0.05]),
      single("Checks failing", "kpi", "| eval v=checks_failed | fields v", "of 32 checks", [GOOD, MEDIUM], [0]),
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
            "<li>Ask questions in natural language: the <b>Security Posture Analyst</b> Genie agent in Databricks.</li></ul>"))}
</form>"""
    return xml


# ----------------------------------------------------------------------------- alerts
ALERT_WINDOW = ("event_date >= CAST(current_timestamp() - INTERVAL 1 DAY AS DATE) "
                "AND event_time >= current_timestamp() - INTERVAL {minutes} MINUTES")
ALERTS = [
    ("Databricks - HIGH security signal",
     "Every HIGH signal of the live feed: admin rights granted, PAT without expiry, high privilege granted to all users, "
     "IP access list deleted, ABAC policy deleted, open-sharing token retrieved. One alert per event.",
     f"""SELECT event_id, unix_timestamp(event_time) AS epoch, workspace_name, category, actor, action_name, target, detail, source_ip
         FROM $sp$.live_security_events WHERE {ALERT_WINDOW.format(minutes=45)} AND signal = 'HIGH'""",
     "event_id"),
    ("Databricks - Failed authentication burst",
     "20 or more failed authentications for the same principal and source IP within the last hour (brute force, leaked or "
     "expired credentials).",
     f"""SELECT actor, source_ip, count(*) AS failures, array_join(slice(collect_set(detail), 1, 3), ' | ') AS errors,
                max(unix_timestamp(event_time)) AS epoch
         FROM $sp$.live_security_events WHERE {ALERT_WINDOW.format(minutes=60)}
           AND category IN ('Authentication failure', 'IP access blocked')
         GROUP BY actor, source_ip HAVING count(*) >= 20""",
     "actor,source_ip"),
    ("Databricks - Mass interactive data export",
     "20 or more interactive downloads / exports by the same person within the last hour (possible exfiltration).",
     f"""SELECT actor, count(*) AS exports, count(DISTINCT target) AS objects,
                array_join(slice(collect_set(detail), 1, 5), ', ') AS channels, max(unix_timestamp(event_time)) AS epoch
         FROM $sp$.live_security_events WHERE {ALERT_WINDOW.format(minutes=60)} AND category = 'Data export'
         GROUP BY actor HAVING count(*) >= 20""",
     "actor"),
    ("Databricks - Denied data access burst",
     "50 or more denied Unity Catalog / SQL requests by the same principal within the last hour (probing, privilege "
     "escalation attempts or a broken pipeline).",
     f"""SELECT principal, count(*) AS attempts, count(DISTINCT securable_name) AS securables,
                array_join(slice(collect_set(securable_name), 1, 5), ', ') AS sample_securables,
                max(unix_timestamp(event_time)) AS epoch
         FROM $sp$.live_access_denied_events WHERE {ALERT_WINDOW.format(minutes=60)}
         GROUP BY principal HAVING count(*) >= 50""",
     "principal"),
]


def savedsearches(cfg):
    warehouse = f' warehouse_id="{cfg["warehouse_id"]}"' if cfg["warehouse_id"] else ""
    out = ["# Generated by tools/build_splunk.py - alerts on the live views of the Databricks Security Posture bundle.",
           "# Disabled by default: enable them in Settings > Searches, reports, and alerts, and add an action (email, ...).",
           "# Every 15 minutes over the last 45-60 minutes (audit events arrive ~10 minutes late); suppression on the listed",
           "# fields avoids alerting twice on the same event / principal.", ""]
    for name, description, query, suppress in ALERTS:
        spl = (f'| databricksquery account_name="{cfg["account"]}"{warehouse} command_timeout=300 '
               f'query="{sql(query.replace("$sp$", cfg["schema"]))}" | eval _time=tonumber(epoch) | fields - epoch')
        out += [f"[{name}]", f"description = {description}", f"search = {spl}", "disabled = 1",
                "cron_schedule = */15 * * * *", "enableSched = 1", "dispatch.earliest_time = -1h", "dispatch.latest_time = now",
                "counttype = number of events", "relation = greater than", "quantity = 0",
                "alert.track = 1", "alert.severity = 4" if "HIGH" in name else "alert.severity = 3",
                "alert.digest_mode = 0", "alert.suppress = 1", f"alert.suppress.fields = {suppress}",
                "alert.suppress.period = 2h", "action.email.useNSSubject = 1", ""]
    return "\n".join(out)


# ----------------------------------------------------------------------------- app
def app_files(cfg):
    return {
        "default/app.conf": f"""# Generated by tools/build_splunk.py
[install]
is_configured = 1

[launcher]
author = Databricks field engineering
description = Databricks security posture and near real-time security activity, from Databricks system tables through the Databricks Add-on for Splunk (TA-Databricks).
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
  <view name="databricks_security_posture" />
  <view name="search" />
  <a href="alerts">Alerts</a>
</nav>
""",
        "default/data/ui/views/databricks_security_live.xml": live_dashboard(cfg),
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
    print(f"wrote {app_dir}: 2 dashboards, {len(ALERTS)} alerts (account {args.account}, schema {args.schema})")
    if args.package:
        package = os.path.join(out, f"{APP}-{VERSION}.tar.gz")
        with tarfile.open(package, "w:gz") as tar:
            tar.add(app_dir, arcname=APP)
        print(f"wrote {package}: Splunk > Apps > Manage Apps > Install app from file")


if __name__ == "__main__":
    main()
