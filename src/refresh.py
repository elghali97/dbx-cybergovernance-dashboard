"""Security Posture refresh job (serverless spark_python_task).

0. Preflight: checks access to the system tables, creates the catalog / schema if needed and grants the
   readers group USE SCHEMA + SELECT. Optional system tables that are not enabled or not granted are replaced
   by an empty result with the same columns (the related dashboard tiles stay empty instead of failing).
1. Creates the src_* views over system tables (sql/10_sources.sql).
2. Rebuilds the state tables (Unity Catalog grants, owners, tags, policies, compute) from their src_* view.
3. Loads the activity tables incrementally: the last --reprocess-days days are replaced atomically
   (INSERT ... REPLACE WHERE), the first load back-fills --events-backfill-days / --activity-backfill-days,
   rows older than --retention-days are purged. A table whose schema no longer matches its src_* view is rebuilt.
4. Creates the semantic views and checks (sql/20_*.sql, sql/30_*.sql).
5. Materialises security_findings_latest and the daily posture snapshot.
"""
import argparse
import glob
import os
import re
import time
from datetime import date, timedelta

# Required: without them there is nothing to analyse.
REQUIRED_SOURCES = ["system.access.audit", "system.information_schema.catalogs"]

# Optional: Public Preview / Beta tables or schemas that may not be enabled or granted. Fallback = same columns, no rows.
NULL = "CAST(NULL AS {}) AS {}"
OPTIONAL_SOURCES = {
    "system.access.workspaces_latest": [("STRING", "workspace_id"), ("STRING", "workspace_name"), ("STRING", "workspace_url"),
                                        ("STRING", "status"), ("TIMESTAMP", "create_time")],
    "system.access.table_lineage": [("DATE", "event_date"), ("TIMESTAMP", "event_time"), ("STRING", "workspace_id"),
                                    ("STRING", "created_by"), ("STRING", "entity_type"), ("STRING", "source_table_full_name"),
                                    ("STRING", "target_table_full_name")],
    "system.access.inbound_network": [("TIMESTAMP", "event_time"), ("STRING", "workspace_id"), ("STRING", "policy_outcome"),
                                      ("STRING", "rule_label"), ("STRING", "request_path"), ("STRUCT<ip: STRING>", "source"),
                                      ("STRING", "authenticated_as")],
    "system.access.outbound_network": [("TIMESTAMP", "event_time"), ("STRING", "workspace_id"), ("STRING", "access_type"),
                                       ("STRING", "network_source_type"), ("STRING", "destination"),
                                       ("STRUCT<rejection_reason: STRING, hostname: STRING>", "storage_event"),
                                       ("STRUCT<domain_name: STRING>", "dns_event")],
    "system.tags.governed_tags": [("STRING", "tag_key"), ("STRING", "id"), ("TIMESTAMP", "change_time"), ("TIMESTAMP", "deleted_at")],
    "system.data_classification.results": [("STRING", "catalog_name"), ("STRING", "schema_name"), ("STRING", "table_name"),
                                           ("STRING", "column_name"), ("STRING", "class_tag"), ("STRING", "confidence"),
                                           ("TIMESTAMP", "latest_detected_time"), ("STRING", "exclusion_state")],
    "system.compute.clusters": [("STRING", "workspace_id"), ("STRING", "cluster_id"), ("STRING", "cluster_name"),
                                ("STRING", "owned_by"), ("STRING", "cluster_source"), ("TIMESTAMP", "create_time"),
                                ("TIMESTAMP", "change_time"), ("TIMESTAMP", "delete_time"), ("STRING", "data_security_mode"),
                                ("STRING", "policy_id"), ("ARRAY<STRING>", "init_scripts"), ("STRING", "dbr_version"),
                                ("BIGINT", "auto_termination_minutes"), ("STRUCT<instance_profile_arn: STRING>", "aws_attributes")],
}
GRANT_HINT = """Ask a metastore admin to run setup/grants.sql, or at least:
  GRANT USE CATALOG ON CATALOG system TO `{who}`;
  GRANT USE SCHEMA, SELECT ON SCHEMA system.access TO `{who}`;
  GRANT USE SCHEMA, SELECT ON SCHEMA system.compute TO `{who}`;
  GRANT USE SCHEMA, SELECT ON SCHEMA system.tags TO `{who}`;"""

# Rebuilt on every run, in dependency order (src view = "src_" + name).
STATE_TABLES = [
    "workspaces", "governed_tags", "uc_grants", "securable_owners", "tag_assignments", "abac_policies",
    "fine_grained_controls", "sensitive_columns", "table_governance_coverage", "delta_sharing_posture", "compute_posture",
]
# Loaded incrementally on event_date. Value = which back-fill window applies on first load.
ACTIVITY_TABLES = {
    "audit_security_events": "events",
    "auth_events_daily": "activity",
    "access_denied_daily": "activity",
    "secret_access_daily": "activity",
    "data_export_daily": "activity",
    "delta_sharing_activity_daily": "activity",
    "network_events_daily": "activity",
    "table_access_activity": "activity",
}

# __file__ is not defined when run as a job spark_python_task; the job passes --sql-dir instead.
SQL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sql") if "__file__" in globals() else None


def render(text, catalog, schema, missing_sources=()):
    """Fill ${catalog} / ${schema}; ${source:<table>} becomes the table, or an empty typed result if it is missing."""
    def source(m):
        table = m.group(1)
        if table not in missing_sources:
            return table
        return "(SELECT " + ", ".join(NULL.format(t, c) for t, c in OPTIONAL_SOURCES[table]) + " WHERE 1 = 0)"
    text = re.sub(r"\$\{source:([\w.]+)\}", source, text)
    return text.replace("${catalog}", catalog).replace("${schema}", schema)


def statements(text):
    for stmt in re.split(r"\n;\s*(?:\n|$)", text + "\n"):
        body = "\n".join(l for l in stmt.splitlines() if not l.strip().startswith("--")).strip().rstrip(";")
        if body:
            yield body


def object_name(stmt):
    m = re.search(r"(?:VIEW|TABLE|SCHEMA)\s+(?:IF NOT EXISTS\s+)?(\S+)", stmt)
    return m.group(1) if m else stmt[:60]


class Refresher:
    def __init__(self, spark, args):
        self.spark, self.args = spark, args
        self.fq = f"`{args.catalog}`.`{args.schema}`"
        self.timings = []
        self.missing_sources = []

    def sql(self, stmt, **params):
        return self.spark.sql(stmt, args=params or None)

    def step(self, name, fn):
        start = time.time()
        result = fn()
        self.timings.append((name, round(time.time() - start, 1), result))
        print(f"{name:<45} {self.timings[-1][1]:>7}s  {'' if result is None else result}", flush=True)
        return result

    def can_read(self, table):
        try:
            self.sql(f"SELECT 1 FROM {table} LIMIT 1").collect()
            return True
        except Exception:
            return False

    def preflight(self):
        """Fails with an actionable message when required access is missing; returns the optional tables to stub."""
        who = self.sql("SELECT current_user() AS u").first()["u"]
        missing = [t for t in REQUIRED_SOURCES if not self.can_read(t)]
        if missing:
            raise RuntimeError(f"Cannot read {', '.join(missing)} as {who}.\n" + GRANT_HINT.format(who=who))
        self.missing_sources = [t for t in OPTIONAL_SOURCES if not self.can_read(t)]
        for t in self.missing_sources:
            print(f"WARNING {t} is not enabled or not granted to {who}: the related views will be empty.")

        catalog, schema = self.args.catalog, self.args.schema
        if not self.sql("SHOW CATALOGS LIKE :c", c=catalog).collect():
            try:
                self.sql(f"CREATE CATALOG IF NOT EXISTS `{catalog}` COMMENT 'Security posture (Databricks Security Posture bundle)'")
                print(f"created catalog {catalog}")
            except Exception as e:
                raise RuntimeError(f"Catalog {catalog} does not exist and {who} cannot create it ({type(e).__name__}). "
                                   f"Create it (or pick an existing catalog in config.yml) and grant {who} USE CATALOG + CREATE SCHEMA.")
        self.sql(f"CREATE SCHEMA IF NOT EXISTS {self.fq} COMMENT 'Security posture semantic layer over Databricks system tables'")
        group = self.args.readers_group
        if group:
            for stmt in (f"GRANT USE SCHEMA, SELECT ON SCHEMA {self.fq} TO `{group}`", f"GRANT USE CATALOG ON CATALOG `{catalog}` TO `{group}`"):
                try:
                    self.sql(stmt)
                except Exception as e:
                    print(f"WARNING could not run [{stmt}]: {str(e).splitlines()[0][:200]}. Grant it manually.")
        return f"as {who}; optional sources missing: {len(self.missing_sources)}"

    def run_sql_files(self, prefix):
        failures = []
        for path in sorted(glob.glob(os.path.join(self.args.sql_dir, f"{prefix}*.sql"))):
            for stmt in statements(render(open(path).read(), self.args.catalog, self.args.schema, self.missing_sources)):
                try:
                    self.sql(stmt)
                except Exception as e:
                    print(f"FAIL {object_name(stmt)}: {str(e)[:800]}")
                    failures.append(object_name(stmt))
        if failures:
            raise RuntimeError(f"{len(failures)} statement(s) failed: {failures}")
        return "ok"

    def exists(self, name):
        return self.spark.catalog.tableExists(f"{self.args.catalog}.{self.args.schema}.{name}")

    def comment_of(self, name):
        """Comment of a table / view, escaped for use inside a SQL string literal."""
        rows = self.sql(f"SELECT comment FROM `{self.args.catalog}`.information_schema.tables "
                        "WHERE table_schema = :s AND table_name = :t", s=self.args.schema, t=name).collect()
        return ((rows[0]["comment"] or "") if rows else "").replace("\\", "\\\\").replace("'", "\\'")

    def drop_if_view(self, name):
        """Upgrade path: objects that used to be views are now tables."""
        rows = self.sql(f"SELECT table_type FROM `{self.args.catalog}`.information_schema.tables "
                        "WHERE table_schema = :s AND table_name = :t", s=self.args.schema, t=name).collect()
        if rows and rows[0]["table_type"] == "VIEW":
            self.sql(f"DROP VIEW {self.fq}.{name}")

    def schema_of(self, name):
        return [(f.name, f.dataType.simpleString()) for f in self.spark.table(f"{self.fq}.`{name}`").schema.fields]

    def rebuild_state(self, name):
        self.drop_if_view(name)
        self.sql(f"CREATE OR REPLACE TABLE {self.fq}.{name} COMMENT '{self.comment_of(f'src_{name}')}' "
                 f"AS SELECT * FROM {self.fq}.src_{name}")
        return f"{self.spark.table(f'{self.fq}.{name}').count()} rows"

    def load_activity(self, name, kind):
        backfill = self.args.events_backfill_days if kind == "events" else self.args.activity_backfill_days
        start = date.today() - timedelta(days=backfill)
        src = f"{self.fq}.src_{name}"
        self.drop_if_view(name)
        if not self.exists(name) or self.schema_of(name) != self.schema_of(f"src_{name}"):
            self.sql(f"CREATE OR REPLACE TABLE {self.fq}.{name} CLUSTER BY (event_date) COMMENT '{self.comment_of(f'src_{name}')}' "
                     f"AS SELECT * FROM {src} WHERE event_date >= DATE'{start}'")
            mode = f"full load from {start}"
        else:
            last = self.sql(f"SELECT max(event_date) AS d FROM {self.fq}.{name}").first()["d"]
            since = max(start, (last or start) - timedelta(days=self.args.reprocess_days))
            self.sql(f"INSERT INTO {self.fq}.{name} REPLACE WHERE event_date >= DATE'{since}' "
                     f"SELECT * FROM {src} WHERE event_date >= DATE'{since}'")
            mode = f"incremental from {since}"
        self.sql(f"DELETE FROM {self.fq}.{name} WHERE event_date < DATE'{date.today() - timedelta(days=self.args.retention_days)}'")
        return mode

    def refresh_findings(self):
        self.sql(f"CREATE OR REPLACE TABLE {self.fq}.security_findings_latest "
                 f"COMMENT '{self.comment_of('security_findings_latest')}' "
                 f"AS SELECT *, current_timestamp() AS refreshed_at FROM {self.fq}.security_findings")
        self.sql(f"DELETE FROM {self.fq}.posture_snapshots WHERE snapshot_date = current_date()")
        self.sql(f"""INSERT INTO {self.fq}.posture_snapshots
                     SELECT current_date(), check_id, category, severity, title, findings FROM {self.fq}.check_results""")
        overall = self.sql(f"SELECT score_pct, checks_failed, total_findings FROM {self.fq}.posture_score WHERE category = 'ALL'").first()
        return f"score {overall['score_pct']}%, {overall['checks_failed']} failing checks, {overall['total_findings']} findings"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--schema", default="security_posture")
    parser.add_argument("--sql-dir", default=SQL_DIR)
    parser.add_argument("--events-backfill-days", type=int, default=365,
                        help="first-load window for audit_security_events (workspace settings are reconstructed from it)")
    parser.add_argument("--activity-backfill-days", type=int, default=90, help="first-load window for the *_daily tables")
    parser.add_argument("--retention-days", type=int, default=365)
    parser.add_argument("--reprocess-days", type=int, default=2, help="late-arriving audit events are re-read for this many days")
    parser.add_argument("--readers-group", default="", help="group granted USE SCHEMA + SELECT on the schema (and USE CATALOG)")
    args = parser.parse_args()

    from pyspark.sql import SparkSession
    r = Refresher(SparkSession.builder.getOrCreate(), args)

    r.step("preflight", r.preflight)
    r.step("source views", lambda: r.run_sql_files("10_"))
    for name in STATE_TABLES:
        r.step(f"state      {name}", lambda name=name: r.rebuild_state(name))
    for name, kind in ACTIVITY_TABLES.items():
        r.step(f"activity   {name}", lambda name=name, kind=kind: r.load_activity(name, kind))
    r.step("semantic views", lambda: r.run_sql_files("20_"))
    r.step("checks, score & KPI views", lambda: r.run_sql_files("30_"))
    r.step("findings & snapshot", r.refresh_findings)
    print(f"total {round(sum(t for _, t, _ in r.timings), 1)}s")


if __name__ == "__main__":
    main()
