#!/usr/bin/env python3
"""Run every SQL statement of the Splunk app (dashboards and alerts, tools/build_splunk.py) against a deployed schema,
with the dashboard tokens set to their defaults (last 4 hours, all workspaces, all signals), so broken SQL is caught
without a Splunk instance. Prints the duration and row count of each statement.
Env: DATABRICKS_WAREHOUSE_ID, CATALOG, SCHEMA (the deployed security_posture schema), DATABRICKS_CONFIG_PROFILE optional."""
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

for var in ("DATABRICKS_WAREHOUSE_ID", "CATALOG", "SCHEMA"):
    if not os.environ.get(var):
        sys.exit(f"set {var}")
sys.path.insert(0, os.path.dirname(__file__))
import build_splunk as b  # noqa: E402
from q import run  # noqa: E402

now = int(time.time())
TOKENS = {"$sp$": f"{os.environ['CATALOG']}.{os.environ['SCHEMA']}", "$t_from$": str(now - 4 * 3600), "$t_to$": str(now),
          "$t_span$": "300", "$ws$": "*", "$actor_like$": "%", "$signals$": "'HIGH','MEDIUM','INFO'",
          "$category$": "*", "$severity$": "*"}


def fill(sql):
    sql = b.sql(sql)
    for token, value in TOKENS.items():
        sql = sql.replace(token, value)
    assert "$" not in b.TOKEN.sub("", sql) and not b.TOKEN.search(sql), f"unresolved token in {sql[:120]}"
    return sql


statements = [(f"live/{k}", fill(v)) for k, v in b.LIVE_QUERIES.items()]
statements += [(f"posture/{k}", fill(v)) for k, v in b.POSTURE_QUERIES.items()]
statements += [(f"alert/{name}", fill(query)) for name, _, query, _ in b.ALERTS]


def check(item):
    name, sql = item
    t = time.time()
    res = run(sql, 1)
    return name, res, round(time.time() - t, 1)


bad = 0
with ThreadPoolExecutor(4) as ex:
    for name, res, seconds in ex.map(check, statements):
        ok = not res.startswith("ERROR")
        bad += not ok
        print(f"{'OK  ' if ok else 'FAIL'} {seconds:>6}s  {name}  {res.splitlines()[-1] if ok else res[:400]}", flush=True)
print(f"{len(statements) - bad}/{len(statements)} Splunk queries OK")
sys.exit(1 if bad else 0)
