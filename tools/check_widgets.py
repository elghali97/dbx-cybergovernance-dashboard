#!/usr/bin/env python3
"""Run every widget query of the generated dashboard (its fields + implied GROUP BY over its dataset, LIMIT 1)
against a deployed schema, so broken SQL is caught before deploying.
Env: DATABRICKS_WAREHOUSE_ID, CATALOG, SCHEMA (the deployed security_posture schema), DATABRICKS_CONFIG_PROFILE optional."""
import json, os, re, sys
from concurrent.futures import ThreadPoolExecutor
for var in ("DATABRICKS_WAREHOUSE_ID", "CATALOG", "SCHEMA"):
    if not os.environ.get(var):
        sys.exit(f"set {var}")
sys.path.insert(0, os.path.dirname(__file__))
from q import run
d = json.load(open(os.path.join(os.path.dirname(__file__), "..", "src", "dashboards", "security_posture.lvdash.json")))
ds = {x["name"]: "".join(x["queryLines"]) for x in d["datasets"]}
AGG = re.compile(r"^(COUNT|SUM|MAX|MIN|AVG|COUNT_IF)\(", re.I)
jobs = []
for p in d["pages"]:
    for l in p["layout"]:
        w = l["widget"]
        for q in w.get("queries", []):
            fields = q["query"]["fields"]
            sel = ", ".join(f'{f["expression"]} AS `{f["name"]}`' for f in fields)
            groups = [f["expression"] for f in fields if not AGG.match(f["expression"])]
            gb = "" if q["query"].get("disaggregated") or not groups or len(groups) == len(fields) else " GROUP BY " + ", ".join(groups)
            jobs.append((f'{p["name"]}/{w["name"]}', f'SELECT {sel} FROM ({ds[q["query"]["datasetName"]]}){gb} LIMIT 1'))
def check(j):
    return j[0], run(j[1], 1)
bad = 0
with ThreadPoolExecutor(8) as ex:
    for name, res in ex.map(check, jobs):
        if res.startswith("ERROR"):
            bad += 1
            print("FAIL", name, res[:400], flush=True)
print(f"{len(jobs) - bad}/{len(jobs)} widget queries OK", flush=True)
sys.exit(1 if bad else 0)
