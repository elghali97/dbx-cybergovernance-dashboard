#!/usr/bin/env python3
"""Run SQL on a SQL warehouse through the Databricks CLI (Statement Execution API).

Usage:  q.py "<sql>"   |   q.py -f file.sql
Env:    DATABRICKS_WAREHOUSE_ID (required), DATABRICKS_CONFIG_PROFILE (optional CLI profile),
        CATALOG / SCHEMA (optional default namespace), LIMIT (rows, default 50), W (max column width, default 120)
"""
import json
import os
import subprocess
import sys
import time


def api(method, path, body=None):
    cmd = ["databricks", "api", method, path]
    if body is not None:
        cmd += ["--json", json.dumps(body)]
    out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if out.returncode:
        sys.exit(out.stderr)
    return json.loads(out.stdout, strict=False)


def run(sql, limit=50):
    body = {"statement": sql, "warehouse_id": os.environ["DATABRICKS_WAREHOUSE_ID"], "wait_timeout": "50s", "row_limit": limit}
    if os.environ.get("CATALOG"):
        body.update(catalog=os.environ["CATALOG"], schema=os.environ.get("SCHEMA", "default"))
    r = api("post", "/api/2.0/sql/statements", body)
    while r["status"]["state"] in ("PENDING", "RUNNING"):
        time.sleep(2)
        r = api("get", f"/api/2.0/sql/statements/{r['statement_id']}")
    st = r["status"]
    if st["state"] != "SUCCEEDED":
        return f"ERROR: {st.get('error', {}).get('message', st)[:1500]}"
    cols = [c["name"] for c in r.get("manifest", {}).get("schema", {}).get("columns", [])]
    rows = r.get("result", {}).get("data_array", []) or []
    width = int(os.environ.get("W", 120))
    lines = [" | ".join(cols)] + [" | ".join("" if v is None else str(v)[:width] for v in row) for row in rows]
    return "\n".join(lines) + f"\n({r['manifest'].get('total_row_count', len(rows))} rows)"


if __name__ == "__main__":
    sql = open(sys.argv[2]).read() if sys.argv[1] == "-f" else sys.argv[1]
    print(run(sql, int(os.environ.get("LIMIT", 50))))
