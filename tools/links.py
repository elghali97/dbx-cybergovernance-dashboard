#!/usr/bin/env python3
"""Print the links of a deployed Security Posture: dashboard, Genie agent and refresh job.

The dashboard and the agent are created by the job's publish task in the bundle's resources folder, so they are
found there (the dashboard's "Ask Genie" setting holds the agent id) rather than in `bundle summary`.
Usage: tools/links.py [-t TARGET] [--var=...]   (Databricks CLI login / DATABRICKS_CONFIG_PROFILE as for deploy)
Standard library only (Python 3.6+).
"""
import json
import os
import subprocess
import sys
from urllib.parse import urlsplit

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DASHBOARD_FILE = "Databricks Security Posture.lvdash.json"


def cli_json(*args):
    out = subprocess.run(["databricks", *args, "-o", "json"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         universal_newlines=True)
    return json.loads(out.stdout, strict=False) if out.returncode == 0 and out.stdout.strip() else None


def links(target, bundle_vars=()):
    summary = cli_json("bundle", "summary", "-t", target, *bundle_vars) or {}
    job = summary.get("resources", {}).get("jobs", {}).get("security_posture_refresh", {})
    # The host is not in the summary with profile logins; the job URL has it (and the workspace id, ?o= / ?w=).
    url = urlsplit(job.get("url") or (summary.get("workspace") or {}).get("host") or "")
    host, query = f"{url.scheme}://{url.netloc}", f"?{url.query}" if url.query else ""
    resource_path = (summary.get("workspace") or {}).get("resource_path", "")
    dashboard_id = genie_id = None
    for obj in (cli_json("workspace", "list", resource_path) or []) if resource_path else []:
        if obj.get("object_type") == "DASHBOARD" and obj.get("path", "").endswith(DASHBOARD_FILE):
            dashboard_id = obj.get("resource_id")
    if dashboard_id:
        dashboard = cli_json("lakeview", "get", dashboard_id) or {}
        ui = json.loads(dashboard.get("serialized_dashboard") or "{}").get("uiSettings", {})
        genie_id = (ui.get("genieSpace") or {}).get("overrideId")
    pending = "- (created by the first run of the refresh job)"
    return {
        "Dashboard": f"{host}/dashboardsv3/{dashboard_id}/published{query}" if dashboard_id else pending,
        "Genie agent": f"{host}/genie/rooms/{genie_id}{query}" if genie_id else pending,
        "Refresh job": job.get("url") or "-",
    }


def main():
    args = sys.argv[1:]
    target = "prod"
    if "-t" in args:
        i = args.index("-t")
        target = args[i + 1]
        args = args[:i] + args[i + 2:]
    for name, url in links(target, args).items():
        print(f"{name:<12} {url}")


if __name__ == "__main__":
    main()
