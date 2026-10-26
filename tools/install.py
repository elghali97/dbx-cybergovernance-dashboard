#!/usr/bin/env python3
"""One-command installer for the Databricks Security Posture bundle (called by ./deploy.sh).

Checks the tooling and the login, asks for the few deployment settings (or takes them from flags / the last run),
verifies that the deploying identity can read the system tables and that the security group exists, then deploys
the bundle (the refresh job), runs it once (the job creates the tables, then the dashboard and the Genie agent)
and prints the links. Re-run it any time to upgrade or change settings.
Standard library only (Python 3.6+).
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from urllib.parse import urlencode

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from links import links  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MIN_CLI = (1, 3, 0)
DEFAULTS = {"catalog": "security", "schema": "security_posture", "security_group": "admins"}
SETTINGS = ("catalog", "schema", "security_group", "warehouse_id", "timezone", "refresh_schedule")


def bold(s):
    return f"\033[1m{s}\033[0m" if sys.stdout.isatty() else s


def step(msg):
    print(f"\n{bold('==> ' + msg)}", flush=True)


def fail(msg):
    sys.exit(f"\nERROR: {msg}")


def cli(*args, parse=True, check=True, stream=False):
    """Run the Databricks CLI. stream=True shows its output live (deploy / run)."""
    cmd = ["databricks", *args]
    if stream:
        code = subprocess.call(cmd, cwd=ROOT)
        if check and code:
            fail(f"`{' '.join(cmd)}` failed (exit {code})")
        return code
    out = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if out.returncode:
        if check:
            fail(f"`{' '.join(cmd)}` failed:\n{out.stderr.strip()[:2000]}")
        return None
    return json.loads(out.stdout, strict=False) if parse and out.stdout.strip() else out.stdout


def ask(question, default="", assume_yes=False):
    if assume_yes or not sys.stdin.isatty():
        return default
    answer = input(f"{question}{f' [{default}]' if default else ''}: ").strip()
    return answer or default


def sql(warehouse_id, statement):
    """Run one statement; returns (ok, error message). Waits for a stopped warehouse to start."""
    r = cli("api", "post", "/api/2.0/sql/statements", "--json",
            json.dumps({"statement": statement, "warehouse_id": warehouse_id, "wait_timeout": "50s"}), check=False)
    if r is None:
        return False, "statement API call failed"
    deadline = time.time() + 600
    while r["status"]["state"] in ("PENDING", "RUNNING") and time.time() < deadline:
        time.sleep(5)
        r = cli("api", "get", f"/api/2.0/sql/statements/{r['statement_id']}")
    ok = r["status"]["state"] == "SUCCEEDED"
    return ok, "" if ok else r["status"].get("error", {}).get("message", r["status"]["state"]).splitlines()[0][:300]


def check_cli():
    step("Checking the Databricks CLI")
    try:
        version = cli("--version", parse=False)
    except FileNotFoundError:
        fail("Databricks CLI not found. Install it (>= 1.3.0): https://docs.databricks.com/aws/en/dev-tools/cli/install")
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", version)
    found = tuple(int(x) for x in m.groups()) if m else (0, 0, 0)
    if found < MIN_CLI:
        fail(f"Databricks CLI {'.'.join(map(str, found))} is too old; 1.3.0 or later is required (`databricks update` or reinstall).")
    print(f"Databricks CLI {'.'.join(map(str, found))}")


def check_login():
    step("Checking the workspace login")
    me = cli("current-user", "me", "-o", "json", check=False)
    if not me:
        fail("Not logged in. Run:  databricks auth login --host https://<your-workspace-url>  (add --profile NAME to keep "
             "several workspaces), then re-run with --profile NAME if you used one.")
    host = ((cli("auth", "describe", "-o", "json", check=False) or {}).get("details") or {}).get("host", "")
    print(f"Deploying as {me['userName']} to {host or 'the default workspace'}")
    return me["userName"]


def choose_warehouse(current, assume_yes):
    warehouses = cli("warehouses", "list", "-o", "json") or []
    if not warehouses:
        fail("No SQL warehouse found. Create a serverless SQL warehouse (or ask an admin for CAN USE on one) and re-run.")
    ids = {w["id"] for w in warehouses}
    if current in ids:
        default = current
    else:
        ranked = sorted(warehouses, key=lambda w: (w.get("name") != "Serverless Starter Warehouse",
                                                   not w.get("enable_serverless_compute"), w.get("state") != "RUNNING"))
        default = ranked[0]["id"]
    if assume_yes or not sys.stdin.isatty():
        return default
    print("SQL warehouses (used by the dashboard, the Genie agent and these checks):")
    for i, w in enumerate(warehouses, 1):
        kind = "serverless" if w.get("enable_serverless_compute") else w.get("warehouse_type", "").lower()
        print(f"  {i:>2}. {w['name']}  ({kind}, {w.get('state', '?').lower()}){'  <- default' if w['id'] == default else ''}")
    answer = ask("Warehouse number", str([w["id"] for w in warehouses].index(default) + 1))
    try:
        return warehouses[int(answer) - 1]["id"]
    except (ValueError, IndexError):
        return answer if answer in ids else default


def preflight(settings, user, force):
    step("Checking access")
    wh = settings["warehouse_id"]
    problems = []
    ok, err = sql(wh, "SELECT 1 FROM system.access.audit LIMIT 1")
    if not ok:
        problems.append(f"cannot read system.access.audit ({err})")
    for table in ("system.access.table_lineage", "system.compute.clusters", "system.tags.governed_tags",
                  "system.access.inbound_network", "system.access.outbound_network", "system.data_classification.results"):
        ok, _ = sql(wh, f"SELECT 1 FROM {table} LIMIT 1")
        print(f"  {'ok ' if ok else 'n/a'}  {table}{'' if ok else '  (optional: related tiles stay empty)'}")
    group = settings["security_group"]
    scim = cli("api", "get", "/api/2.0/preview/scim/v2/Groups?" + urlencode(
        {"filter": f'displayName eq "{group}"', "attributes": "displayName,meta"}), check=False) or {}
    found = scim.get("Resources", [])
    if not found:
        problems.append(f"group '{group}' is not visible in this workspace (assign the account group to the workspace, "
                        "or choose another group)")
    elif (found[0].get("meta") or {}).get("resourceType") == "WorkspaceGroup":
        print(f"  WARNING '{group}' is a workspace-local group: it can open the dashboard and the Genie agent, but Unity "
              "Catalog cannot grant it the schema. Prefer an account group (or grant its members the schema).")
    catalogs = cli("catalogs", "get", settings["catalog"], "-o", "json", check=False)
    if not catalogs:
        print(f"  catalog {settings['catalog']} does not exist yet: the refresh job will try to create it "
              "(needs CREATE CATALOG); otherwise create it and re-run.")
    if problems:
        hint = ("\nA metastore admin can grant the system tables with setup/grants.sql, or at least:\n"
                f"  GRANT USE CATALOG ON CATALOG system TO `{user}`;\n"
                f"  GRANT USE SCHEMA, SELECT ON SCHEMA system.access TO `{user}`;\n"
                f"  GRANT USE SCHEMA, SELECT ON SCHEMA system.compute TO `{user}`;\n"
                f"  GRANT USE SCHEMA, SELECT ON SCHEMA system.tags TO `{user}`;")
        message = "\n".join(f"  - {p}" for p in problems) + hint
        if not force:
            fail("Pre-deployment checks failed:\n" + message + "\nRe-run with --force to deploy anyway.")
        print("WARNING (continuing because of --force):\n" + message)
    else:
        print("  ok   system.access.audit, security group and warehouse")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile", help="Databricks CLI profile of the target workspace (see `databricks auth profiles`)")
    p.add_argument("--target", default="prod", choices=["prod", "dev"], help="bundle target (default: prod)")
    p.add_argument("--catalog", help=f"catalog for the security_posture schema (default: {DEFAULTS['catalog']})")
    p.add_argument("--schema", help=f"schema name (default: {DEFAULTS['schema']}; dev target: security_posture_dev)")
    p.add_argument("--group", dest="security_group", help=f"security team account group (default: {DEFAULTS['security_group']})")
    p.add_argument("--warehouse-id", dest="warehouse_id", help="SQL warehouse id (default: pick from the list)")
    p.add_argument("--timezone", help="timezone of the refresh schedule (default from config.yml)")
    p.add_argument("--refresh-schedule", dest="refresh_schedule", help="Quartz cron of the refresh job (default from config.yml)")
    p.add_argument("--notify", help="comma-separated emails notified when the refresh job fails")
    p.add_argument("--yes", "-y", action="store_true", help="non-interactive: use flags, previous answers and defaults")
    p.add_argument("--no-run", action="store_true", help="deploy only, do not run the first refresh")
    p.add_argument("--force", action="store_true", help="deploy even if the pre-deployment checks fail")
    args = p.parse_args()

    if args.profile:
        os.environ["DATABRICKS_CONFIG_PROFILE"] = args.profile
    state_file = os.path.join(ROOT, f".deploy.{args.target}.json")
    saved = json.load(open(state_file)) if os.path.exists(state_file) else {}

    check_cli()
    user = check_login()

    step("Deployment settings")
    settings = {}
    for key, question in (("catalog", "Catalog for the posture tables"), ("security_group", "Security team group")):
        settings[key] = getattr(args, key) or ask(question, saved.get(key, DEFAULTS[key]), args.yes)
    settings["schema"] = args.schema or saved.get("schema") or ("security_posture_dev" if args.target == "dev" else DEFAULTS["schema"])
    settings["warehouse_id"] = args.warehouse_id or choose_warehouse(saved.get("warehouse_id"), args.yes)
    for key in ("timezone", "refresh_schedule"):
        if getattr(args, key) or saved.get(key):
            settings[key] = getattr(args, key) or saved[key]
    notify = args.notify if args.notify is not None else ",".join(saved.get("failure_recipients", []))
    if args.notify is None and not saved:
        notify = ask("Emails notified when the refresh fails (comma-separated, optional)", "", args.yes)
    recipients = [e.strip() for e in notify.split(",") if e.strip()]
    for key in SETTINGS:
        if key in settings:
            print(f"  {key:<16} {settings[key]}")
    print(f"  {'notify':<16} {', '.join(recipients) or '-'}")

    preflight(settings, user, args.force)

    # Remember the answers; complex variables can only be overridden through variable-overrides.json.
    json.dump({**settings, "failure_recipients": recipients}, open(state_file, "w"), indent=2)
    overrides_dir = os.path.join(ROOT, ".databricks", "bundle", args.target)
    os.makedirs(overrides_dir, exist_ok=True)
    json.dump({"failure_recipients": recipients}, open(os.path.join(overrides_dir, "variable-overrides.json"), "w"))
    bundle_vars = [f"--var={k}={v}" for k, v in settings.items()]

    step(f"Deploying the bundle (target {args.target})")
    cli("bundle", "deploy", "-t", args.target, *bundle_vars, "--auto-approve", stream=True)

    if not args.no_run:
        step("Running the first refresh (about 5-15 minutes; the first run back-fills the history, then publishes "
             "the dashboard and the Genie agent)")
        cli("bundle", "run", "-t", args.target, *bundle_vars, "security_posture_refresh", stream=True)

    step("Done")
    for name, url in links(args.target, bundle_vars).items():
        print(f"  {name:<12} {url}")
    print(f"\nNext: create the weekly Genie One scheduled task (docs/weekly-report.md).\n"
          f"Settings saved to {os.path.basename(state_file)}; re-run ./deploy.sh{' --profile ' + args.profile if args.profile else ''}"
          f"{' --target dev' if args.target == 'dev' else ''} --yes to upgrade.")


if __name__ == "__main__":
    main()
