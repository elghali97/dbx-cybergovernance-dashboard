# Deployment

Three ways to install the same bundle. Pick the one that fits the customer's environment. All of them deploy into
the **current workspace**, with the identity of whoever (or whatever) deploys.

| | Needs | Best for |
|---|---|---|
| [A. Workspace UI](#a-workspace-ui-no-install) | A Git folder in the workspace | Locked-down environments: nothing to install |
| [B. `./deploy.sh`](#b-deploysh-one-command) | Databricks CLI ≥ 1.3.0 + python3 on a laptop | Fastest guided install, upgrades |
| [C. GitHub Actions](#c-github-actions-run-workflow) | Repo secrets for a service principal | Production, repeatable deployments by a service principal |

## Prerequisites (one time)

1. **Unity Catalog** workspace with **serverless** compute (jobs and SQL warehouses) enabled.
2. **Read access to the system tables** for the identity that deploys. A metastore admin runs
   [`setup/grants.sql`](../setup/grants.sql); account admin is not needed. Minimum: `USE CATALOG` on `system` and
   `USE SCHEMA` + `SELECT` on `system.access`; `system.compute` and `system.tags` are recommended. Optional Preview
   tables (network events, governed tags, Data Classification) are detected automatically, and their tiles stay
   empty when missing.
3. **Whole-estate metadata.** Grant `BROWSE` on every catalog to the deploying identity (also in `setup/grants.sql`).
   `information_schema` only returns objects the reader can see.
4. **A catalog** for the posture schema (default `security`). The refresh job creates it if the identity has
   `CREATE CATALOG`; otherwise create it and grant `USE CATALOG` + `CREATE SCHEMA`.
5. **The security team's account group**, assigned to the workspace (default `admins`, which only works for workspace
   ACLs: use a real account group so the schema grants work too).
6. **A SQL warehouse** (serverless recommended) the deployer can use.

The refresh job runs as the deploying identity, so the system-table grants must be on that identity. For production,
deploy with a service principal (option C) and grant it the prerequisites.

## A. Workspace UI (no install)

1. **Workspace → New → Git folder**, paste `https://github.com/elghali97/dbx-cybergovernance-dashboard` (or the URL of your fork).
2. Open **`config.yml`** in the Git folder and set at least `catalog`, `security_group` and the warehouse name
   (`warehouse_id: lookup: warehouse: "<your warehouse name>"`).
3. Open **`databricks.yml`** → **Deployments** pane (rocket icon) → target **prod** → **Deploy** → confirm.
4. In **Bundle resources**, click ▶ next to **Security Posture - refresh**. The first run takes about 5 to 15
   minutes because it back-fills the history. Its last task, `publish`, creates the dashboard and the Genie agent
   (the agent needs the tables to exist, so they cannot be created by Deploy itself).
5. Open **Databricks Security Posture** from the bundle's `resources` folder (or from the links at the end of the
   `publish` task output), then create the weekly report ([weekly-report.md](weekly-report.md)).

Deploy only creates the job: the dashboard and the agent appear after the first run.

To upgrade, pull the Git folder, then Deploy again.

## B. `./deploy.sh` (one command)

```bash
databricks auth login --host https://<workspace-url> --profile customer   # once
./deploy.sh --profile customer
```

The installer:
- checks the CLI version and the login;
- asks for the catalog, the group and the warehouse (it lists them);
- verifies system-table access and that the group exists, and prints the exact `GRANT` statements if something is
  missing;
- deploys the bundle, runs the first refresh and prints the dashboard, Genie agent and job links.

Answers are saved in `.deploy.<target>.json` (git-ignored). Re-run `./deploy.sh --profile customer --yes` to upgrade.

| Option | Meaning |
|---|---|
| `--catalog`, `--schema`, `--group`, `--warehouse-id` | settings (otherwise asked / reused) |
| `--notify a@x.com,b@x.com` | emails notified when the refresh job fails |
| `--timezone`, `--refresh-schedule` | schedule of the refresh job (default every 6 h, Asia/Dubai) |
| `--target dev` | personal copy: resources prefixed with your name, schedule paused, schema `security_posture_dev` |
| `--yes` | non-interactive |
| `--no-run` | deploy without running the first refresh |
| `--force` | deploy even if the pre-deployment checks fail |

Plain CLI equivalent:
`databricks bundle deploy -t prod --var="catalog=security" --var="warehouse_id=<id>" --var="security_group=<group>"`,
then `databricks bundle run -t prod security_posture_refresh`.

## C. GitHub Actions ("Run workflow")

1. Create a service principal in the workspace, generate an **OAuth secret**, and grant it the prerequisites.
2. In the GitHub repository → **Settings → Secrets and variables → Actions**:
   - secrets `DATABRICKS_CLIENT_ID` and `DATABRICKS_CLIENT_SECRET`;
   - variable `DATABRICKS_HOST`, and optionally `SECURITY_POSTURE_CATALOG`, `SECURITY_POSTURE_GROUP` and
     `SECURITY_POSTURE_WAREHOUSE_ID`. They can also be set per GitHub environment `prod` / `dev`, for example to
     point each one at a different workspace.
3. **Actions → Deploy Security Posture → Run workflow** → target `prod`. The run summary shows the links.

The [CI workflow](../.github/workflows/ci.yml) checks every push without credentials: generated files must be up to
date, Python must compile, and every optional system table needs a fallback.

## After the first deployment

- **Share:** the security group gets `CAN RUN` on the dashboard and the Genie agent, and the refresh job grants it
  `USE SCHEMA` + `SELECT` on the schema plus `USE CATALOG` when allowed. The job log prints a warning with the
  statement to run if a grant could not be applied.
- **Weekly report:** create the Genie One scheduled task, see [weekly-report.md](weekly-report.md).
- **Splunk (optional):** live activity and posture dashboards plus alerts in Splunk Enterprise, see [splunk.md](splunk.md).
- **Several metastores (regions):** the audit log is account-wide, but `information_schema` is per metastore.
  Deploy once in a workspace of each metastore.

## Upgrade, change settings, uninstall

- **Upgrade:** get the new version, then Deploy again (any option). The next refresh run rebuilds the tables whose
  definition changed and updates the dashboard and the Genie agent if their template changed (an upgrade replaces
  edits made to them in the UI; scheduled runs do not).
- **Change settings:** edit `config.yml` or re-run `./deploy.sh` with new flags, then deploy.
- **Uninstall:** delete the dashboard and the Genie agent (their ids are in `<catalog>.security_posture.published_assets`),
  then `databricks bundle destroy -t prod` (or **Destroy** in the Deployments pane) removes the job and the files.
  The data stays: `DROP SCHEMA <catalog>.security_posture CASCADE`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `failed to resolve warehouse: Serverless Starter Warehouse` | Set your warehouse name in `config.yml`, or pass `--warehouse-id` |
| `Databricks CLI ... is too old` / `databricks_cli_version` error | Update the CLI to 1.3.0 or later (`databricks update`) |
| Refresh job fails with `Cannot read system.access.audit` | Run `setup/grants.sql` for the identity printed in the error |
| `Catalog ... does not exist and ... cannot create it` | Create the catalog, or set an existing one in `config.yml` |
| Deploy fails on permissions with an unknown group | The group must exist in (be assigned to) the workspace |
| No dashboard / Genie agent after Deploy | Expected: run **Security Posture - refresh** once, its `publish` task creates them |
| `publish` task fails on the Genie agent | The `refresh` task did not create every table: check its log, fix, run again |
| Some tiles are always empty | An optional system table is not enabled; the job log lists it as `WARNING ... not enabled or not granted` |
| Dashboard viewers get permission errors | Grant them `USE CATALOG` on the catalog and `USE SCHEMA` + `SELECT` on the schema |
