# Databricks Security Posture

**A security posture dashboard, a Genie agent and a weekly report for the whole Databricks estate, built only on
system tables.** It's a workspace-level alternative to the Governance Hub security views for security teams that
don't have account-admin access. No account API, no secrets, no external tooling: one Databricks Asset Bundle.

| What you get | |
|---|---|
| 📊 **Databricks Security Posture** dashboard | 8 SAT-style pages: posture overview with a score, category scorecard and the 32 checks (each linked to the Databricks security best practice and the remediation docs) · findings explorer · identity & authentication · data access control · policies & data protection · tags & metadata · data activity & sharing · compute, network & configuration |
| 🤖 **Security Posture Analyst** Genie agent | Natural-language questions: *who has access to X, who got admin rights this week, which sensitive columns are unprotected, what changed last week …* Also opens from the dashboard's **Ask Genie** button |
| 🔄 **Security Posture - refresh** job | Every 6 hours on serverless: incremental, materialised tables, so the dashboard and Genie stay fast at any account size |
| 📧 **Weekly report** | A Genie One scheduled task, built on the agent and the dashboard, that emails the posture of the week to the security team ([setup](docs/weekly-report.md)) |

Coverage:
- **Identities:** admins, PATs, OAuth, failed logins, IP blocks.
- **Unity Catalog access:** grants, owners, broad and high-privilege grants, denied access.
- **Policies:** ABAC policies, column masks, row filters, cluster and serverless policies, init scripts.
- **Tags:** governed tags, tag coverage, classification, documentation gaps.
- **Data movement:** exports and downloads, secrets, Delta Sharing exposure.
- **Platform:** network policy denials, workspace security settings, compute access modes.

## Quick start

**1. Prerequisites (once, by a metastore admin):** run [`setup/grants.sql`](setup/grants.sql). It grants read access
to the system tables and `BROWSE` on the catalogs; account admin is not required.

**2. Deploy, with one of:**

| | How |
|---|---|
| **Workspace UI** (nothing to install) | Workspace → New → **Git folder** from `https://github.com/elghali97/dbx-cybergovernance-dashboard` → set the catalog, group and warehouse in **`config.yml`** → open `databricks.yml` → **Deployments → prod → Deploy** → ▶ **Security Posture - refresh** |
| **One command** | `git clone https://github.com/elghali97/dbx-cybergovernance-dashboard.git && cd dbx-cybergovernance-dashboard`, `databricks auth login --host https://<workspace>`, then **`./deploy.sh`**. It checks access, asks for the catalog, group and warehouse, deploys, runs the first refresh and prints the links |
| **GitHub Actions** | Set the service principal secrets and `DATABRICKS_HOST` → Actions → **Deploy Security Posture** → **Run workflow** |

**3. Weekly report:** create the Genie One scheduled task with the ready-made instructions in
[docs/weekly-report.md](docs/weekly-report.md).

Details, options, upgrade and uninstall are in [docs/deployment.md](docs/deployment.md).

## Documentation

| | |
|---|---|
| [Deployment](docs/deployment.md) | Prerequisites, the three install paths, upgrade / uninstall, troubleshooting |
| [Architecture](docs/architecture.md) | Data flow, tables and views, refresh job, performance, security considerations |
| [Security checks](docs/checks.md) | The 32 checks, SAT mapping, scoring, how to tune or add checks, what needs account access |
| [Weekly report](docs/weekly-report.md) | Genie One scheduled task setup and instructions |
| [Development](docs/development.md) | Repository layout, generators, query checker, conventions |

## Requirements

- Unity Catalog workspace with serverless compute.
- Databricks CLI ≥ 1.3.0, for `deploy.sh` / CI only; the workspace UI path needs nothing.
- The identity that deploys (user or service principal) runs the refresh job, so the system-table grants go to it.

> This is a field-built asset, not an official Databricks product, and it is not supported by Databricks Support.
> Review the checks and thresholds against your own security policies.
