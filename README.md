# Databricks Security Posture

**A security posture dashboard, a Genie agent and a weekly report for the whole Databricks estate, built only on
system tables.** It's a workspace-level alternative to the Governance Hub security views for security teams that
don't have account-admin access. No account API, no secrets, no external tooling: one Databricks Asset Bundle.

| What you get | |
|---|---|
| 📊 **Databricks Security Posture** dashboard | 8 SAT-style pages: posture overview with a score, category scorecard and the 32 checks (each linked to the Databricks security best practice and the remediation docs) · findings explorer · identity & authentication · data access control · policies & data protection · tags & metadata · data activity & sharing · compute, network & configuration |
| 🤖 **Security Posture Analyst** Genie agent | Natural-language questions: *who has access to X, who got admin rights this week, which sensitive columns are unprotected, what changed last week …* Also opens from the dashboard's **Ask Genie** button |
| 🔄 **Security Posture - refresh** job | Every 6 hours on serverless: incremental, materialised tables, so the dashboard and Genie stay fast at any account size. The only bundle resource: its `publish` task creates the dashboard and the agent |
| 📧 **Weekly report** | A Genie One scheduled task, built on the agent and the dashboard, that emails the posture of the week to the security team ([setup](docs/weekly-report.md)) |
| 📡 **Splunk app** (optional) | Near real-time *Live activity* and *Posture* dashboards plus 4 alerts for Splunk Enterprise on-premises, through the Databricks Add-on for Splunk ([setup](docs/splunk.md)) |

## Coverage and use cases, page by page

Each page has a guide explaining every visualization, how to read it and what to do: [docs/dashboard](docs/dashboard/README.md).

| Page | Covers | Use cases for the security team |
|---|---|---|
| [**1. Posture overview**](docs/dashboard/01-posture-overview.md) | Weighted posture score and trend, scorecard of 8 security domains, the 32 checks with links to the Databricks best practice and the remediation docs, security activity this week vs last week | Weekly posture review and CISO reporting · show remediation progress · pick the next control to fix · evidence for audits |
| [**2. Findings explorer**](docs/dashboard/02-findings-explorer.md) | Every failing object of every check (grants, clusters, tokens, recipients, settings …) with the evidence and the fix, filterable by severity, category, check, workspace | Remediation work lists per owner or workspace · track HIGH findings to closure · export evidence |
| [**3. Identity & authentication**](docs/dashboard/03-identity-authentication.md) | SSO / PAT / OAuth logins, failed authentication and IP access list blocks, top failing IPs, admin rights and group changes, PAT creation and lifetime | Detect brute force and credential misuse · review every admin grant · find PATs without expiry · drive the PAT to OAuth migration |
| [**4. Data access control**](docs/dashboard/04-data-access-control.md) | Current Unity Catalog grants (broad, high-privilege), securable ownership, grant / revoke history, denied data access, workspace object ACL changes | Access reviews and least privilege · spot data opened to all users · privilege escalation and probing (denied access bursts) · fix ownership by individuals |
| [**5. Policies & data protection**](docs/dashboard/05-policies-data-protection.md) | ABAC policies and exceptions, column masks, row filters, sensitive columns (Data Classification and tags) and their protection, policy change history | Prove PII / PCI protection · find unprotected sensitive columns · review policy exemptions · detect weakened or deleted policies |
| [**6. Tags & metadata**](docs/dashboard/06-tags-metadata.md) | Governed tags, tag and description coverage per catalog, most used tag keys, popular tables missing tags, tag change history | Steer the classification programme (ABAC depends on tags) · prioritise the most-read untagged tables · detect removed classification tags |
| [**7. Data activity & sharing**](docs/dashboard/07-data-activity-sharing.md) | Interactive and automated exports and downloads, top exporters, secret reads and failures, Delta Sharing recipients (open / IP list / token expiry) and their activity | Exfiltration and insider-risk investigations · DLP evidence · secure external sharing (IP lists, token expiry) |
| [**8. Compute, network & config**](docs/dashboard/08-compute-network-config.md) | Cluster access modes, policies, runtimes and init scripts, network policy denials (ingress and serverless egress), last known workspace security settings and their changes | Hardening baseline per workspace · isolate clusters under Unity Catalog · detect disabled controls (IP access lists, verbose audit logs, downloads) · egress exfiltration attempts |

**Near real-time in Splunk.** The dashboard refreshes every 6 hours. For a SOC that monitors in Splunk, the
[Splunk app](docs/splunk.md) adds a *Live activity* dashboard on the `live_*` views, which read the audit log at query
time (about 10 minutes behind): HIGH signals to act on (admin granted, PAT without expiry, high privilege to all
users, IP access list deleted …), failed-login bursts, denied access, exports, network denials, with drill-down on any
actor, and four alerts.

## Quick start

**1. Prerequisites (once, by a metastore admin):** run [`setup/grants.sql`](setup/grants.sql). It grants read access
to the system tables and `BROWSE` on the catalogs; account admin is not required.

**2. Deploy, with one of:**

| | How |
|---|---|
| **Workspace UI** (nothing to install) | Workspace → New → **Git folder** from `https://github.com/elghali97/dbx-cybergovernance-dashboard` → set the catalog, group and warehouse in **`config.yml`** → open `databricks.yml` → **Deployments → prod → Deploy** → ▶ **Security Posture - refresh** (its first run creates the dashboard and the Genie agent) |
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
| [Dashboard guide](docs/dashboard/README.md) | Every page and visualization: what it shows, how to read it, what to do |
| [Weekly report](docs/weekly-report.md) | Genie One scheduled task setup and instructions |
| [Splunk](docs/splunk.md) | Live and posture dashboards and alerts for Splunk Enterprise, with the Databricks Add-on for Splunk |
| [Development](docs/development.md) | Repository layout, generators, query checker, conventions |

## Requirements

- Unity Catalog workspace with serverless compute.
- Databricks CLI ≥ 1.3.0, for `deploy.sh` / CI only; the workspace UI path needs nothing.
- The identity that deploys (user or service principal) runs the refresh job, so the system-table grants go to it.

> This is a field-built asset, not an official Databricks product, and it is not supported by Databricks Support.
> Review the checks and thresholds against your own security policies.
