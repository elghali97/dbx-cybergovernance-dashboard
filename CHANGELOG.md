# Changelog

## 1.1.0

- Fix: the first Deploy failed with `cannot create resources.genie_spaces.security_posture_genie ... does not exist`
  because Genie checks that the agent's tables exist, and they are only created by the refresh job. The dashboard
  and the Genie agent are now created by a new `publish` task of the job, after the refresh: Deploy, then run the
  job once. Existing deployments: the next Deploy removes the bundle-managed dashboard and agent, the next run
  creates them again (new URLs).
- `tools/links.py` prints the links of a deployment (used by `deploy.sh` and the GitHub Actions workflow).

## 1.0.0

- Dashboard (8 pages, SAT-style). The posture overview links each check to the Databricks security best practice
  and the remediation docs.
- Security Posture Analyst Genie agent: 30 tables, instructions and example queries.
- Refresh job: materialised, incremental layer over system tables, with a preflight check and fallbacks for
  optional Preview tables.
- 32 security checks with weighted posture score and daily snapshots.
- Weekly report as a Genie One scheduled task.
- One-step deployment: workspace UI Deploy button, `./deploy.sh`, GitHub Actions workflow.
