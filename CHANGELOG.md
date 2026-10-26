# Changelog

## 1.0.0

- Dashboard (8 pages, SAT-style). The posture overview links each check to the Databricks security best practice
  and the remediation docs.
- Security Posture Analyst Genie agent: 30 tables, instructions and example queries.
- Refresh job: materialised, incremental layer over system tables, with a preflight check and fallbacks for
  optional Preview tables.
- 32 security checks with weighted posture score and daily snapshots.
- Weekly report as a Genie One scheduled task.
- One-step deployment: workspace UI Deploy button, `./deploy.sh`, GitHub Actions workflow.
