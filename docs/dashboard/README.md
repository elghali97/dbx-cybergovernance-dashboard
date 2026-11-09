# Dashboard guide

The **Databricks Security Posture** dashboard has nine pages. Each page has its own guide: who it is for, what
security questions it answers, and every visualization with what it shows, how to read it and what to do about it.

| # | Page | Main question | Typical users |
|---|---|---|---|
| 1 | [Posture overview](01-posture-overview.md) | How secure is the estate today, and is it getting better? | CISO, security manager, GRC |
| 2 | [Findings explorer](02-findings-explorer.md) | Which objects fail which check, and who must fix them? | Security engineer, platform team |
| 3 | [Threat detections](03-threat-detections.md) | Is anyone brute-forcing, harvesting secrets, probing data, escalating privileges or exfiltrating? From where? | SOC analyst, incident response |
| 4 | [Identity & authentication](04-identity-authentication.md) | Who logs in how, who failed, who became admin, which tokens exist? | SOC analyst, IAM team |
| 5 | [Data access control](05-data-access-control.md) | Who can access what, who changed it, who was refused? | Data security, data owners, auditors |
| 6 | [Policies & data protection](06-policies-data-protection.md) | Is sensitive data masked or filtered, and did anyone weaken a policy? | Data protection officer, data security |
| 7 | [Tags & metadata](07-tags-metadata.md) | Is data classified and documented enough for tag-based policies? | Data governance, data stewards |
| 8 | [Data activity & sharing](08-data-activity-sharing.md) | What data leaves the platform: downloads, exports, secrets, Delta Sharing? | SOC analyst, insider-risk, DLP |
| 9 | [Compute, network & config](09-compute-network-config.md) | Are clusters isolated, network policies enforced, workspace settings hardened? | Platform security, cloud security |

## Reading the dashboard

- **Freshness.** The refresh job updates the tables every 6 hours by default. The *Data age* counter on the overview
  says how old the data is. For near real-time activity (about 10 minutes behind), use the
  [Splunk live dashboard](../splunk.md), which reads the `live_*` views.
- **Severity colours** are the same everywhere and always come with a label: HIGH red, MEDIUM orange, LOW yellow,
  PASS green. ⚠️ marks a risky value in tables (broad audience, high privilege, unprotected, risky setting).
- **Filters** apply to the visualizations of their page. Date filters only apply to activity (events); state
  (current grants, policies, clusters) is always the latest refresh.
- **Counters** of activity pages show the total for the selected period, with a sparkline per day.
- **History.** Activity tables keep 365 days of security events and 90 days of high-volume daily aggregates (first
  load); posture snapshots accumulate from the first refresh.
- **Links.** On the posture overview, a check title opens the Databricks security best practice behind it, and its
  recommendation opens the remediation documentation (docs.databricks.com or learn.microsoft.com, depending on the
  cloud of the metastore).
- **Ask Genie.** The *Ask Genie* button opens the **Security Posture Analyst** agent on the same data, for follow-up
  questions in natural language ("who granted MANAGE on catalog x last week?").

All data comes from Databricks system tables, read with the deploying identity's access, and stays in the
workspace. See [architecture](../architecture.md) for the tables behind each page and [checks](../checks.md) for
the 44 checks, and [use cases](../use-cases.md) for the SRA detection use cases and their audit events.
