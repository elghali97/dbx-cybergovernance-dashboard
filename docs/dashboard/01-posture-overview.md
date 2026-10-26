# 1. Posture overview

> The executive view: one score, the eight security domains and the 32 checks, each linked to the Databricks
> security best practice and to the documentation that fixes it.

**For:** CISO and security managers (weekly review, reporting), GRC (control evidence), security engineers (where to
start).

**Answers:**
- What is our security posture today, and did it improve compared to last week?
- Which domain is weakest (identity, access control, data protection, tags, policies, sharing, compute, audit & network)?
- Which HIGH-severity controls fail, how many objects and workspaces are affected, and what is the fix?
- Did risky activity (admin grants, broad grants, failed logins, exports, policy or setting changes) increase this week?

**Filters:** none. Everything is account-wide, at the last refresh.
**Data:** `posture_score`, `posture_trend`, `check_results`, `activity_kpis_daily`.

## Headline counters

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Posture score** | Weighted share of passing checks (HIGH 5, MEDIUM 3, LOW 1), compared with 7 days ago | Green at 80 % or more, red under 50 %. A drop week over week means a new failing check: look at the checks table |
| **Checks failing** | Checks with at least one finding, out of 32 | The number of controls to remediate, independent of how many objects fail |
| **HIGH findings** | Failing objects of HIGH-severity checks | Fix first: admin rights granted, PATs without expiry, high privilege granted to all users, unprotected sensitive columns, open sharing without IP list, IP access lists disabled |
| **MEDIUM findings** | Failing objects of MEDIUM-severity checks | Plan remediation with the owners |
| **Data age** | Hours since the last refresh | Over 6 h (default schedule) means the refresh job failed or is paused: check the job |

## Charts

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Findings by category and severity** | Number of failing objects per domain, stacked by severity | The tallest red bars are the domains to work on. A long MEDIUM / LOW bar is often an hygiene problem (tagging, ownership) rather than an incident |
| **Posture score trend** | Daily score snapshot written by the refresh job | Steps down = a control started failing (new grant, setting change); steps up = remediation landed. Use it to show progress in reviews |

## Posture by category

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Category scorecard** | Per domain: score, checks, failing checks by severity, findings and scope | Give each domain an owner (IAM for identity, data owners for access control, platform team for compute). A domain with failing HIGH checks needs an action this week |

## All checks

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Security checks** | Every check with status (✅ Pass / ⚠️ Fail), severity, ID, category, findings, affected workspaces and SAT reference | **Click the title** for the Databricks security best practice behind the check, **click the recommendation** for the remediation documentation. Failing checks come first, by severity. The SAT reference maps the check to the Security Analysis Tool. Details per object are in the [Findings explorer](02-findings-explorer.md) |

## Activity: last 7 days vs previous 7 days

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Security activity** | 25 security metrics (logins, failed auth, IP blocks, admin grants, PATs, grants, revokes, broad grants, denied access, exports, secret reads, policy and setting changes …), all workspaces, this week vs last week | Increases are highlighted. A jump in admin grants, broad grants, exports or denied access deserves a look on the related page |
| **Key security activity per day (30 days)** | Daily admin grants, broad grants, failed authentication, interactive exports, policy changes and risky setting changes | Spikes point to the day to investigate. Compare with change windows to rule out planned work |

## Related

- Weekly e-mail: the [Genie One scheduled task](../weekly-report.md) summarises this page every week.
- Checks, thresholds and scoring: [checks.md](../checks.md).
