# 3. Identity & authentication

> Logins, failed authentication, IP blocks, personal access tokens and changes to users, groups and admin rights.

**For:** SOC analysts (brute force, credential misuse, privilege escalation), IAM teams (admin hygiene, PAT to OAuth
migration).

**Answers:**
- Who was granted admin rights, by whom, and when?
- Are there bursts of failed logins or token failures, and from which IPs?
- Which requests were blocked by IP access lists (attacks, or users outside the corporate network)?
- Who still uses personal access tokens, and were tokens created without expiry or with very long lifetimes?
- Which users, groups and service principals were created, changed or removed?

**Filters:** Date, Workspace.
**Data:** `auth_events_daily`, `failed_auth_events`, `identity_changes`, `token_events`, `activity_kpis_daily`.
**Checks:** IA-01 PAT without expiry · IA-02 PAT > 90 days · IA-03 max token lifetime · IA-04 users on PATs ·
IA-05 admin privileges granted · IA-06 repeated authentication failures · IA-07 IP access list blocks.

## Counters (selected period)

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **SSO logins** | Browser single sign-on logins | Baseline of interactive use; a sudden drop or spike is worth a look |
| **Failed authentications** | Failed logins and token / OAuth authentications | Compare with the chart by type below to see what fails |
| **IP access list blocks** | Requests refused because the source IP is not allowed | High numbers: attacks from the internet, or users / integrations outside the allowed ranges |
| **Admin rights granted** | Grants of workspace or account admin rights and admin-group memberships | Every one should match an approved request (check IA-05, HIGH) |
| **PATs created** | Personal access tokens created | Prefer OAuth; PATs should be rare and short-lived |
| **PATs without expiry** | Tokens created with no expiry | Should be 0 (check IA-01, HIGH): revoke them and set a maximum token lifetime |

## Charts

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Authentication by method** | Daily authentications by method: SSO browser, PAT, OAuth, IP access denied | Track the PAT to OAuth migration; IP denials on top of normal traffic suggest an attack |
| **Failed authentication by type** | Failures per login action (token, OAuth, SAML, …) and IP access list blocks | One dominant type points to the cause: expired tokens (`tokenLogin`), broken OAuth integrations (`mintOAuthToken`), blocked networks |
| **Top failing source IPs** (30 days) | IPs with the most failures and IP blocks | Unknown external IPs with many failures: block upstream, look for the principals targeted in the table below |
| **Top human PAT users** (30 days) | Users (not service principals) with the most PAT requests | Candidates to move to OAuth U2M (check IA-04) |
| **PATs created by lifetime** | Created tokens by lifetime: No expiry, > 90 days, ≤ 90 days | Anything but ≤ 90 days fails a check |

## Tables

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Identity, group & admin changes** | Every change to users, groups, service principals, admin rights and workspace assignments: actor, action, target, group, permissions, ⚠️ Privileged flag | Filter on ⚠️ Privileged for admin-related changes. Unknown actors or out-of-hours changes are escalation candidates |
| **Failed authentication events** | Each failure: principal, type, source IP, error | Pivot from an IP or principal seen in the charts; the error message tells expired token vs wrong credentials vs IP block |
| **PAT creations** | Each created token: who, lifetime bucket, expiry, scopes | Ask the creators of no-expiry and long-lived tokens to rotate them |

**Near real-time:** the [Splunk live dashboard](../splunk.md) shows the same events about 10 minutes after they happen,
with alerts on failed-login bursts and admin grants.
