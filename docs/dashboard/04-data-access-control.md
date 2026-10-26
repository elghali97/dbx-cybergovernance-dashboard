# 4. Data access control

> Unity Catalog grants and ownership as they are now, how they changed, and who was refused access.

**For:** data security and data owners (least privilege), auditors (access reviews), SOC (privilege escalation,
probing).

**Answers:**
- Who has access to a catalog, schema, table, volume, external location or credential, directly?
- What is granted to all users, and which high privileges (ALL PRIVILEGES, MANAGE, MODIFY, CREATE …) exist?
- Which critical securables are owned by individuals instead of groups?
- Who granted or revoked what, and when?
- Who tried to read data they are not allowed to?
- Which workspace objects (notebooks, jobs, clusters, warehouses, secret scopes …) had their permissions changed?

**Filters:** Catalog (state and changes), Date (activity), Workspace (activity).
**Data:** `uc_grants`, `securable_owners`, `uc_permission_changes`, `workspace_acl_changes`, `access_denied_daily`.
**Checks:** AC-01 high privilege to all users · AC-02 catalog / schema open to all users · AC-03 powerful privilege to
an individual · AC-04 critical securable owned by an individual · AC-05 new grants to all users · AC-06 metastore
privileges held by individuals.

## Counters

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Direct grants** | Privileges granted directly on securables (not inherited), selected catalogs | The size of the access surface to review |
| **Grants to all users** | Direct grants to `account users` / `users` | Each one opens data to everyone in the account: confirm it is intended |
| **High-privilege grants** | ALL PRIVILEGES, MANAGE, MODIFY and CREATE-type privileges | Should go to a few admin or engineering groups only |
| **Owned by individuals** | Securables owned by a user | Owners have full control and leave the company: transfer to groups |
| **Grants (period)** | GRANT events in the selected period | Activity level; compare with change windows |
| **Denied data access** | Requests refused by Unity Catalog / SQL (401 / 403) | Bursts by one principal: probing, privilege escalation, or a pipeline missing a grant |

## Charts

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Direct grants by securable and grantee type** | Grants per securable type, split users / groups / service principals | Many grants to users = access managed person by person; prefer groups |
| **Top grantees** | Principals with the most direct grants | The most privileged identities: review them first in access reviews |
| **Unity Catalog grants and revokes per day** | Daily GRANT and REVOKE counts | Spikes = bulk changes; check they match a project or a migration |
| **Securable ownership** | Securables by type, owned by users / groups / service principals | The user-owned share is the ownership debt |

## Tables

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Current direct grants** | Securable, grantee and type, privilege, ⚠️ All users audience, ⚠️ High privilege level, grantor; broad and high-privilege grants first | The access review list. Export per catalog and send to its owner |
| **Unity Catalog permission changes** | Each GRANT / REVOKE: actor, principal, privilege, securable, ⚠️ All users | Who opened what. Grants to all users and unexpected actors first |
| **Denied data access** | Per day: principal, securable, attempts, error | A user cycling through many securables is suspicious; one service principal failing every day is a broken job |
| **Workspace object ACL changes** | Permission changes on notebooks, folders, dashboards, Genie spaces, clusters, jobs, warehouses, secret scopes, serving endpoints, apps … | Grants to `users` on sensitive objects (secret scopes, jobs running as privileged identities) |

**Ask Genie:** *"Who can read catalog finance?"*, *"Which grants to all users were added last week and by whom?"*.
