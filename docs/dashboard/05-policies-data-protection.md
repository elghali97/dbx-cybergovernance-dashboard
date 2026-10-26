# 5. Policies & data protection

> Attribute-based access control (ABAC) policies, column masks, row filters and sensitive data: is sensitive data
> protected, and did anyone weaken a policy?

**For:** data protection officers and data security (PII / PCI protection, regulatory evidence), data governance
(policy design).

**Answers:**
- How many ABAC policies, column masks and row filters protect data, and where?
- Which columns are sensitive (Data Classification or classification tags), and which are not protected?
- Who is exempted from a policy (`EXCEPT` principals)? Is any policy exempting everyone?
- Who created, changed or deleted a security policy (ABAC, governed tag policy, cluster / serverless policy, global init
  script)?

**Filters:** Catalog (policies, controls, sensitive columns), Date (policy changes).
**Data:** `abac_policies`, `fine_grained_controls`, `sensitive_columns`, `table_governance_coverage`, `policy_changes`.
**Checks:** DP-01 sensitive column without protection · PO-01 security policy deleted · PO-02 ABAC policy exempts all
users · PO-03 global init script changed.

## Counters

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **ABAC policies** | ABAC row-filter and column-mask policies defined on catalogs, schemas and tables | Tag-driven protection that scales; the target model for sensitive data |
| **Column masks** | Columns with a mask function | Table-level protection, managed one table at a time |
| **Row filters** | Tables with a row filter function | |
| **Sensitive columns** | Columns detected by Data Classification or tagged as sensitive (class.*, PII …) | The data to protect |
| **Unprotected sensitive** | Sensitive columns with no mask and no ABAC policy in scope | Should be 0 (check DP-01, HIGH) |
| **Policy changes** | Policy create / update / delete events in the period | Every deletion should match a change request |

## Charts

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Sensitive columns by classification** | Sensitive columns per classification (email, phone, credit card, …), protected vs unprotected | The classes to cover with an ABAC column mask on the governed tag |
| **Policy changes by kind** | Changes per policy kind, created / updated vs ⚠️ deleted | Deletions of ABAC or governed tag policies weaken protection immediately |

## Tables

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **ABAC policies** | Name, type (row filter / column mask), scope, `TO` principals, `EXCEPT` principals, `WHEN` condition, governed tags | Review the EXCEPT lists: exemptions should be small break-glass groups |
| **Sensitive columns** | ✅ Protected / ⚠️ Unprotected, table, column, classification, source (classification or tag), mask | The remediation list for DP-01, unprotected first |
| **Column masks & row filters** | Each control: type, table, column or filter, function | Inventory of table-level controls; candidates to replace by ABAC policies |
| **Policy change history** | Each policy change: actor, kind, ⚠️ Deleted, name, type, scope | Who weakened or removed a control and when |

**Note:** Data Classification results (`system.data_classification.results`) are a Preview system table: when it is
not enabled, sensitive columns only come from classification tags (the refresh job lists missing optional sources).
