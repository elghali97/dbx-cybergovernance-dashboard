# 6. Tags & metadata

> Governed tags, tag coverage and documentation gaps: the metadata that ABAC policies, discovery and audits rely on.

**For:** data governance teams and data stewards (classification programme), data security (ABAC depends on tags),
auditors (classification evidence).

**Answers:**
- What share of tables is tagged (including tags inherited from the schema or catalog) and documented?
- Which catalogs lag behind?
- Which heavily used tables have no tags or no description? (the Governance Hub recommendation)
- Which tag keys are used most, and which are governed tags?
- Who added or removed tags, especially classification tags?

**Filters:** Catalog (coverage, gaps), Date (tag changes).
**Data:** `table_governance_coverage`, `governed_tags`, `tag_assignments`, `tag_changes`, `table_access_activity`.
**Checks:** GT-01 untagged tables · GT-02 undocumented tables · GT-03 classification tag removed.

## Counters

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Tables & views** | Tables and views in the selected catalogs | The scope |
| **Tagged** | Tables with at least one tag, including inherited ones | Coverage numerator |
| **Documented** | Tables with a description | AI-generated comments in Catalog Explorer close this gap quickly |
| **Governed tags** | Governed tag policies (account-level tag keys with allowed values) | Governed tags are what ABAC policies match on |
| **Tag assignments** | Tags assigned on catalogs, schemas, tables, volumes and columns | |
| **Tag changes** | Tag add / remove events in the period | |

## Charts

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Tagging coverage by catalog** | Tagged vs untagged tables per catalog | Catalogs with a large untagged share: tag at catalog / schema level to cover them by inheritance |
| **Most used tag keys** | Top 12 tag keys by assignments, per securable type | Shows the de-facto taxonomy; inconsistent keys (`pii` vs `PII` vs `class.pii`) call for governed tags |
| **Tag changes per day** | Tag additions and removals per day | Removal spikes can switch off ABAC protection on many objects at once |
| **Documentation coverage by catalog** | Documented vs undocumented tables per catalog | |

## Tables

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Popular tables missing tags or descriptions** | Untagged or undocumented tables, most read first: owner, readers and reads (30 days), sensitive columns | Start the classification programme here: these tables have the most consumers |
| **Tag change history** | Each tag change: actor, add / remove, tag and value, ⚠️ Classification, securable, column | A removed classification tag (GT-03) can remove a mask: confirm it was approved |
