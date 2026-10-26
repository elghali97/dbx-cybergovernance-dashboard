# 2. Findings explorer

> Every failing object of every check at the last refresh: the remediation work list.

**For:** security engineers and platform / data teams who fix the findings; GRC who needs the evidence per object.

**Answers:**
- Which catalogs, grants, clusters, tokens, recipients or settings fail a given check?
- Which workspace has the most HIGH findings?
- What exactly is wrong with an object (the evidence) and when was it last seen?
- What list do I send to the owner of workspace X?

**Filters:** Severity, Category, Check, Workspace (multi-select, all visualizations of the page).
**Data:** `security_findings_latest` (one row per failing check and object, materialised at each refresh).

## Visualizations

| Visualization | What it shows | How to read it / act |
|---|---|---|
| **Findings per check** | Number of failing objects per check, coloured by severity | The checks with the most objects. Many objects on one check usually mean one root cause to fix centrally (for example a default grant to all users, a missing compute policy) |
| **Findings by severity** | Share of findings by severity | Use it with the Workspace filter to compare workspaces |
| **Findings** | One row per failing object: severity, check ID and title, workspace, object type and name, detail (the evidence), detected at, recommendation | Filter, then export the table (⋮ → Download) to hand the list to the owner. `workspace_name` is empty for metastore-level objects (catalogs, grants, shares). `detected_at` is the most recent evidence: an old date on an activity check means the finding will age out of its window |

## Tips

- A finding disappears at the next refresh after the fix; the score on the overview follows.
- Activity checks look back over a window (7 or 90 days, see [checks.md](../checks.md)): an event stays a finding until
  it leaves the window, even if it was legitimate. Review and accept, or tune the window.
- Ask Genie: *"List the HIGH findings of workspace X with the recommendation"*, *"Which owners have the most findings?"*.
