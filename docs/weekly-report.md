# Weekly security posture report: Genie One scheduled task

The weekly report is a **Genie One scheduled task**. It builds the report from the **Security Posture Analyst** Genie agent
and the **Databricks Security Posture** dashboard, both deployed by this bundle. Nothing is pre-computed for it: each run
queries the tables the refresh job keeps up to date (every 6 hours by default).

Scheduled tasks are personal objects created in the Genie One UI. They can't be deployed from a bundle and have no
public API. Create the task once with the account that owns security reporting. It runs with that user's Unity Catalog
permissions, so that user needs `CAN RUN` on the Genie agent and the dashboard, and `SELECT` on the
`security_posture` schema.

## Create the task

Genie One → sidebar **Schedules** → **Create manually** (next to **+ Create in chat**):

| Field | Value |
|---|---|
| Title | `Weekly Databricks security posture` |
| Instructions | the prompt below (replace the dashboard link and the email addresses) |
| Connections | none needed (all data is in Databricks) |
| Schedule | Weekly, Monday 08:00 |
| Timezone | `Asia/Dubai` (or the security team's timezone) |

Then click **Run now** once to check the output before the first scheduled run.

## Instructions (copy-paste)

```
Write the weekly Databricks security posture report for the Cybersecurity team, covering last week
(the previous complete Monday–Sunday week).

Use the Genie agent @Security Posture Analyst for every number, and only that data: do not estimate, do not
guess causes or intent. The same data is shown on the "Databricks Security Posture" dashboard:
<dashboard published URL>

Structure:
1. Headline — overall posture score (posture_score, category ALL), its change versus a week ago (posture_trend),
   number of failing checks and of HIGH findings. If there is no HIGH finding and the score did not drop,
   start with "No critical change this week".
2. Top risks — every failing HIGH check (check_results), then the 3 MEDIUM checks with the most findings:
   check id and title, number of affected objects and workspaces, 3 example objects with their evidence,
   the recommendation, and the documentation link (doc_url).
3. Activity — table of last week vs the week before for each metric of weekly_activity_kpis; highlight
   changes above 25 %.
4. Changes to review — admin rights granted (identity_changes, is_privileged, not removals), grants to all
   users (uc_permission_changes, is_broad_principal), security policies deleted (policy_changes, is_deletion),
   classification tags removed (tag_changes), risky setting changes (workspace_config_changes,
   is_risky_value): what, who and when.
5. Next steps — at most 5 concrete actions ordered by risk reduction, each with its documentation link.

Add two charts: overall posture score over the last 30 days, and findings by category and severity.
Keep it concise and executive-friendly; end with the dashboard link.

Email the report with the subject "Databricks security posture – week of <Monday date>" to
security-team@<customer-domain>, and attach it as a PDF.
```

## Notes

- **Recipients.** Scheduled tasks send emails through an email tool, so the instructions can name recipients. The
  Genie One docs only guarantee delivery to the task owner, so check the first **Run now** email. If other recipients
  don't receive it, create the task from a shared security mailbox account, or forward the "Genie Task:" emails from
  the owner's inbox.
- **Frequency.** Scheduled tasks run at most daily; weekly is supported.
- **Consistency.** Scheduled tasks look up their past runs, so the report keeps the same structure week after week.
- **Fallback without Genie One.** On the dashboard, use **Schedule** → weekly, Monday 08:00 → subscribers = the
  security distribution list (PDF attachment). The subscribers then get a snapshot of the dashboard pages, but no
  written summary.
