-- =============================================================================
-- Databricks Security Posture — one-time prerequisites
-- Run as a METASTORE ADMIN in a SQL editor attached to the target metastore. Account admin is NOT required.
--
-- Replace before running:
--   <deployer>        the user or service principal that deploys the bundle and runs the refresh job
--                     (service principal: use its application id, e.g. `1a2b3c4d-....`)
--   <security-team>   the account group of the Cybersecurity team (dashboard / Genie / weekly report readers)
--   security          the catalog for the posture schema (must match `catalog` in config.yml)
-- =============================================================================

-- 1. System tables read by the refresh job (system.access is required, the others are recommended)
GRANT USE CATALOG ON CATALOG system TO `<deployer>`;
GRANT USE SCHEMA, SELECT ON SCHEMA system.access TO `<deployer>`;               -- audit, lineage, network, workspaces
GRANT USE SCHEMA, SELECT ON SCHEMA system.compute TO `<deployer>`;              -- clusters
GRANT USE SCHEMA, SELECT ON SCHEMA system.tags TO `<deployer>`;                 -- governed tags
GRANT USE SCHEMA, SELECT ON SCHEMA system.data_classification TO `<deployer>`;  -- optional: Data Classification results

-- 2. Whole-estate metadata WITHOUT data access: BROWSE lets information_schema return every catalog, schema,
--    table, grant, tag, mask and policy, but not the data itself. Run the statements generated below
--    (one per catalog), and again when new catalogs are created.
SELECT concat('GRANT BROWSE ON CATALOG `', catalog_name, '` TO `<deployer>`;') AS run_these_statements
FROM system.information_schema.catalogs
WHERE catalog_name NOT IN ('system', '__databricks_internal')
ORDER BY catalog_name;

-- 3. Catalog for the posture schema (the refresh job creates the schema and grants the security team on it).
--    Skip CREATE CATALOG if the catalog exists; on workspaces without default storage add MANAGED LOCATION '<url>'.
CREATE CATALOG IF NOT EXISTS security COMMENT 'Databricks Security Posture';
GRANT USE CATALOG, CREATE SCHEMA ON CATALOG security TO `<deployer>`;
GRANT USE CATALOG ON CATALOG security TO `<security-team>`;

-- 4. Check: should return a recent count (system tables enabled and readable).
SELECT count(*) AS audit_events_last_day FROM system.access.audit WHERE event_date >= current_date() - 1;

-- Notes
-- * System schemas access / compute / tags are enabled by default on recent accounts. If a GRANT above fails
--   with "schema not found", an account admin must enable that system schema.
-- * Data Classification must be enabled per catalog for system.data_classification.results to have content.
-- * Verbose audit logs (workspace setting) add command-level events but are not required.
-- * The schema is created and owned by <deployer>; it grants <security-team> USE SCHEMA + SELECT on every run.
