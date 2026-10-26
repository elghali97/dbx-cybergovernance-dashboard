#!/usr/bin/env python3
"""Local dev helper: render and run each statement of the given SQL files (default: all) via the SQL Statement API.
Only for iterating on views; the refresh job is what materialises the tables."""
import glob, os, sys
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from q import run
from refresh import file_statements, object_name, SQL_DIR, OPTIONAL_SOURCES

CATALOG = os.environ["CATALOG"]
SCHEMA = os.environ["SCHEMA"]
MISSING = [t for t in OPTIONAL_SOURCES if run(f"SELECT 1 FROM {t} LIMIT 1", 1).startswith("ERROR")]

failed = 0
for path in sys.argv[1:] or sorted(glob.glob(os.path.join(SQL_DIR, '*.sql'))):
    for stmt in file_statements(path, CATALOG, SCHEMA, MISSING):
        res = run(stmt, 5)
        ok = not res.startswith("ERROR")
        failed += not ok
        print(("OK   " if ok else "FAIL ") + object_name(stmt))
        if not ok:
            print("     " + res[:1200])
sys.exit(1 if failed else 0)
