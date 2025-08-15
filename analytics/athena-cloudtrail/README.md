
**What**: External table over CloudTrail logs in S3 + sample queries and (optional) views.

**Paths**
- `sql/01_create_external_table_event_data_store.sql` – DDL for external table
- `sql/20_sample_queries.sql` – example queries
- `artifacts/screenshots/` – screenshots (CSV exports are **ignored**)

**Notes**
- Do not commit CSV exports; they are ignored via `.gitignore`.
- View/query examples expect timestamps as strings to avoid Hive TZ type issues.
