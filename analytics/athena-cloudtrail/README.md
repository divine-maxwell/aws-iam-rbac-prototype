# Athena / CloudTrail slice

This folder contains:
- `sql/01_create_external_table_event_data_store.sql` — external table over CloudTrail logs in S3
- `views/10_events_v.sql` — convenience view (keeps timestamps as strings to avoid Hive TZ type)
- `sql/20_sample_queries.sql` — example queries
- `artifacts/csv/` — exported CSV results
- `artifacts/screenshots/` — console screenshots

**Athena settings used**
- Workgroup: `primary`
- Query result location: `s3://aws-cloudtrail-lake-query-results-237206024795-us-east-2/`
- Database: `cloudtrail_logs`
