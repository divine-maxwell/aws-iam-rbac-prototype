-- Latest 50 events (string timestamp)
SELECT ts_string, eventName, eventSource, userIdentity.type, sourceIPAddress
FROM cloudtrail_logs.events_v
ORDER BY ts_string DESC
LIMIT 50;

-- Filter by date window using string compare on ISO8601 (works because lexicographic)
SELECT ts_string, eventName, eventSource
FROM cloudtrail_logs.events_v
WHERE ts_string BETWEEN '2025-08-11T00:00:00Z' AND '2025-08-12T23:59:59Z'
ORDER BY ts_string DESC
LIMIT 100;
