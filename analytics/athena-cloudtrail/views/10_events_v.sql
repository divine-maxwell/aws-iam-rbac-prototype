-- View using plain string for ts to avoid unsupported TIMESTAMP WITH TIME ZONE
CREATE OR REPLACE VIEW cloudtrail_logs.events_v AS
SELECT
  eventTime                              AS ts_string,
  eventName, eventSource, awsRegion,
  userIdentity, sourceIPAddress, userAgent,
  errorCode, errorMessage, requestParameters, responseElements,
  additionalEventData, eventID, resources, eventType, readOnly
FROM cloudtrail_logs.event_data_store;
