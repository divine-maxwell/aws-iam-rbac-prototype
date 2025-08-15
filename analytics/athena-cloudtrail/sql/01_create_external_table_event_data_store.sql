CREATE EXTERNAL TABLE cloudtrail_logs.event_data_store (
  eventVersion            string,
  userIdentity            struct<
    type:string,
    principalId:string,
    arn:string,
    accountId:string,
    invokedBy:string,
    accessKeyId:string,
    userName:string,
    sessionContext:struct<
      attributes:struct<mfaAuthenticated:string, creationDate:string>,
      sessionIssuer:struct<type:string, principalId:string, arn:string, accountId:string, userName:string>
    >
  >,
  eventTime               string,
  eventSource             string,
  eventName               string,
  awsRegion               string,
  sourceIPAddress         string,
  userAgent               string,
  errorCode               string,
  errorMessage            string,
  requestParameters       string,
  responseElements        string,
  additionalEventData     string,
  requestID               string,
  eventID                 string,
  resources               array<struct<arn:string, accountId:string, type:string>>,
  eventType               string,
  apiVersion              string,
  readOnly                string,
  recipientAccountId      string,
  serviceEventDetails     string,
  sharedEventID           string,
  vpcEndpointId           string
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://aws-cloudtrail-logs-237206024795-0c43aff5/AWSLogs/237206024795/CloudTrail/';
