---
subcategory: "IoT Core"
layout: "aws"
page_title: "AWS: aws_iot_topic_rule"
description: |-
    Creates and manages an AWS IoT topic rule
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_iot_topic_rule

Creates and manages an AWS IoT topic rule.

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsIamPolicyDocument } from "./.gen/providers/aws/data-aws-iam-policy-document";
import { IamRole } from "./.gen/providers/aws/iam-role";
import { IamRolePolicy } from "./.gen/providers/aws/iam-role-policy";
import { IotTopicRule } from "./.gen/providers/aws/iot-topic-rule";
import { SnsTopic } from "./.gen/providers/aws/sns-topic";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    const myerrortopic = new SnsTopic(this, "myerrortopic", {
      name: "myerrortopic",
    });
    const mytopic = new SnsTopic(this, "mytopic", {
      name: "mytopic",
    });
    const assumeRole = new DataAwsIamPolicyDocument(this, "assume_role", {
      statement: [
        {
          actions: ["sts:AssumeRole"],
          effect: "Allow",
          principals: [
            {
              identifiers: ["iot.amazonaws.com"],
              type: "Service",
            },
          ],
        },
      ],
    });
    const mypolicy = new DataAwsIamPolicyDocument(this, "mypolicy", {
      statement: [
        {
          actions: ["sns:Publish"],
          effect: "Allow",
          resources: [mytopic.arn],
        },
      ],
    });
    const myrole = new IamRole(this, "myrole", {
      assumeRolePolicy: Token.asString(assumeRole.json),
      name: "myrole",
    });
    const awsIamRolePolicyMypolicy = new IamRolePolicy(this, "mypolicy_5", {
      name: "mypolicy",
      policy: Token.asString(mypolicy.json),
      role: myrole.id,
    });
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    awsIamRolePolicyMypolicy.overrideLogicalId("mypolicy");
    new IotTopicRule(this, "rule", {
      description: "Example rule",
      enabled: true,
      errorAction: {
        sns: {
          messageFormat: "RAW",
          roleArn: role.arn,
          targetArn: myerrortopic.arn,
        },
      },
      name: "MyRule",
      sns: [
        {
          messageFormat: "RAW",
          roleArn: role.arn,
          targetArn: mytopic.arn,
        },
      ],
      sql: "SELECT * FROM 'topic/test'",
      sqlVersion: "2016-03-23",
    });
  }
}

```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `name` - (Required) The name of the rule.
* `description` - (Optional) The description of the rule.
* `enabled` - (Required) Specifies whether the rule is enabled.
* `sql` - (Required) The SQL statement used to query the topic. For more information, see AWS IoT SQL Reference (http://docs.aws.amazon.com/iot/latest/developerguide/iot-rules.html#aws-iot-sql-reference) in the AWS IoT Developer Guide.
* `sqlVersion` - (Required) The version of the SQL rules engine to use when evaluating the rule.
* `errorAction` - (Optional) Configuration block with error action to be associated with the rule. See the documentation for `cloudwatchAlarm`, `cloudwatchLogs`, `cloudwatchMetric`, `dynamodb`, `dynamodbv2`, `elasticsearch`, `firehose`, `http`, `iotAnalytics`, `iotEvents`, `kafka`, `kinesis`, `lambda`, `republish`, `s3`, `sns`, `sqs`, `stepFunctions`, `timestream` configuration blocks for further configuration details.
* `tags` - (Optional) Key-value map of resource tags. If configured with a provider [`defaultTags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.

The `cloudwatchAlarm` object takes the following arguments:

* `alarmName` - (Required) The CloudWatch alarm name.
* `roleArn` - (Required) The IAM role ARN that allows access to the CloudWatch alarm.
* `stateReason` - (Required) The reason for the alarm change.
* `stateValue` - (Required) The value of the alarm state. Acceptable values are: OK, ALARM, INSUFFICIENT_DATA.

The `cloudwatchLogs` object takes the following arguments:

* `batchMode` - (Optional) The payload that contains a JSON array of records will be sent to CloudWatch via a batch call.
* `logGroupName` - (Required) The CloudWatch log group name.
* `roleArn` - (Required) The IAM role ARN that allows access to the CloudWatch alarm.

The `cloudwatchMetric` object takes the following arguments:

* `metricName` - (Required) The CloudWatch metric name.
* `metricNamespace` - (Required) The CloudWatch metric namespace name.
* `metricTimestamp` - (Optional) An optional Unix timestamp (http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/cloudwatch_concepts.html#about_timestamp).
* `metricUnit` - (Required) The metric unit (supported units can be found here: http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/cloudwatch_concepts.html#Unit)
* `metricValue` - (Required) The CloudWatch metric value.
* `roleArn` - (Required) The IAM role ARN that allows access to the CloudWatch metric.

The `dynamodb` object takes the following arguments:

* `hashKeyField` - (Required) The hash key name.
* `hashKeyType` - (Optional) The hash key type. Valid values are "STRING" or "NUMBER".
* `hashKeyValue` - (Required) The hash key value.
* `payloadField` - (Optional) The action payload.
* `rangeKeyField` - (Optional) The range key name.
* `rangeKeyType` - (Optional) The range key type. Valid values are "STRING" or "NUMBER".
* `rangeKeyValue` - (Optional) The range key value.
* `operation` - (Optional) The operation. Valid values are "INSERT", "UPDATE", or "DELETE".
* `roleArn` - (Required) The ARN of the IAM role that grants access to the DynamoDB table.
* `tableName` - (Required) The name of the DynamoDB table.

The `dynamodbv2` object takes the following arguments:

* `putItem` - (Required) Configuration block with DynamoDB Table to which the message will be written. Nested arguments below.
    * `tableName` - (Required) The name of the DynamoDB table.
* `roleArn` - (Required) The ARN of the IAM role that grants access to the DynamoDB table.

The `elasticsearch` object takes the following arguments:

* `endpoint` - (Required) The endpoint of your Elasticsearch domain.
* `id` - (Required) The unique identifier for the document you are storing.
* `index` - (Required) The Elasticsearch index where you want to store your data.
* `roleArn` - (Required) The IAM role ARN that has access to Elasticsearch.
* `type` - (Required) The type of document you are storing.

The `firehose` object takes the following arguments:

* `deliveryStreamName` - (Required) The delivery stream name.
* `roleArn` - (Required) The IAM role ARN that grants access to the Amazon Kinesis Firehose stream.
* `separator` - (Optional) A character separator that is used to separate records written to the Firehose stream. Valid values are: '\n' (newline), '\t' (tab), '\r\n' (Windows newline), ',' (comma).
* `batchMode` - (Optional) The payload that contains a JSON array of records will be sent to Kinesis Firehose via a batch call.

The `http` object takes the following arguments:

* `url` - (Required) The HTTPS URL.
* `confirmationUrl` - (Optional) The HTTPS URL used to verify ownership of `url`.
* `httpHeader` - (Optional) Custom HTTP header IoT Core should send. It is possible to define more than one custom header.

The `httpHeader` object takes the following arguments:

* `key` - (Required) The name of the HTTP header.
* `value` - (Required) The value of the HTTP header.

The `iotAnalytics` object takes the following arguments:

* `channelName` - (Required) Name of AWS IOT Analytics channel.
* `roleArn` - (Required) The ARN of the IAM role that grants access.
* `batchMode` - (Optional) The payload that contains a JSON array of records will be sent to IoT Analytics via a batch call.

The `iotEvents` object takes the following arguments:

* `inputName` - (Required) The name of the AWS IoT Events input.
* `roleArn` - (Required) The ARN of the IAM role that grants access.
* `messageId` - (Optional) Use this to ensure that only one input (message) with a given messageId is processed by an AWS IoT Events detector.
* `batchMode` - (Optional) The payload that contains a JSON array of records will be sent to IoT Events via a batch call.

The `kafka` object takes the following arguments:

* `clientProperties` - (Required) Properties of the Apache Kafka producer client. For more info, see the [AWS documentation](https://docs.aws.amazon.com/iot/latest/developerguide/apache-kafka-rule-action.html).
* `destinationArn` - (Required) The ARN of Kafka action's VPC [`aws_iot_topic_rule_destination`](iot_topic_rule_destination.html).
* `header` - (Optional) The list of Kafka headers that you specify. Nested arguments below.
    * `key` - (Required) The key of the Kafka header.
    * `value` - (Required) The value of the Kafka header.
* `key` - (Optional) The Kafka message key.
* `partition` - (Optional) The Kafka message partition.
* `topic` - (Optional) The Kafka topic for messages to be sent to the Kafka broker.

The `kinesis` object takes the following arguments:

* `partitionKey` - (Optional) The partition key.
* `roleArn` - (Required) The ARN of the IAM role that grants access to the Amazon Kinesis stream.
* `streamName` - (Required) The name of the Amazon Kinesis stream.

The `lambda` object takes the following arguments:

* `functionArn` - (Required) The ARN of the Lambda function.

The `republish` object takes the following arguments:

* `roleArn` - (Required) The ARN of the IAM role that grants access.
* `topic` - (Required) The name of the MQTT topic the message should be republished to.
* `qos` - (Optional) The Quality of Service (QoS) level to use when republishing messages. Valid values are 0 or 1. The default value is 0.

The `s3` object takes the following arguments:

* `bucketName` - (Required) The Amazon S3 bucket name.
* `cannedAcl` - (Optional) The Amazon S3 canned ACL that controls access to the object identified by the object key. [Valid values](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#canned-acl).
* `key` - (Required) The object key.
* `roleArn` - (Required) The ARN of the IAM role that grants access.

The `sns` object takes the following arguments:

* `messageFormat` - (Required) The message format of the message to publish. Accepted values are "JSON" and "RAW".
* `roleArn` - (Required) The ARN of the IAM role that grants access.
* `targetArn` - (Required) The ARN of the SNS topic.

The `sqs` object takes the following arguments:

* `queueUrl` - (Required) The URL of the Amazon SQS queue.
* `roleArn` - (Required) The ARN of the IAM role that grants access.
* `useBase64` - (Required) Specifies whether to use Base64 encoding.

The `stepFunctions` object takes the following arguments:

* `executionNamePrefix` - (Optional) The prefix used to generate, along with a UUID, the unique state machine execution name.
* `stateMachineName` - (Required) The name of the Step Functions state machine whose execution will be started.
* `roleArn` - (Required) The ARN of the IAM role that grants access to start execution of the state machine.

The `timestream` object takes the following arguments:

* `databaseName` - (Required) The name of an Amazon Timestream database.
* `dimension` - (Required) Configuration blocks with metadata attributes of the time series that are written in each measure record. Nested arguments below.
    * `name` - (Required) The metadata dimension name. This is the name of the column in the Amazon Timestream database table record.
    * `value` - (Required) The value to write in this column of the database record.
* `roleArn` - (Required) The ARN of the role that grants permission to write to the Amazon Timestream database table.
* `tableName` - (Required) The name of the database table into which to write the measure records.
* `timestamp` - (Optional) Configuration block specifying an application-defined value to replace the default value assigned to the Timestream record's timestamp in the time column. Nested arguments below.
    * `unit` - (Required) The precision of the timestamp value that results from the expression described in value. Valid values: `SECONDS`, `MILLISECONDS`, `MICROSECONDS`, `NANOSECONDS`.
    * `value` - (Required) An expression that returns a long epoch time value.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `id` - The name of the topic rule
* `arn` - The ARN of the topic rule
* `tagsAll` - A map of tags assigned to the resource, including those inherited from the provider [`defaultTags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block).

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import IoT Topic Rules using the `name`. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { IotTopicRule } from "./.gen/providers/aws/iot-topic-rule";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    IotTopicRule.generateConfigForImport(this, "rule", "<name>");
  }
}

```

Using `terraform import`, import IoT Topic Rules using the `name`. For example:

```console
% terraform import aws_iot_topic_rule.rule <name>
```

<!-- cache-key: cdktf-0.20.8 input-8c47ffad2f9a4b9a8ecbefddfde63961fecc967d1991c264666a65d45aca693a -->