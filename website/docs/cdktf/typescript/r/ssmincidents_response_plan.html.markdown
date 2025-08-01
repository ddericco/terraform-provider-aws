---
subcategory: "SSM Incident Manager Incidents"
layout: "aws"
page_title: "AWS: aws_ssmincidents_response_plan"
description: |-
  Terraform resource for managing an incident response plan in AWS Systems Manager Incident Manager.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_ssmincidents_response_plan

Provides a Terraform resource to manage response plans in AWS Systems Manager Incident Manager.

~> NOTE: A response plan implicitly depends on a replication set. If you configured your replication set in Terraform, we recommend you add it to the `dependsOn` argument for the Terraform ResponsePlan Resource.

## Example Usage

### Basic Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { SsmincidentsResponsePlan } from "./.gen/providers/aws/ssmincidents-response-plan";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new SsmincidentsResponsePlan(this, "example", {
      dependsOn: [awsSsmincidentsReplicationSetExample],
      incidentTemplate: {
        impact: Token.asNumber("3"),
        title: "title",
      },
      name: "name",
      tags: {
        key: "value",
      },
    });
  }
}

```

### Usage With All Fields

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { SsmincidentsResponsePlan } from "./.gen/providers/aws/ssmincidents-response-plan";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new SsmincidentsResponsePlan(this, "example", {
      action: {
        ssmAutomation: [
          {
            documentName: document1.name,
            documentVersion: "version1",
            dynamicParameters: {
              anotherKey: "INCIDENT_RECORD_ARN",
              someKey: "INVOLVED_RESOURCES",
            },
            parameter: [
              {
                name: "key",
                values: ["value1", "value2"],
              },
              {
                name: "foo",
                values: ["bar"],
              },
            ],
            roleArn: role1.arn,
            targetAccount: "RESPONSE_PLAN_OWNER_ACCOUNT",
          },
        ],
      },
      chatChannel: [topic.arn],
      dependsOn: [awsSsmincidentsReplicationSetExample],
      displayName: "display name",
      engagements: [
        "arn:aws:ssm-contacts:us-east-2:111122223333:contact/test1",
      ],
      incidentTemplate: {
        dedupeString: "dedupe",
        impact: Token.asNumber("3"),
        incidentTags: {
          key: "value",
        },
        notificationTarget: [
          {
            snsTopicArn: example1.arn,
          },
          {
            snsTopicArn: example2.arn,
          },
        ],
        summary: "summary",
        title: "title",
      },
      integration: {
        pagerduty: [
          {
            name: "pagerdutyIntergration",
            secretId: "example",
            serviceId: "example",
          },
        ],
      },
      name: "name",
      tags: {
        key: "value",
      },
    });
  }
}

```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `name` - (Required) The name of the response plan.
* `incidentTemplate` - (Required) The `incidentTemplate` configuration block is required and supports the following arguments:
    * `title` - (Required) The title of a generated incident.
    * `impact` - (Required) The impact value of a generated incident. The following values are supported:
        * `1` - Severe Impact
        * `2` - High Impact
        * `3` - Medium Impact
        * `4` - Low Impact
        * `5` - No Impact
    * `dedupeString` - (Optional) A string used to stop Incident Manager from creating multiple incident records for the same incident.
    * `incidentTags` - (Optional) The tags assigned to an incident template. When an incident starts, Incident Manager assigns the tags specified in the template to the incident.
    * `summary` - (Optional) The summary of an incident.
    * `notificationTarget` - (Optional) The Amazon Simple Notification Service (Amazon SNS) targets that this incident notifies when it is updated. The `notificationTarget` configuration block supports the following argument:
        * `snsTopicArn` - (Required) The ARN of the Amazon SNS topic.
* `tags` - (Optional) The tags applied to the response plan.
* `displayName` - (Optional) The long format of the response plan name. This field can contain spaces.
* `chatChannel` - (Optional) The Chatbot chat channel used for collaboration during an incident.
* `engagements` - (Optional) The Amazon Resource Name (ARN) for the contacts and escalation plans that the response plan engages during an incident.
* `action` - (Optional) The actions that the response plan starts at the beginning of an incident.
    * `ssmAutomation` - (Optional) The Systems Manager automation document to start as the runbook at the beginning of the incident. The following values are supported:
        * `documentName` - (Required) The automation document's name.
        * `roleArn` - (Required) The Amazon Resource Name (ARN) of the role that the automation document assumes when it runs commands.
        * `documentVersion` - (Optional) The version of the automation document to use at runtime.
        * `targetAccount` -  (Optional) The account that the automation document runs in. This can be in either the management account or an application account.
        * `parameter` - (Optional) The key-value pair parameters to use when the automation document runs. The following values are supported:
            * `name` - The name of parameter.
            * `values` - The values for the associated parameter name.
        * `dynamicParameters` - (Optional) The key-value pair to resolve dynamic parameter values when processing a Systems Manager Automation runbook.
* `integration` - (Optional) Information about third-party services integrated into the response plan. The following values are supported:
    * `pagerduty` - (Optional) Details about the PagerDuty configuration for a response plan. The following values are supported:
        * `name` - (Required) The name of the PagerDuty configuration.
        * `serviceId` - (Required) The ID of the PagerDuty service that the response plan associated with the incident at launch.
        * `secretId` - (Required) The ID of the AWS Secrets Manager secret that stores your PagerDuty key &mdash; either a General Access REST API Key or User Token REST API Key &mdash; and other user credentials.

For more information about the constraints for each field, see [CreateResponsePlan](https://docs.aws.amazon.com/incident-manager/latest/APIReference/API_CreateResponsePlan.html) in the *AWS Systems Manager Incident Manager API Reference*.
  
## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - The ARN of the response plan.
* `tagsAll` - A map of tags assigned to the resource, including those inherited from the provider [`defaultTags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block).

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import an Incident Manager response plan using the response plan ARN. You can find the response plan ARN in the AWS Management Console. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { SsmincidentsResponsePlan } from "./.gen/providers/aws/ssmincidents-response-plan";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    SsmincidentsResponsePlan.generateConfigForImport(
      this,
      "responsePlanName",
      "ARNValue"
    );
  }
}

```

Using `terraform import`, import an Incident Manager response plan using the response plan ARN. You can find the response plan ARN in the AWS Management Console. For example:

```console
% terraform import aws_ssmincidents_response_plan.responsePlanName ARNValue
```

<!-- cache-key: cdktf-0.20.8 input-86bfb1208d28a313aea7035eff8f46797a526ad3fe513fb64e426e0e2b854a7a -->