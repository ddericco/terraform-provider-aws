---
subcategory: "SNS (Simple Notification)"
layout: "aws"
page_title: "AWS: aws_sns_topic_policy"
description: |-
  Provides an SNS topic policy resource.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_sns_topic_policy

Provides an SNS topic policy resource

~> **NOTE:** If a Principal is specified as just an AWS account ID rather than an ARN, AWS silently converts it to the ARN for the root user, causing future terraform plans to differ. To avoid this problem, just specify the full ARN, e.g., `arn:aws:iam::123456789012:root`

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
import { SnsTopic } from "./.gen/providers/aws/sns-topic";
import { SnsTopicPolicy } from "./.gen/providers/aws/sns-topic-policy";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    const test = new SnsTopic(this, "test", {
      name: "my-topic-with-policy",
    });
    const snsTopicPolicy = new DataAwsIamPolicyDocument(
      this,
      "sns_topic_policy",
      {
        policyId: "__default_policy_ID",
        statement: [
          {
            actions: [
              "SNS:Subscribe",
              "SNS:SetTopicAttributes",
              "SNS:RemovePermission",
              "SNS:Receive",
              "SNS:Publish",
              "SNS:ListSubscriptionsByTopic",
              "SNS:GetTopicAttributes",
              "SNS:DeleteTopic",
              "SNS:AddPermission",
            ],
            condition: [
              {
                test: "StringEquals",
                values: [accountId.stringValue],
                variable: "AWS:SourceOwner",
              },
            ],
            effect: "Allow",
            principals: [
              {
                identifiers: ["*"],
                type: "AWS",
              },
            ],
            resources: [test.arn],
            sid: "__default_statement_ID",
          },
        ],
      }
    );
    new SnsTopicPolicy(this, "default", {
      arn: test.arn,
      policy: Token.asString(snsTopicPolicy.json),
    });
  }
}

```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `arn` - (Required) The ARN of the SNS topic
* `policy` - (Required) The fully-formed AWS policy as JSON. For more information about building AWS IAM policy documents with Terraform, see the [AWS IAM Policy Document Guide](https://learn.hashicorp.com/terraform/aws/iam-policy).

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `owner` - The AWS Account ID of the SNS topic owner

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import SNS Topic Policy using the topic ARN. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { SnsTopicPolicy } from "./.gen/providers/aws/sns-topic-policy";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    SnsTopicPolicy.generateConfigForImport(
      this,
      "userUpdates",
      "arn:aws:sns:us-west-2:123456789012:my-topic"
    );
  }
}

```

Using `terraform import`, import SNS Topic Policy using the topic ARN. For example:

```console
% terraform import aws_sns_topic_policy.user_updates arn:aws:sns:us-west-2:123456789012:my-topic
```

<!-- cache-key: cdktf-0.20.8 input-c022902cc8236bf2f9f29320c1fc0fcb0a9195879ac5b789b1e67b89becdf0f9 -->