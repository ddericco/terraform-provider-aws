---
subcategory: "CloudWatch Logs"
layout: "aws"
page_title: "AWS: aws_cloudwatch_log_group"
description: |-
  Provides a CloudWatch Log Group resource.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_cloudwatch_log_group

Provides a CloudWatch Log Group resource.

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { CloudwatchLogGroup } from "./.gen/providers/aws/cloudwatch-log-group";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new CloudwatchLogGroup(this, "yada", {
      name: "Yada",
      tags: {
        Application: "serviceA",
        Environment: "production",
      },
    });
  }
}

```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `name` - (Optional, Forces new resource) The name of the log group. If omitted, Terraform will assign a random, unique name.
* `namePrefix` - (Optional, Forces new resource) Creates a unique name beginning with the specified prefix. Conflicts with `name`.
* `skipDestroy` - (Optional) Set to true if you do not wish the log group (and any logs it may contain) to be deleted at destroy time, and instead just remove the log group from the Terraform state.
* `logGroupClass` - (Optional) Specified the log class of the log group. Possible values are: `STANDARD`, `INFREQUENT_ACCESS`, or `DELIVERY`.
* `retentionInDays` - (Optional) Specifies the number of days
  you want to retain log events in the specified log group.  Possible values are: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653, and 0.
  If you select 0, the events in the log group are always retained and never expire. If `logGroupClass` is set to `DELIVERY`, this argument is ignored and `retentionInDays` is forcibly set to 2.
* `kmsKeyId` - (Optional) The ARN of the KMS Key to use when encrypting log data. Please note, after the AWS KMS CMK is disassociated from the log group,
AWS CloudWatch Logs stops encrypting newly ingested data for the log group. All previously ingested data remains encrypted, and AWS CloudWatch Logs requires
permissions for the CMK whenever the encrypted data is requested.
* `tags` - (Optional) A map of tags to assign to the resource. If configured with a provider [`defaultTags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - The Amazon Resource Name (ARN) specifying the log group. Any `:*` suffix added by the API, denoting all CloudWatch Log Streams under the CloudWatch Log Group, is removed for greater compatibility with other AWS services that do not accept the suffix.
* `tagsAll` - A map of tags assigned to the resource, including those inherited from the provider [`defaultTags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block).

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import Cloudwatch Log Groups using the `name`. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { CloudwatchLogGroup } from "./.gen/providers/aws/cloudwatch-log-group";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    CloudwatchLogGroup.generateConfigForImport(this, "testGroup", "yada");
  }
}

```

Using `terraform import`, import Cloudwatch Log Groups using the `name`. For example:

```console
% terraform import aws_cloudwatch_log_group.test_group yada
```

<!-- cache-key: cdktf-0.20.8 input-04f19ef86e60651ec6a077feefb3858e19351a67349374b4326895e74bc37107 -->