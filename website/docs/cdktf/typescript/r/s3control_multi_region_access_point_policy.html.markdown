---
subcategory: "S3 Control"
layout: "aws"
page_title: "AWS: aws_s3control_multi_region_access_point_policy"
description: |-
  Provides a resource to manage an S3 Multi-Region Access Point access control policy.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_s3control_multi_region_access_point_policy

Provides a resource to manage an S3 Multi-Region Access Point access control policy.

## Example Usage

### Basic Example

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Fn, Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsCallerIdentity } from "./.gen/providers/aws/data-aws-caller-identity";
import { DataAwsPartition } from "./.gen/providers/aws/data-aws-partition";
import { S3Bucket } from "./.gen/providers/aws/s3-bucket";
import { S3ControlMultiRegionAccessPoint } from "./.gen/providers/aws/s3-control-multi-region-access-point";
import { S3ControlMultiRegionAccessPointPolicy } from "./.gen/providers/aws/s3-control-multi-region-access-point-policy";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    const fooBucket = new S3Bucket(this, "foo_bucket", {
      bucket: "example-bucket-foo",
    });
    const example = new S3ControlMultiRegionAccessPoint(this, "example", {
      details: {
        name: "example",
        region: [
          {
            bucket: fooBucket.id,
          },
        ],
      },
    });
    const current = new DataAwsCallerIdentity(this, "current", {});
    const dataAwsPartitionCurrent = new DataAwsPartition(this, "current_3", {});
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    dataAwsPartitionCurrent.overrideLogicalId("current");
    const awsS3ControlMultiRegionAccessPointPolicyExample =
      new S3ControlMultiRegionAccessPointPolicy(this, "example_4", {
        details: {
          name: Token.asString(Fn.element(Fn.split(":", example.id), 1)),
          policy: Token.asString(
            Fn.jsonencode({
              Statement: [
                {
                  Action: ["s3:GetObject", "s3:PutObject"],
                  Effect: "Allow",
                  Principal: {
                    AWS: current.accountId,
                  },
                  Resource:
                    "arn:${" +
                    dataAwsPartitionCurrent.partition +
                    "}:s3::${" +
                    current.accountId +
                    "}:accesspoint/${" +
                    example.alias +
                    "}/object/*",
                  Sid: "Example",
                },
              ],
              Version: "2012-10-17",
            })
          ),
        },
      });
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    awsS3ControlMultiRegionAccessPointPolicyExample.overrideLogicalId(
      "example"
    );
  }
}

```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `accountId` - (Optional) The AWS account ID for the owner of the Multi-Region Access Point. Defaults to automatically determined account ID of the Terraform AWS provider.
* `details` - (Required) A configuration block containing details about the policy for the Multi-Region Access Point. See [Details Configuration Block](#details-configuration) below for more details

### Details Configuration

The `details` block supports the following:

* `name` - (Required) The name of the Multi-Region Access Point.
* `policy` - (Required) A valid JSON document that specifies the policy that you want to associate with this Multi-Region Access Point. Once applied, the policy can be edited, but not deleted. For more information, see the documentation on [Multi-Region Access Point Permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiRegionAccessPointPermissions.html).

-> **NOTE:** When you update the `policy`, the update is first listed as the proposed policy. After the update is finished and all Regions have been updated, the proposed policy is listed as the established policy. If both policies have the same version number, the proposed policy is the established policy.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `established` - The last established policy for the Multi-Region Access Point.
* `id` - The AWS account ID and access point name separated by a colon (`:`).
* `proposed` - The proposed policy for the Multi-Region Access Point.

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

* `create` - (Default `15m`)
* `update` - (Default `15m`)

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import Multi-Region Access Point Policies using the `accountId` and `name` of the Multi-Region Access Point separated by a colon (`:`). For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { S3ControlMultiRegionAccessPointPolicy } from "./.gen/providers/aws/s3-control-multi-region-access-point-policy";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    S3ControlMultiRegionAccessPointPolicy.generateConfigForImport(
      this,
      "example",
      "123456789012:example"
    );
  }
}

```

Using `terraform import`, import Multi-Region Access Point Policies using the `accountId` and `name` of the Multi-Region Access Point separated by a colon (`:`). For example:

```console
% terraform import aws_s3control_multi_region_access_point_policy.example 123456789012:example
```

<!-- cache-key: cdktf-0.20.8 input-88e044392f2cdb313f2543f6b26f6814fc784996d5e333594b344ff8e8e6cae5 -->