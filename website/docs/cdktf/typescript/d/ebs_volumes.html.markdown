---
subcategory: "EBS (EC2)"
layout: "aws"
page_title: "AWS: aws_ebs_volumes"
description: |-
    Provides identifying information for EBS volumes matching given criteria
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_ebs_volumes

`aws_ebs_volumes` provides identifying information for EBS volumes matching given criteria.

This data source can be useful for getting a list of volume IDs with (for example) matching tags.

## Example Usage

The following demonstrates obtaining a map of availability zone to EBS volume ID for volumes with a given tag value.

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import {
  Token,
  TerraformIterator,
  TerraformOutput,
  TerraformStack,
} from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsEbsVolume } from "./.gen/providers/aws/data-aws-ebs-volume";
import { DataAwsEbsVolumes } from "./.gen/providers/aws/data-aws-ebs-volumes";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    const example = new DataAwsEbsVolumes(this, "example", {
      tags: {
        VolumeSet: "TestVolumeSet",
      },
    });
    /*In most cases loops should be handled in the programming language context and 
    not inside of the Terraform context. If you are looping over something external, e.g. a variable or a file input
    you should consider using a for loop. If you are looping over something only known to Terraform, e.g. a result of a data source
    you need to keep this like it is.*/
    const exampleForEachIterator = TerraformIterator.fromList(
      Token.asAny(example.ids)
    );
    const dataAwsEbsVolumeExample = new DataAwsEbsVolume(this, "example_1", {
      filter: [
        {
          name: "volume-id",
          values: [Token.asString(exampleForEachIterator.value)],
        },
      ],
      forEach: exampleForEachIterator,
    });
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    dataAwsEbsVolumeExample.overrideLogicalId("example");
    new TerraformOutput(this, "availability_zone_to_volume_id", {
      value:
        "${{ for s in ${" +
        dataAwsEbsVolumeExample.fqn +
        "} : s.id => s.availability_zone}}",
    });
  }
}

```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `filter` - (Optional) Custom filter block as described below.
* `tags` - (Optional) Map of tags, each pair of which must exactly match
  a pair on the desired volumes.

More complex filters can be expressed using one or more `filter` sub-blocks,
which take the following arguments:

* `name` - (Required) Name of the field to filter by, as defined by
  [the underlying AWS API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html).
  For example, if matching against the `size` filter, use:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsEbsVolumes } from "./.gen/providers/aws/data-aws-ebs-volumes";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new DataAwsEbsVolumes(this, "ten_or_twenty_gb_volumes", {
      filter: [
        {
          name: "size",
          values: ["10", "20"],
        },
      ],
    });
  }
}

```

* `values` - (Required) Set of values that are accepted for the given field.
  EBS Volume IDs will be selected if any one of the given values match.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `id` - AWS Region.
* `ids` - Set of all the EBS Volume IDs found. This data source will fail if
  no volumes match the provided criteria.

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

- `read` - (Default `20m`)

<!-- cache-key: cdktf-0.20.8 input-aca3009d90e03941ba871e80e9b7cce8ac783bd4f86da72c0de03dea50f8a632 -->