---
subcategory: "Outposts"
layout: "aws"
page_title: "AWS: aws_outposts_outposts"
description: |-
  Provides details about multiple Outposts
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_outposts_outposts

Provides details about multiple Outposts.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_outposts_outposts import DataAwsOutpostsOutposts
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        DataAwsOutpostsOutposts(self, "example",
            site_id=id
        )
```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `availability_zone` - (Optional) Availability Zone name.
* `availability_zone_id` - (Optional) Availability Zone identifier.
* `site_id` - (Optional) Site identifier.
* `owner_id` - (Optional) AWS Account identifier of the Outpost owner.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `arns` - Set of Amazon Resource Names (ARNs).
* `id` - AWS Region.
* `ids` - Set of identifiers.

<!-- cache-key: cdktf-0.20.8 input-25e253353acf18a98898930ae71cea344223127ee301e20a7d17311cafcc7601 -->