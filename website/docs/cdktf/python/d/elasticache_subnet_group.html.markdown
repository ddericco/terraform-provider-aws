---
subcategory: "ElastiCache"
layout: "aws"
page_title: "AWS: aws_elasticache_subnet_group"
description: |-
  Provides information about a ElastiCache Subnet Group.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_elasticache_subnet_group

Provides information about a ElastiCache Subnet Group.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_elasticache_subnet_group import DataAwsElasticacheSubnetGroup
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        DataAwsElasticacheSubnetGroup(self, "example",
            name="my-subnet-group"
        )
```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `name` - (Required) Name of the subnet group.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `id` - Name of the subnet group.
* `arn` - ARN of the subnet group.
* `description` - Description of the subnet group.
* `subnet_ids` - Set of VPC Subnet ID-s of the subnet group.
* `tags` - Map of tags assigned to the subnet group.
* `vpc_id` - The Amazon Virtual Private Cloud identifier (VPC ID) of the cache subnet group.

<!-- cache-key: cdktf-0.20.8 input-f9a21b2fbc7c61b3346edad8192e39cc9ea2d3d16560884554ea139a2325e724 -->