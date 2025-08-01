---
subcategory: "MemoryDB"
layout: "aws"
page_title: "AWS: aws_memorydb_parameter_group"
description: |-
  Provides information about a MemoryDB Parameter Group.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_memorydb_parameter_group

Provides information about a MemoryDB Parameter Group.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_memorydb_parameter_group import DataAwsMemorydbParameterGroup
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        DataAwsMemorydbParameterGroup(self, "example",
            name="my-parameter-group"
        )
```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `name` - (Required) Name of the parameter group.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `id` - Name of the parameter group.
* `arn` - ARN of the parameter group.
* `description` - Description of the parameter group.
* `family` - Engine version that the parameter group can be used with.
* `parameter` - Set of user-defined MemoryDB parameters applied by the parameter group.
    * `name` - Name of the parameter.
    * `value` - Value of the parameter.
* `tags` - Map of tags assigned to the parameter group.

<!-- cache-key: cdktf-0.20.8 input-74097601d6aac5fab8a8014aefac165f70f534ca1731830303f3466e8242bb9a -->