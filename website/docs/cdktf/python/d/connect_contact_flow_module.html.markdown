---
subcategory: "Connect"
layout: "aws"
page_title: "AWS: aws_connect_contact_flow_module"
description: |-
  Provides details about a specific Amazon Connect Contact Flow Module.
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_connect_contact_flow_module

Provides details about a specific Amazon Connect Contact Flow Module.

## Example Usage

By `name`

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_connect_contact_flow_module import DataAwsConnectContactFlowModule
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        DataAwsConnectContactFlowModule(self, "example",
            instance_id="aaaaaaaa-bbbb-cccc-dddd-111111111111",
            name="example"
        )
```

By `contact_flow_module_id`

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_connect_contact_flow_module import DataAwsConnectContactFlowModule
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        DataAwsConnectContactFlowModule(self, "example",
            contact_flow_module_id="cccccccc-bbbb-cccc-dddd-111111111111",
            instance_id="aaaaaaaa-bbbb-cccc-dddd-111111111111"
        )
```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `contact_flow_module_id` - (Optional) Returns information on a specific Contact Flow Module by contact flow module id
* `instance_id` - (Required) Reference to the hosting Amazon Connect Instance
* `name` - (Optional) Returns information on a specific Contact Flow Module by name

~> **NOTE:** `instance_id` and one of either `name` or `contact_flow_module_id` is required.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `arn` - ARN of the Contact Flow Module.
* `content` - Logic of the Contact Flow Module.
* `description` - Description of the Contact Flow Module.
* `tags` - Map of tags to assign to the Contact Flow Module.
* `state` - Type of Contact Flow Module Module. Values are either `ACTIVE` or `ARCHIVED`.
* `status` - Status of the Contact Flow Module Module. Values are either `PUBLISHED` or `SAVED`.

<!-- cache-key: cdktf-0.20.8 input-a0d234c880a8e9c9c7992a266ae48b299ddc59343a4696158bc34c815e6049e7 -->