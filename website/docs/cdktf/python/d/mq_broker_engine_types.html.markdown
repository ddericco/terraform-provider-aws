---
subcategory: "MQ"
layout: "aws"
page_title: "AWS: aws_mq_broker_engine_types"
description: |-
  Provides details about available MQ broker engine types.
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_mq_broker_engine_types

Provides details about available MQ broker engine types. Use this data source to retrieve supported engine types and their versions for Amazon MQ brokers.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_mq_broker_engine_types import DataAwsMqBrokerEngineTypes
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        DataAwsMqBrokerEngineTypes(self, "example",
            engine_type="ACTIVEMQ"
        )
```

## Argument Reference

This data source supports the following arguments:

* `engine_type` - (Optional) MQ engine type to return version details for.
* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `broker_engine_types` - List of available engine types and versions. See [Engine Types](#engine-types).

### Engine Types

* `engine_type` - Broker's engine type.
* `engine_versions` - List of engine versions. See [Engine Versions](#engine-versions).

### Engine Versions

* `name` - Name of the engine version.

<!-- cache-key: cdktf-0.20.8 input-3b789b146335da98a97819deda3a6feb61a8fe168de033accf142fdc549dfb00 -->