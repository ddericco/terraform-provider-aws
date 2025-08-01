---
subcategory: "ECS (Elastic Container)"
layout: "aws"
page_title: "AWS: aws_ecs_service"
description: |-
    Provides details about an ecs service
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_ecs_service

The ECS Service data source allows access to details of a specific
Service within a AWS ECS Cluster.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_ecs_service import DataAwsEcsService
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        DataAwsEcsService(self, "example",
            cluster_arn=Token.as_string(data_aws_ecs_cluster_example.arn),
            service_name="example"
        )
```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `service_name` - (Required) Name of the ECS Service
* `cluster_arn` - (Required) ARN of the ECS Cluster

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `arn` - ARN of the ECS Service
* `desired_count` - Number of tasks for the ECS Service
* `launch_type` - Launch type for the ECS Service
* `scheduling_strategy` - Scheduling strategy for the ECS Service
* `task_definition` - Family for the latest ACTIVE revision or full ARN of the task definition.
* `tags` - Resource tags.

<!-- cache-key: cdktf-0.20.8 input-5b8733268565a22b6ada6c1d07bd05eaf0a2dcf7c95ea724f2e08f688157367c -->