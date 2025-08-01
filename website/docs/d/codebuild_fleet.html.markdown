---
subcategory: "CodeBuild"
layout: "aws"
page_title: "AWS: aws_codebuild_fleet"
description: |-
  Retrieve information about an CodeBuild Fleet
---

# Data Source: aws_codebuild_fleet

Retrieve information about an CodeBuild Fleet.

## Example Usage

```terraform
data "aws_codebuild_fleet" "test" {
  name = aws_codebuild_fleet.test.name
}

resource "aws_codebuild_fleet" "test" {
  base_capacity     = 2
  compute_type      = "BUILD_GENERAL1_SMALL"
  environment_type  = "LINUX_CONTAINER"
  name              = "full-example-codebuild-fleet"
  overflow_behavior = "QUEUE"

  scaling_configuration {
    max_capacity = 5
    scaling_type = "TARGET_TRACKING_SCALING"

    target_tracking_scaling_configs {
      metric_type  = "FLEET_UTILIZATION_RATE"
      target_value = 97.5
    }
  }
}
```

### Basic Usage

```terraform
data "aws_codebuild_fleet" "example" {
  name = "my-codebuild-fleet-name"
}
```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `name` - (Required) Fleet name.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `arn` - ARN of the Fleet.
* `base_capacity` - Number of machines allocated to the ﬂeet.
* `compute_configuration` - Compute configuration of the compute fleet.
    * `disk` - Amount of disk space of the instance type included in the fleet.
    * `instance_type` - EC2 instance type in the fleet.
    * `machine_type` - Machine type of the instance type included in the fleet.
    * `memory` - Amount of memory of the instance type included in the fleet.
    * `vcpu` - Number of vCPUs of the instance type included in the fleet.
* `compute_type` - Compute resources the compute fleet uses.
* `created` - Creation time of the fleet.
* `environment_type` - Environment type of the compute fleet.
* `fleet_service_role` - The service role associated with the compute fleet.
* `id` - ARN of the Fleet.
* `image_id` - The Amazon Machine Image (AMI) of the compute fleet.
* `last_modified` - Last modification time of the fleet.
* `overflow_behavior` - Overflow behavior for compute fleet.
* `scaling_configuration` -  Nested attribute containing information about the scaling configuration.
    * `desired_capacity` - The desired number of instances in the ﬂeet when auto-scaling.
    * `max_capacity` - The maximum number of instances in the ﬂeet when auto-scaling.
    * `scaling_type` - The scaling type for a compute fleet.
    * `target_tracking_scaling_configs` - Nested attribute containing information about thresholds when new instance is auto-scaled into the compute fleet.
        * `metric_type` - The metric type to determine auto-scaling.
        * `target_value` - The value of metric_type when to start scaling.
* `status` - Nested attribute containing information about the current status of the fleet.
    * `context` - Additional information about a compute fleet.
    * `message` - Message associated with the status of a compute fleet.
    * `status_code` - Status code of the compute fleet.
* `tags` - Mapping of Key-Value tags for the resource.
* `vpc_config` - Nested attribute containing information about the VPC configuration.
    * `security_group_ids` - A list of one or more security groups IDs in your Amazon VPC.
    * `subnets` - A list of one or more subnet IDs in your Amazon VPC.
    * `vpc_id` - The ID of the Amazon VPC.
