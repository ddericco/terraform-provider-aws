---
subcategory: "EC2 (Elastic Compute Cloud)"
layout: "aws"
page_title: "AWS: aws_ec2_capacity_block_reservation"
description: |-
  Provides an EC2 Capacity Block Reservation. This allows you to purchase capacity block for your Amazon EC2 instances in a specific Availability Zone for machine learning (ML) Workloads.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_ec2_capacity_block_reservation

Provides an EC2 Capacity Block Reservation. This allows you to purchase capacity block for your Amazon EC2 instances in a specific Availability Zone for machine learning (ML) Workloads.

~> **NOTE:** Once created, a reservation is valid for the `duration` of the provided `capacityBlockOfferingId` and cannot be deleted. Performing a `destroy` will only remove the resource from state. For more information see [EC2 Capacity Block Reservation Documentation](https://aws.amazon.com/ec2/instance-types/p5/) and [PurchaseReservedDBInstancesOffering](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/capacity-blocks-pricing-billing.html).

~> **NOTE:** Due to the expense of testing this resource, we provide it as best effort. If you find it useful, and have the ability to help test or notice issues, consider reaching out to us on [GitHub](https://github.com/hashicorp/terraform-provider-aws).

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsEc2CapacityBlockOffering } from "./.gen/providers/aws/data-aws-ec2-capacity-block-offering";
import { Ec2CapacityBlockReservation } from "./.gen/providers/aws/ec2-capacity-block-reservation";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    const test = new DataAwsEc2CapacityBlockOffering(this, "test", {
      capacityDurationHours: 24,
      endDateRange: "2024-05-30T15:04:05Z",
      instanceCount: 1,
      instanceType: "p4d.24xlarge",
      startDateRange: "2024-04-28T15:04:05Z",
    });
    new Ec2CapacityBlockReservation(this, "example", {
      capacityBlockOfferingId: Token.asString(test.capacityBlockOfferingId),
      instancePlatform: "Linux/UNIX",
      tags: {
        Environment: "dev",
      },
    });
  }
}

```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `capacityBlockOfferingId` - (Required) The Capacity Block Reservation ID.
* `instancePlatform` - (Required) The type of operating system for which to reserve capacity. Valid options are `Linux/UNIX`, `Red Hat Enterprise Linux`, `SUSE Linux`, `Windows`, `Windows with SQL Server`, `Windows with SQL Server Enterprise`, `Windows with SQL Server Standard` or `Windows with SQL Server Web`.
* `tags` - (Optional) A map of tags to assign to the resource. If configured with a provider [`defaultTags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - The ARN of the reservation.
* `availabilityZone` - The Availability Zone in which to create the Capacity Block Reservation.
* `createdDate` - The date and time at which the Capacity Block Reservation was created.
* `ebsOptimized` - Indicates whether the Capacity Reservation supports EBS-optimized instances.
* `endDate` - The date and time at which the Capacity Block Reservation expires. When a Capacity Block Reservation expires, the reserved capacity is released and you can no longer launch instances into it. Valid values: [RFC3339 time string](https://tools.ietf.org/html/rfc3339#section-5.8) (`YYYY-MM-DDTHH:MM:SSZ`)
* `endDateType` - Indicates the way in which the Capacity Reservation ends.
* `id` - The ID of the Capacity Block Reservation.
* `instanceCount` - The number of instances for which to reserve capacity.
* `instanceType` - The instance type for which to reserve capacity.
* `outpostArn` - The ARN of the Outpost on which to create the Capacity Block Reservation.
* `placementGroupArn` - The ARN of the placement group in which to create the Capacity Block Reservation.
* `reservationType` - The type of Capacity Reservation.
* `startDate` - The date and time at which the Capacity Block Reservation starts. Valid values: [RFC3339 time string](https://tools.ietf.org/html/rfc3339#section-5.8) (`YYYY-MM-DDTHH:MM:SSZ`)
* `tenancy` - Indicates the tenancy of the Capacity Block Reservation. Specify either `default` or `dedicated`.
* `tagsAll` - A map of tags assigned to the resource, including those inherited from the provider [`defaultTags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block)

<!-- cache-key: cdktf-0.20.8 input-a255b5237c1c6bd40840b5df4d5b418ef6095eb8c08f619abbddc42e5c972444 -->