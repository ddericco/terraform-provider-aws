---
subcategory: "Transit Gateway"
layout: "aws"
page_title: "AWS: aws_ec2_transit_gateway_multicast_group_member"
description: |-
  Manages an EC2 Transit Gateway Multicast Group Member
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_ec2_transit_gateway_multicast_group_member

Registers members (network interfaces) with the transit gateway multicast group.
A member is a network interface associated with a supported EC2 instance that receives multicast traffic.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.ec2_transit_gateway_multicast_group_member import Ec2TransitGatewayMulticastGroupMember
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        Ec2TransitGatewayMulticastGroupMember(self, "example",
            group_ip_address="224.0.0.1",
            network_interface_id=Token.as_string(aws_network_interface_example.id),
            transit_gateway_multicast_domain_id=Token.as_string(aws_ec2_transit_gateway_multicast_domain_example.id)
        )
```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `group_ip_address` - (Required) The IP address assigned to the transit gateway multicast group.
* `network_interface_id` - (Required) The group members' network interface ID to register with the transit gateway multicast group.
* `transit_gateway_multicast_domain_id` - (Required) The ID of the transit gateway multicast domain.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `id` - EC2 Transit Gateway Multicast Group Member identifier.

<!-- cache-key: cdktf-0.20.8 input-505a25f71ba1923c6c78d90ea4ecc144df402cd0cdbcc7908b65827e8fea807d -->