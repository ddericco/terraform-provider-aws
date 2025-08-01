---
subcategory: "Transit Gateway"
layout: "aws"
page_title: "AWS: aws_ec2_transit_gateway_default_route_table_association"
description: |-
  Terraform resource for managing an AWS EC2 (Elastic Compute Cloud) Transit Gateway Default Route Table Association.
---

<!-- Please do not edit this file, it is generated. -->
# Resource: aws_ec2_transit_gateway_default_route_table_association

Terraform resource for managing an AWS EC2 (Elastic Compute Cloud) Transit Gateway Default Route Table Association.

## Example Usage

### Basic Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { Ec2TransitGatewayDefaultRouteTableAssociation } from "./.gen/providers/aws/ec2-transit-gateway-default-route-table-association";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new Ec2TransitGatewayDefaultRouteTableAssociation(this, "example", {
      transitGatewayId: Token.asString(awsEc2TransitGatewayExample.id),
      transitGatewayRouteTableId: Token.asString(
        awsEc2TransitGatewayRouteTableExample.id
      ),
    });
  }
}

```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `transitGatewayId` - (Required) ID of the Transit Gateway to change the default association route table on.
* `transitGatewayRouteTableId` - (Required) ID of the Transit Gateway Route Table to be made the default association route table.

## Attribute Reference

This resource exports no additional attributes.

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

* `create` - (Default `5m`)
* `update` - (Default `5m`)
* `delete` - (Default `5m`)

<!-- cache-key: cdktf-0.20.8 input-7068dbf1692fd40c2fc006cbdde9f7e1503a1c0dfc216527b3b00508a458a71a -->