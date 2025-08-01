---
subcategory: "Transit Gateway"
layout: "aws"
page_title: "AWS: aws_ec2_transit_gateway_route_table_association"
description: |-
  Manages an EC2 Transit Gateway Route Table association
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_ec2_transit_gateway_route_table_association

Manages an EC2 Transit Gateway Route Table association.

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { Ec2TransitGatewayRouteTableAssociation } from "./.gen/providers/aws/ec2-transit-gateway-route-table-association";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new Ec2TransitGatewayRouteTableAssociation(this, "example", {
      transitGatewayAttachmentId: Token.asString(
        awsEc2TransitGatewayVpcAttachmentExample.id
      ),
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
* `transitGatewayAttachmentId` - (Required) Identifier of EC2 Transit Gateway Attachment.
* `transitGatewayRouteTableId` - (Required) Identifier of EC2 Transit Gateway Route Table.
* `replaceExistingAssociation` - (Optional) Boolean whether the Gateway Attachment should remove any current Route Table association before associating with the specified Route Table. Default value: `false`. This argument is intended for use with EC2 Transit Gateways shared into the current account, otherwise the `transitGatewayDefaultRouteTableAssociation` argument of the `aws_ec2_transit_gateway_vpc_attachment` resource should be used.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `id` - EC2 Transit Gateway Route Table identifier combined with EC2 Transit Gateway Attachment identifier
* `resourceId` - Identifier of the resource
* `resourceType` - Type of the resource

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import `aws_ec2_transit_gateway_route_table_association` using the EC2 Transit Gateway Route Table identifier, an underscore, and the EC2 Transit Gateway Attachment identifier. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { Ec2TransitGatewayRouteTableAssociation } from "./.gen/providers/aws/ec2-transit-gateway-route-table-association";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    Ec2TransitGatewayRouteTableAssociation.generateConfigForImport(
      this,
      "example",
      "tgw-rtb-12345678_tgw-attach-87654321"
    );
  }
}

```

Using `terraform import`, import `aws_ec2_transit_gateway_route_table_association` using the EC2 Transit Gateway Route Table identifier, an underscore, and the EC2 Transit Gateway Attachment identifier. For example:

```console
% terraform import aws_ec2_transit_gateway_route_table_association.example tgw-rtb-12345678_tgw-attach-87654321
```

<!-- cache-key: cdktf-0.20.8 input-b5a116d0309e360d26f59bdaed374343ad6880591d830e953bf2bfb7638d043c -->