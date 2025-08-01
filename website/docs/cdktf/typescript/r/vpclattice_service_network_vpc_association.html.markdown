---
subcategory: "VPC Lattice"
layout: "aws"
page_title: "AWS: aws_vpclattice_service_network_vpc_association"
description: |-
  Terraform resource for managing an AWS VPC Lattice Service Network VPC Association.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_vpclattice_service_network_vpc_association

Terraform resource for managing an AWS VPC Lattice Service Network VPC Association.

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
import { VpclatticeServiceNetworkVpcAssociation } from "./.gen/providers/aws/vpclattice-service-network-vpc-association";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new VpclatticeServiceNetworkVpcAssociation(this, "example", {
      securityGroupIds: [Token.asString(awsSecurityGroupExample.id)],
      serviceNetworkIdentifier: Token.asString(
        awsVpclatticeServiceNetworkExample.id
      ),
      vpcIdentifier: Token.asString(awsVpcExample.id),
    });
  }
}

```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `vpcIdentifier` - (Required) The ID of the VPC.
* `serviceNetworkIdentifier` - (Required) The ID or Amazon Resource Identifier (ARN) of the service network. You must use the ARN if the resources specified in the operation are in different accounts.
The following arguments are optional:
* `tags` - (Optional) Key-value mapping of resource tags. If configured with a provider [`defaultTags` configuration block](/docs/providers/aws/index.html#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.
* `securityGroupIds` - (Optional) The IDs of the security groups.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - The ARN of the Association.
* `createdBy` - The account that created the association.
* `id` - The ID of the association.
* `status` - The operations status. Valid Values are CREATE_IN_PROGRESS | ACTIVE | DELETE_IN_PROGRESS | CREATE_FAILED | DELETE_FAILED
* `tagsAll` - Map of tags assigned to the resource, including those inherited from the provider [`defaultTags` configuration block](/docs/providers/aws/index.html#default_tags-configuration-block).

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

* `create` - (Default `5m`)
* `delete` - (Default `5m`)

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import VPC Lattice Service Network VPC Association using the `id`. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { VpclatticeServiceNetworkVpcAssociation } from "./.gen/providers/aws/vpclattice-service-network-vpc-association";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    VpclatticeServiceNetworkVpcAssociation.generateConfigForImport(
      this,
      "example",
      "snsa-05e2474658a88f6ba"
    );
  }
}

```

Using `terraform import`, import VPC Lattice Service Network VPC Association using the `id`. For example:

```console
% terraform import aws_vpclattice_service_network_vpc_association.example snsa-05e2474658a88f6ba
```

<!-- cache-key: cdktf-0.20.8 input-99510012adb56ebe8ba2cca4d1808d936fb1657147ed8ddabb0229090f6f483d -->