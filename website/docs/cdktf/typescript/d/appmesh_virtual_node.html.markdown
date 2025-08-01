---
subcategory: "App Mesh"
layout: "aws"
page_title: "AWS: aws_appmesh_virtual_node"
description: |-
    Terraform data source for managing an AWS App Mesh Virtual Node.
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_appmesh_virtual_node

Terraform data source for managing an AWS App Mesh Virtual Node.

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsAppmeshVirtualNode } from "./.gen/providers/aws/data-aws-appmesh-virtual-node";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new DataAwsAppmeshVirtualNode(this, "test", {
      meshName: "example-mesh",
      name: "serviceBv1",
    });
  }
}

```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `name` - (Required) Name of the virtual node.
* `meshName` - (Required) Name of the service mesh in which the virtual node exists.
* `meshOwner` - (Optional) AWS account ID of the service mesh's owner.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `arn` - ARN of the virtual node.
* `createdDate` - Creation date of the virtual node.
* `lastUpdatedDate` - Last update date of the virtual node.
* `resourceOwner` - Resource owner's AWS account ID.
* `spec` - Virtual node specification. See the [`aws_appmesh_virtual_node`](/docs/providers/aws/r/appmesh_virtual_node.html#spec) resource for details.
* `tags` - Map of tags.

<!-- cache-key: cdktf-0.20.8 input-e83d289f382686d9860e631593fc2be4248602f05e25587a1063cb31559bcbc3 -->