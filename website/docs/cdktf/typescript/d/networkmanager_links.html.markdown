---
subcategory: "Network Manager"
layout: "aws"
page_title: "AWS: aws_networkmanager_links"
description: |-
  Provides details about existing Network Manager links.
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_networkmanager_links

Provides details about existing Network Manager links.

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsNetworkmanagerLinks } from "./.gen/providers/aws/data-aws-networkmanager-links";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new DataAwsNetworkmanagerLinks(this, "example", {
      globalNetworkId: globalNetworkId.stringValue,
      tags: {
        Env: "test",
      },
    });
  }
}

```

## Argument Reference

This data source supports the following arguments:

* `globalNetworkId` - (Required) ID of the Global Network of the links to retrieve.
* `providerName` - (Optional) Link provider to retrieve.
* `siteId` - (Optional) ID of the site of the links to retrieve.
* `tags` - (Optional) Restricts the list to the links with these tags.
* `type` - (Optional) Link type to retrieve.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `ids` - IDs of the links.

<!-- cache-key: cdktf-0.20.8 input-ebb4671d0d9a4e2c1f6d33035bf5705cae392605e4ef6ddbf63adc02fb8b53a0 -->