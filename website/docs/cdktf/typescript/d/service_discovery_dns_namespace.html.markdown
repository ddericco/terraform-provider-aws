---
subcategory: "Cloud Map"
layout: "aws"
page_title: "AWS: aws_service_discovery_dns_namespace"
description: |-
  Retrieves information about a Service Discovery private or public DNS namespace.
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_service_discovery_dns_namespace

Retrieves information about a Service Discovery private or public DNS namespace.

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsServiceDiscoveryDnsNamespace } from "./.gen/providers/aws/data-aws-service-discovery-dns-namespace";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new DataAwsServiceDiscoveryDnsNamespace(this, "test", {
      name: "example.terraform.local",
      type: "DNS_PRIVATE",
    });
  }
}

```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `name` - (Required) Name of the namespace.
* `type` - (Required) Type of the namespace. Allowed values are `DNS_PUBLIC` or `DNS_PRIVATE`.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `arn` - ARN of the namespace.
* `description` - Description of the namespace.
* `id` - Namespace ID.
* `hostedZone` - ID for the hosted zone that Amazon Route 53 creates when you create a namespace.
* `tags` - Map of tags for the resource.

<!-- cache-key: cdktf-0.20.8 input-adff9443347be15de12eea44e44100beab3a07dbb872fde0c356a392f54cd427 -->