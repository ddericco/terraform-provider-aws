---
subcategory: "Lightsail"
layout: "aws"
page_title: "AWS: aws_lightsail_domain_entry"
description: |-
  Manages a Lightsail domain entry (DNS record).
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_lightsail_domain_entry

Manages a Lightsail domain entry (DNS record). Use this resource to define how DNS queries for your domain are handled.

~> **NOTE on `id`:** In an effort to simplify imports, this resource `id` field has been updated to the standard resource id separator, a comma (`,`). For backward compatibility, the previous separator (underscore `_`) can still be used to read and import existing resources. When state is refreshed, the `id` will be updated to use the new standard separator. The previous separator will be deprecated in a future major release.

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { LightsailDomain } from "./.gen/providers/aws/lightsail-domain";
import { LightsailDomainEntry } from "./.gen/providers/aws/lightsail-domain-entry";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    const example = new LightsailDomain(this, "example", {
      domainName: "example.com",
    });
    const awsLightsailDomainEntryExample = new LightsailDomainEntry(
      this,
      "example_1",
      {
        domainName: example.domainName,
        name: "www",
        target: "127.0.0.1",
        type: "A",
      }
    );
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    awsLightsailDomainEntryExample.overrideLogicalId("example");
  }
}

```

## Argument Reference

The following arguments are required:

* `domainName` - (Required) Name of the Lightsail domain in which to create the entry.
* `name` - (Required) Name of the entry record.
* `target` - (Required) Target of the domain entry.
* `type` - (Required) Type of record. Valid values: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `SRV`, `TXT`.

The following arguments are optional:

* `isAlias` - (Optional) Whether the entry should be an alias. Default: `false`.
* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `id` - Combination of attributes to create a unique id: `name`,`domainName`,`type`,`target`.

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import Lightsail Domain Entry using the id attribute. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { LightsailDomainEntry } from "./.gen/providers/aws/lightsail-domain-entry";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    LightsailDomainEntry.generateConfigForImport(
      this,
      "example",
      "www,example.com,A,127.0.0.1"
    );
  }
}

```

Using `terraform import`, import Lightsail Domain Entry using the id attribute. For example:

```console
% terraform import aws_lightsail_domain_entry.example www,example.com,A,127.0.0.1
```

<!-- cache-key: cdktf-0.20.8 input-02ae3a4ff4b9a47e906a1b53cf5f2991f58445992008551f90adf810d0b1ef9a -->