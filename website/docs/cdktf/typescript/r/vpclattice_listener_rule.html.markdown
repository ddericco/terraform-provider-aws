---
subcategory: "VPC Lattice"
layout: "aws"
page_title: "AWS: aws_vpclattice_listener_rule"
description: |-
  Terraform resource for managing an AWS VPC Lattice Listener Rule.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_vpclattice_listener_rule

Terraform resource for managing an AWS VPC Lattice Listener Rule.

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { VpclatticeListenerRule } from "./.gen/providers/aws/vpclattice-listener-rule";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new VpclatticeListenerRule(this, "example", {
      action: {
        forward: {
          targetGroups: [
            {
              targetGroupIdentifier: Token.asString(
                awsVpclatticeTargetGroupExample.id
              ),
              weight: 1,
            },
            {
              targetGroupIdentifier: example2.id,
              weight: 2,
            },
          ],
        },
      },
      listenerIdentifier: Token.asString(
        awsVpclatticeListenerExample.listenerId
      ),
      match: {
        httpMatch: {
          headerMatches: [
            {
              caseSensitive: false,
              match: {
                exact: "example-contains",
              },
              name: "example-header",
            },
          ],
          pathMatch: {
            caseSensitive: true,
            match: {
              prefix: "/example-path",
            },
          },
        },
      },
      name: "example",
      priority: 20,
      serviceIdentifier: Token.asString(awsVpclatticeServiceExample.id),
    });
  }
}

```

### Basic Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { VpclatticeListenerRule } from "./.gen/providers/aws/vpclattice-listener-rule";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new VpclatticeListenerRule(this, "example", {
      action: {
        fixedResponse: {
          statusCode: 404,
        },
      },
      listenerIdentifier: Token.asString(
        awsVpclatticeListenerExample.listenerId
      ),
      match: {
        httpMatch: {
          pathMatch: {
            caseSensitive: false,
            match: {
              exact: "/example-path",
            },
          },
        },
      },
      name: "example",
      priority: 10,
      serviceIdentifier: Token.asString(awsVpclatticeServiceExample.id),
    });
  }
}

```

## Argument Reference

The following arguments are required:

* `serviceIdentifier` - (Required) The ID or Amazon Resource Identifier (ARN) of the service.
* `listenerIdentifier` - (Required) The ID or Amazon Resource Name (ARN) of the listener.
* `action` - (Required) The action for the listener rule.
  See [`action` Block](#action-block) for details.
* `match` - (Required) The rule match.
  See [`match` Block](#match-block)
* `name` - (Required) The name of the rule. The name must be unique within the listener. The valid characters are a-z, 0-9, and hyphens (-). You can't use a hyphen as the first or last character, or immediately after another hyphen.
* `priority` - (Required) The priority assigned to the rule. Each rule for a specific listener must have a unique priority. The lower the priority number the higher the priority.

The following arguments are optional:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `tags` - (Optional) Key-value mapping of resource tags. If configured with a provider [`defaultTags` configuration block](/docs/providers/aws/index.html#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.

### `action` Block

The `action` block supports the following:

Exactly one of `fixedResponse` or `forward` is required.

* `fixedResponse` - (Optional) Describes the rule action that returns a custom HTTP response.
  See [`fixedResponse` Block](#fixed_response-block) for details.
* `forward` - (Optional) The forward action. Traffic that matches the rule is forwarded to the specified target groups.
  See [`forward` Block](#forward-block) for details.

### `fixedResponse` Block

The `fixedResponse` block supports the following:

* `statusCode` - (Optional) The HTTP response code.

### `forward` Block

The `forward` block supports the following:

* `targetGroups` - (Optional) The target groups. Traffic matching the rule is forwarded to the specified target groups. With forward actions, you can assign a weight that controls the prioritization and selection of each target group. This means that requests are distributed to individual target groups based on their weights. For example, if two target groups have the same weight, each target group receives half of the traffic.

The default value is 1 with maximum number of 2. If only one target group is provided, there is no need to set the weight; 100% of traffic will go to that target group.

### `match` Block

The `match` block supports the following:

* `httpMatch` - (Required) The HTTP criteria that a rule must match.
  See [`httpMatch` Block](#http_match-block) for details.

### `httpMatch` Block

The `httpMatch` block supports the following:

At least one of `headerMatches`, `method`, or `pathMatch` is required.

* `headerMatches` - (Optional) The header matches.
  Matches incoming requests with rule based on request header value before applying rule action.
  See [`headerMatches` Block](#header_matches-block) for details.
* `method` - (Optional) The HTTP method type.
* `pathMatch` - (Optional) The path match.
  See [`pathMatch` Block](#path_match-block) for details.

### `headerMatches` Block

The `headerMatches` block supports the following:

* `caseSensitive` - (Optional) Indicates whether the match is case sensitive.
  Default is `false`.
* `match` - (Optional) The header match type.
  See [Header Match `match` Block](#header-match-match-block) for details.
* `name` - (Required) The name of the header.

### Header Match `match` Block

The Header Match `match` block supports the following:

Exactly one of `contains`, `exact`, or `prefix` is required.

* `contains` - (Optional) Specifies a contains type match.
* `exact` - (Optional) Specifies an exact type match.
* `prefix` - (Optional) Specifies a prefix type match.
  Matches the value with the prefix.

### `pathMatch` Block

The `pathMatch` block supports the following:

* `caseSensitive` - (Optional) Indicates whether the match is case sensitive.
  Default is `false`.
* `match` - (Optional) The header match type.
  See [Path Match `match` Block](#path-match-match-block) for details.

### Path Match `match` Block

The Path Match `match` block supports the following:

Exactly one of `exact` or `prefix` is required.

* `exact` - (Optional) Specifies an exact type match.
* `prefix` - (Optional) Specifies a prefix type match.
  Matches the value with the prefix.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - The ARN for the listener rule.
* `ruleId` - Unique identifier for the listener rule.
* `tagsAll` - Map of tags assigned to the resource, including those inherited from the provider [`defaultTags` configuration block](/docs/providers/aws/index.html#default_tags-configuration-block).

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

* `create` - (Default `60m`)
* `update` - (Default `180m`)
* `delete` - (Default `90m`)

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import VPC Lattice Listener Rule using the `id`. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { VpclatticeListenerRule } from "./.gen/providers/aws/vpclattice-listener-rule";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    VpclatticeListenerRule.generateConfigForImport(
      this,
      "example",
      "service123/listener456/rule789"
    );
  }
}

```

Using `terraform import`, import VPC Lattice Listener Rule using the `id`. For example:

```console
% terraform import aws_vpclattice_listener_rule.example service123/listener456/rule789
```

<!-- cache-key: cdktf-0.20.8 input-f95017130829eedd78838a84b4ae93d2ba8cfb5b398e577b6369c7ff22310277 -->