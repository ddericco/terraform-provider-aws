---
subcategory: "EventBridge Schemas"
layout: "aws"
page_title: "AWS: aws_schemas_schema"
description: |-
  Provides an EventBridge Schema resource.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_schemas_schema

Provides an EventBridge Schema resource.

~> **Note:** EventBridge was formerly known as CloudWatch Events. The functionality is identical.

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Fn, Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { SchemasRegistry } from "./.gen/providers/aws/schemas-registry";
import { SchemasSchema } from "./.gen/providers/aws/schemas-schema";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    const test = new SchemasRegistry(this, "test", {
      name: "my_own_registry",
    });
    const awsSchemasSchemaTest = new SchemasSchema(this, "test_1", {
      content: Token.asString(
        Fn.jsonencode({
          components: {
            schemas: {
              Event: {
                properties: {
                  name: {
                    type: "string",
                  },
                },
                type: "object",
              },
            },
          },
          info: {
            title: "Event",
            version: "1.0.0",
          },
          openapi: "3.0.0",
          paths: {},
        })
      ),
      description: "The schema definition for my event",
      name: "my_schema",
      registryName: test.name,
      type: "OpenApi3",
    });
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    awsSchemasSchemaTest.overrideLogicalId("test");
  }
}

```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `name` - (Required) The name of the schema. Maximum of 385 characters consisting of lower case letters, upper case letters, ., -, _, @.
* `content` - (Required) The schema specification. Must be a valid Open API 3.0 spec.
* `registryName` - (Required) The name of the registry in which this schema belongs.
* `type` - (Required) The type of the schema. Valid values: `OpenApi3` or `JSONSchemaDraft4`.
* `description` - (Optional) The description of the schema. Maximum of 256 characters.
* `tags` - (Optional) A map of tags to assign to the resource. If configured with a provider [`defaultTags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - The Amazon Resource Name (ARN) of the discoverer.
* `lastModified` - The last modified date of the schema.
* `tagsAll` - A map of tags assigned to the resource, including those inherited from the provider [`defaultTags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block).
* `version` - The version of the schema.
* `versionCreatedDate` - The created date of the version of the schema.

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import EventBridge schema using the `name` and `registryName`. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { SchemasSchema } from "./.gen/providers/aws/schemas-schema";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    SchemasSchema.generateConfigForImport(this, "test", "name/registry");
  }
}

```

Using `terraform import`, import EventBridge schema using the `name` and `registryName`. For example:

```console
% terraform import aws_schemas_schema.test name/registry
```

<!-- cache-key: cdktf-0.20.8 input-a60ebb2d06e69af38dd2fce39120e57e70fca8660edf7df6ad179bf3a2a5eb36 -->