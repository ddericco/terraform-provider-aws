---
subcategory: "OpenSearch Serverless"
layout: "aws"
page_title: "AWS: aws_opensearchserverless_security_policy"
description: |-
  Get information on an OpenSearch Serverless Security Policy.
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_opensearchserverless_security_policy

Use this data source to get information about an AWS OpenSearch Serverless Security Policy.

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsOpensearchserverlessSecurityPolicy } from "./.gen/providers/aws/data-aws-opensearchserverless-security-policy";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new DataAwsOpensearchserverlessSecurityPolicy(this, "example", {
      name: "example-security-policy",
      type: "encryption",
    });
  }
}

```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `name` - (Required) Name of the policy
* `type` - (Required) Type of security policy. One of `encryption` or `network`.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `createdDate` - The date the security policy was created.
* `description` - Description of the security policy.
* `lastModifiedDate` - The date the security policy was last modified.
* `policy` - The JSON policy document without any whitespaces.
* `policyVersion` - Version of the policy.

<!-- cache-key: cdktf-0.20.8 input-dc4e5f4b6fbcb198d3e5c896884618d9532eef479833efde06f7865e58dc70b9 -->