---
subcategory: "CodeArtifact"
layout: "aws"
page_title: "AWS: aws_codeartifact_domain_permissions_policy"
description: |-
  Provides a CodeArtifact Domain Permissions Policy resource.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_codeartifact_domain_permissions_policy

Provides a CodeArtifact Domains Permissions Policy Resource.

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { CodeartifactDomain } from "./.gen/providers/aws/codeartifact-domain";
import { CodeartifactDomainPermissionsPolicy } from "./.gen/providers/aws/codeartifact-domain-permissions-policy";
import { DataAwsIamPolicyDocument } from "./.gen/providers/aws/data-aws-iam-policy-document";
import { KmsKey } from "./.gen/providers/aws/kms-key";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    const example = new KmsKey(this, "example", {
      description: "domain key",
    });
    const awsCodeartifactDomainExample = new CodeartifactDomain(
      this,
      "example_1",
      {
        domain: "example",
        encryptionKey: example.arn,
      }
    );
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    awsCodeartifactDomainExample.overrideLogicalId("example");
    const test = new DataAwsIamPolicyDocument(this, "test", {
      statement: [
        {
          actions: ["codeartifact:CreateRepository"],
          effect: "Allow",
          principals: [
            {
              identifiers: ["*"],
              type: "*",
            },
          ],
          resources: [Token.asString(awsCodeartifactDomainExample.arn)],
        },
      ],
    });
    const awsCodeartifactDomainPermissionsPolicyTest =
      new CodeartifactDomainPermissionsPolicy(this, "test_3", {
        domain: Token.asString(awsCodeartifactDomainExample.domain),
        policyDocument: Token.asString(test.json),
      });
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    awsCodeartifactDomainPermissionsPolicyTest.overrideLogicalId("test");
  }
}

```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `domain` - (Required) The name of the domain on which to set the resource policy.
* `policyDocument` - (Required) A JSON policy string to be set as the access control resource policy on the provided domain.
* `domainOwner` - (Optional) The account number of the AWS account that owns the domain.
* `policyRevision` - (Optional) The current revision of the resource policy to be set. This revision is used for optimistic locking, which prevents others from overwriting your changes to the domain's resource policy.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `id` - The Name of Domain.
* `resourceArn` - The ARN of the resource associated with the resource policy.

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import CodeArtifact Domain Permissions Policies using the CodeArtifact Domain ARN. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { CodeartifactDomainPermissionsPolicy } from "./.gen/providers/aws/codeartifact-domain-permissions-policy";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    CodeartifactDomainPermissionsPolicy.generateConfigForImport(
      this,
      "example",
      "arn:aws:codeartifact:us-west-2:012345678912:domain/tf-acc-test-1928056699409417367"
    );
  }
}

```

Using `terraform import`, import CodeArtifact Domain Permissions Policies using the CodeArtifact Domain ARN. For example:

```console
% terraform import aws_codeartifact_domain_permissions_policy.example arn:aws:codeartifact:us-west-2:012345678912:domain/tf-acc-test-1928056699409417367
```

<!-- cache-key: cdktf-0.20.8 input-63a40f68ab8862f38b166c6f0bb7c73298dbb7711d30c11b8388fe8f7708ef47 -->