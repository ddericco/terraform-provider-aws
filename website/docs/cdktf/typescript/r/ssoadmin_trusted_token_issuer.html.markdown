---
subcategory: "SSO Admin"
layout: "aws"
page_title: "AWS: aws_ssoadmin_trusted_token_issuer"
description: |-
  Terraform resource for managing an AWS SSO Admin Trusted Token Issuer.
---

<!-- Please do not edit this file, it is generated. -->
# Resource: aws_ssoadmin_trusted_token_issuer

Terraform resource for managing an AWS SSO Admin Trusted Token Issuer.

## Example Usage

### Basic Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Fn, Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsSsoadminInstances } from "./.gen/providers/aws/data-aws-ssoadmin-instances";
import { SsoadminTrustedTokenIssuer } from "./.gen/providers/aws/ssoadmin-trusted-token-issuer";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    const example = new DataAwsSsoadminInstances(this, "example", {});
    const awsSsoadminTrustedTokenIssuerExample = new SsoadminTrustedTokenIssuer(
      this,
      "example_1",
      {
        instanceArn: Token.asString(
          Fn.lookupNested(Fn.tolist(example.arns), ["0"])
        ),
        name: "example",
        trustedTokenIssuerConfiguration: [
          {
            oidcJwtConfiguration: [
              {
                claimAttributePath: "email",
                identityStoreAttributePath: "emails.value",
                issuerUrl: "https://example.com",
                jwksRetrievalOption: "OPEN_ID_DISCOVERY",
              },
            ],
          },
        ],
        trustedTokenIssuerType: "OIDC_JWT",
      }
    );
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    awsSsoadminTrustedTokenIssuerExample.overrideLogicalId("example");
  }
}

```

## Argument Reference

The following arguments are required:

* `instanceArn` - (Required) ARN of the instance of IAM Identity Center.
* `name` - (Required) Name of the trusted token issuer.
* `trustedTokenIssuerConfiguration` - (Required) A block that specifies settings that apply to the trusted token issuer, these change depending on the type you specify in `trustedTokenIssuerType`. [Documented below](#trusted_token_issuer_configuration-argument-reference).
* `trustedTokenIssuerType` - (Required) Specifies the type of the trusted token issuer. Valid values are `OIDC_JWT`

The following arguments are optional:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `clientToken` - (Optional) A unique, case-sensitive ID that you provide to ensure the idempotency of the request. AWS generates a random value when not provided.
* `tags` - (Optional) Key-value mapping of resource tags. If configured with a provider [`defaultTags` configuration block](/docs/providers/aws/index.html#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.

### `trustedTokenIssuerConfiguration` Argument Reference

* `oidcJwtConfiguration` - (Optional) A block that describes the settings for a trusted token issuer that works with OpenID Connect (OIDC) by using JSON Web Tokens (JWT). See [Documented below](#oidc_jwt_configuration-argument-reference) below.

### `oidcJwtConfiguration` Argument Reference

* `claimAttributePath` - (Required) Specifies the path of the source attribute in the JWT from the trusted token issuer.
* `identityStoreAttributePath` - (Required) Specifies path of the destination attribute in a JWT from IAM Identity Center. The attribute mapped by this JMESPath expression is compared against the attribute mapped by `claimAttributePath` when a trusted token issuer token is exchanged for an IAM Identity Center token.
* `issuerUrl` - (Required) Specifies the URL that IAM Identity Center uses for OpenID Discovery. OpenID Discovery is used to obtain the information required to verify the tokens that the trusted token issuer generates.
* `jwksRetrievalOption` - (Required) The method that the trusted token issuer can use to retrieve the JSON Web Key Set used to verify a JWT. Valid values are `OPEN_ID_DISCOVERY`

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - ARN of the trusted token issuer.
* `id` - ARN of the trusted token issuer.
* `tagsAll` - Map of tags assigned to the resource, including those inherited from the provider [`defaultTags` configuration block](/docs/providers/aws/index.html#default_tags-configuration-block).

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import SSO Admin Trusted Token Issuer using the `id`. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { SsoadminTrustedTokenIssuer } from "./.gen/providers/aws/ssoadmin-trusted-token-issuer";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    SsoadminTrustedTokenIssuer.generateConfigForImport(
      this,
      "example",
      "arn:aws:sso::123456789012:trustedTokenIssuer/ssoins-lu1ye3gew4mbc7ju/tti-2657c556-9707-11ee-b9d1-0242ac120002"
    );
  }
}

```

Using `terraform import`, import SSO Admin Trusted Token Issuer using the `id`. For example:

```console
% terraform import aws_ssoadmin_trusted_token_issuer.example arn:aws:sso::123456789012:trustedTokenIssuer/ssoins-lu1ye3gew4mbc7ju/tti-2657c556-9707-11ee-b9d1-0242ac120002
```

<!-- cache-key: cdktf-0.20.8 input-d26a7fec5eef4da5306f9b711aaeb8ba3d93c3e290520c0884c12458d431b69b -->