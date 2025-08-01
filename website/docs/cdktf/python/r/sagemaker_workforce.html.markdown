---
subcategory: "SageMaker AI"
layout: "aws"
page_title: "AWS: aws_sagemaker_workforce"
description: |-
  Provides a SageMaker AI Workforce resource.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_sagemaker_workforce

Provides a SageMaker AI Workforce resource.

## Example Usage

### Cognito Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.cognito_user_pool import CognitoUserPool
from imports.aws.cognito_user_pool_client import CognitoUserPoolClient
from imports.aws.cognito_user_pool_domain import CognitoUserPoolDomain
from imports.aws.sagemaker_workforce import SagemakerWorkforce
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        example = CognitoUserPool(self, "example",
            name="example"
        )
        aws_cognito_user_pool_client_example = CognitoUserPoolClient(self, "example_1",
            generate_secret=True,
            name="example",
            user_pool_id=example.id
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_cognito_user_pool_client_example.override_logical_id("example")
        aws_cognito_user_pool_domain_example = CognitoUserPoolDomain(self, "example_2",
            domain="example",
            user_pool_id=example.id
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_cognito_user_pool_domain_example.override_logical_id("example")
        aws_sagemaker_workforce_example = SagemakerWorkforce(self, "example_3",
            cognito_config=SagemakerWorkforceCognitoConfig(
                client_id=Token.as_string(aws_cognito_user_pool_client_example.id),
                user_pool=Token.as_string(aws_cognito_user_pool_domain_example.user_pool_id)
            ),
            workforce_name="example"
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_sagemaker_workforce_example.override_logical_id("example")
```

### Oidc Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.sagemaker_workforce import SagemakerWorkforce
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        SagemakerWorkforce(self, "example",
            oidc_config=SagemakerWorkforceOidcConfig(
                authorization_endpoint="https://example.com",
                client_id="example",
                client_secret="example",
                issuer="https://example.com",
                jwks_uri="https://example.com",
                logout_endpoint="https://example.com",
                token_endpoint="https://example.com",
                user_info_endpoint="https://example.com"
            ),
            workforce_name="example"
        )
```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `workforce_name` - (Required) The name of the Workforce (must be unique).
* `cognito_config` - (Optional) Use this parameter to configure an Amazon Cognito private workforce. A single Cognito workforce is created using and corresponds to a single Amazon Cognito user pool. Conflicts with `oidc_config`. see [Cognito Config](#cognito-config) details below.
* `oidc_config` - (Optional) Use this parameter to configure a private workforce using your own OIDC Identity Provider. Conflicts with `cognito_config`. see [OIDC Config](#oidc-config) details below.
* `source_ip_config` - (Optional) A list of IP address ranges Used to create an allow list of IP addresses for a private workforce. By default, a workforce isn't restricted to specific IP addresses. see [Source Ip Config](#source-ip-config) details below.
* `workforce_vpc_config` - (Optional) configure a workforce using VPC. see [Workforce VPC Config](#workforce-vpc-config) details below.

### Cognito Config

* `client_id` - (Required) The client ID for your Amazon Cognito user pool.
* `user_pool` - (Required) ID for your Amazon Cognito user pool.

### Oidc Config

* `authentication_request_extra_params` - (Optional) A string to string map of identifiers specific to the custom identity provider (IdP) being used.
* `authorization_endpoint` - (Required) The OIDC IdP authorization endpoint used to configure your private workforce.
* `client_id` - (Required) The OIDC IdP client ID used to configure your private workforce.
* `client_secret` - (Required) The OIDC IdP client secret used to configure your private workforce.
* `issuer` - (Required) The OIDC IdP issuer used to configure your private workforce.
* `jwks_uri` - (Required) The OIDC IdP JSON Web Key Set (Jwks) URI used to configure your private workforce.
* `logout_endpoint` - (Required) The OIDC IdP logout endpoint used to configure your private workforce.
* `scope` - (Optional) An array of string identifiers used to refer to the specific pieces of user data or claims that the client application wants to access.
* `token_endpoint` - (Required) The OIDC IdP token endpoint used to configure your private workforce.
* `user_info_endpoint` - (Required) The OIDC IdP user information endpoint used to configure your private workforce.

### Source Ip Config

* `cidrs` - (Required) A list of up to 10 CIDR values.

### Workforce VPC Config

* `security_group_ids` - (Optional) The VPC security group IDs. The security groups must be for the same VPC as specified in the subnet.
* `subnets` - (Optional) The ID of the subnets in the VPC that you want to connect.
* `vpc_id` - (Optional) The ID of the VPC that the workforce uses for communication.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - The Amazon Resource Name (ARN) assigned by AWS to this Workforce.
* `id` - The name of the Workforce.
* `subdomain` - The subdomain for your OIDC Identity Provider.
* `workforce_vpc_config.0.vpc_endpoint_id` - The IDs for the VPC service endpoints of your VPC workforce.

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import SageMaker AI Workforces using the `workforce_name`. For example:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.sagemaker_workforce import SagemakerWorkforce
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        SagemakerWorkforce.generate_config_for_import(self, "example", "example")
```

Using `terraform import`, import SageMaker AI Workforces using the `workforce_name`. For example:

```console
% terraform import aws_sagemaker_workforce.example example
```

<!-- cache-key: cdktf-0.20.8 input-b4b8779a11d7bef5fb0af2b2106f24a5347c8e2fe92650827fae68f786b4577a -->