---
subcategory: "OpenSearch"
layout: "aws"
page_title: "AWS: aws_opensearch_authorize_vpc_endpoint_access"
description: |-
  Terraform resource for managing an AWS OpenSearch Authorize Vpc Endpoint Access.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_opensearch_authorize_vpc_endpoint_access

Terraform resource for managing an AWS OpenSearch Authorize Vpc Endpoint Access.

## Example Usage

### Basic Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_caller_identity import DataAwsCallerIdentity
from imports.aws.opensearch_authorize_vpc_endpoint_access import OpensearchAuthorizeVpcEndpointAccess
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        current = DataAwsCallerIdentity(self, "current")
        OpensearchAuthorizeVpcEndpointAccess(self, "test",
            account=Token.as_string(current.account_id),
            domain_name=Token.as_string(aws_opensearch_domain_test.domain_name)
        )
```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `account` - (Required) AWS account ID to grant access to.
* `domain_name` - (Required) Name of OpenSearch Service domain to provide access to.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `authorized_principal` - Information about the Amazon Web Services account or service that was provided access to the domain. See [authorized principal](#authorized_principal) attribute for further details.

### authorized_principal

* `principal` - IAM principal that is allowed to access to the domain.
* `principal_type` - Type of principal.

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import OpenSearch Authorize Vpc Endpoint Access using the `example_id_arg`. For example:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.opensearch_authorize_vpc_endpoint_access import OpensearchAuthorizeVpcEndpointAccess
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        OpensearchAuthorizeVpcEndpointAccess.generate_config_for_import(self, "example", "authorize_vpc_endpoint_access-id-12345678")
```

Using `terraform import`, import OpenSearch Authorize Vpc Endpoint Access using the `example_id_arg`. For example:

```console
% terraform import aws_opensearch_authorize_vpc_endpoint_access.example authorize_vpc_endpoint_access-id-12345678
```

<!-- cache-key: cdktf-0.20.8 input-a72fc0c250433ebc1c624df0436ce0641ff1583821336426349c165b6f3ce451 -->