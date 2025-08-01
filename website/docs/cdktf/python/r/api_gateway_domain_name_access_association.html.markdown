---
subcategory: "API Gateway"
layout: "aws"
page_title: "AWS: aws_api_gateway_domain_name_access_association"
description: |-
  Creates a domain name access association resource between an access association source and a private custom domain name.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_api_gateway_domain_name_access_association

Creates a domain name access association resource between an access association source and a private custom domain name.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.api_gateway_domain_name_access_association import ApiGatewayDomainNameAccessAssociation
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        ApiGatewayDomainNameAccessAssociation(self, "example",
            access_association_source=Token.as_string(aws_vpc_endpoint_example.id),
            access_association_source_type="VPCE",
            domain_name_arn=Token.as_string(aws_api_gateway_domain_name_example.arn)
        )
```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `access_association_source` - (Required) The identifier of the domain name access association source. For a `VPCE`, the value is the VPC endpoint ID.
* `access_association_source_type` - (Required) The type of the domain name access association source. Valid values are `VPCE`.
* `domain_name_arn` - (Required) The ARN of the domain name.
* `tags` - (Optional) Key-value map of resource tags. If configured with a provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - ARN of the domain name access association.
* `id` - (**Deprecated**, use `arn` instead) Internal identifier assigned to this domain name access association.
* `tags_all` - Map of tags assigned to the resource, including those inherited from the provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block).

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import API Gateway domain name acces associations using their `arn`. For example:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.api_gateway_domain_name_access_association import ApiGatewayDomainNameAccessAssociation
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        ApiGatewayDomainNameAccessAssociation.generate_config_for_import(self, "example", "arn:aws:apigateway:us-west-2:123456789012:/domainnameaccessassociations/domainname/12qmzgp2.9m7ilski.test+hykg7a12e7/vpcesource/vpce-05de3f8f82740a748")
```

Using `terraform import`, import API Gateway domain name acces associations as using their `arn`. For example:

```console
% terraform import aws_api_gateway_domain_name_access_association.example arn:aws:apigateway:us-west-2:123456789012:/domainnameaccessassociations/domainname/12qmzgp2.9m7ilski.test+hykg7a12e7/vpcesource/vpce-05de3f8f82740a748
```

<!-- cache-key: cdktf-0.20.8 input-8bb3d64cfd1ad084281554ff87806749a8adb5f7178578ce4584a48eb1b01f18 -->