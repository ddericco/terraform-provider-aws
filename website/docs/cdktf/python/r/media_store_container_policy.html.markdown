---
subcategory: "Elemental MediaStore"
layout: "aws"
page_title: "AWS: aws_media_store_container_policy"
description: |-
  Provides a MediaStore Container Policy.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_media_store_container_policy

Provides a MediaStore Container Policy.

!> **WARNING:** _This resource is deprecated and will be removed in a future version._ AWS has [announced](https://aws.amazon.com/blogs/media/support-for-aws-elemental-mediastore-ending-soon/) the discontinuation of AWS Elemental MediaStore, effective **November 13, 2025**. Users should begin transitioning to alternative solutions as soon as possible. For **simple live streaming workflows**, AWS recommends migrating to **Amazon S3**. For **advanced use cases** that require features such as packaging, DRM, or cross-region redundancy, consider using **AWS Elemental MediaPackage**.

~> **NOTE:** We suggest using [`jsonencode()`](https://developer.hashicorp.com/terraform/language/functions/jsonencode) or [`aws_iam_policy_document`](/docs/providers/aws/d/iam_policy_document.html) when assigning a value to `policy`. They seamlessly translate Terraform language into JSON, enabling you to maintain consistency within your configuration without the need for context switches. Also, you can sidestep potential complications arising from formatting discrepancies, whitespace inconsistencies, and other nuances inherent to JSON.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_caller_identity import DataAwsCallerIdentity
from imports.aws.data_aws_iam_policy_document import DataAwsIamPolicyDocument
from imports.aws.data_aws_region import DataAwsRegion
from imports.aws.media_store_container import MediaStoreContainer
from imports.aws.media_store_container_policy import MediaStoreContainerPolicy
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        example = MediaStoreContainer(self, "example",
            name="example"
        )
        current = DataAwsCallerIdentity(self, "current")
        data_aws_region_current = DataAwsRegion(self, "current_2")
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        data_aws_region_current.override_logical_id("current")
        data_aws_iam_policy_document_example = DataAwsIamPolicyDocument(self, "example_3",
            statement=[DataAwsIamPolicyDocumentStatement(
                actions=["mediastore:*"],
                condition=[DataAwsIamPolicyDocumentStatementCondition(
                    test="Bool",
                    values=["true"],
                    variable="aws:SecureTransport"
                )
                ],
                effect="Allow",
                principals=[DataAwsIamPolicyDocumentStatementPrincipals(
                    identifiers=["arn:aws:iam::${" + current.account_id + "}:root"],
                    type="AWS"
                )
                ],
                resources=["arn:aws:mediastore:${" + data_aws_region_current.region + "}:${" + current.account_id + "}:container/${" + example.name + "}/*"
                ],
                sid="MediaStoreFullAccess"
            )
            ]
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        data_aws_iam_policy_document_example.override_logical_id("example")
        aws_media_store_container_policy_example = MediaStoreContainerPolicy(self, "example_4",
            container_name=example.name,
            policy=Token.as_string(data_aws_iam_policy_document_example.json)
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_media_store_container_policy_example.override_logical_id("example")
```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `container_name` - (Required) The name of the container.
* `policy` - (Required) The contents of the policy. For more information about building AWS IAM policy documents with Terraform, see the [AWS IAM Policy Document Guide](https://learn.hashicorp.com/terraform/aws/iam-policy).

## Attribute Reference

This resource exports no additional attributes.

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import MediaStore Container Policy using the MediaStore Container Name. For example:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.media_store_container_policy import MediaStoreContainerPolicy
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        MediaStoreContainerPolicy.generate_config_for_import(self, "example", "example")
```

Using `terraform import`, import MediaStore Container Policy using the MediaStore Container Name. For example:

```console
% terraform import aws_media_store_container_policy.example example
```

<!-- cache-key: cdktf-0.20.8 input-02a1c7841dd05949a6ad1e4575d9d0404ca70390130bd09e6639482a6649dfe0 -->