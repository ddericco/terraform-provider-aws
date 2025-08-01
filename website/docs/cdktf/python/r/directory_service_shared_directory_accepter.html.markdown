---
subcategory: "Directory Service"
layout: "aws"
page_title: "AWS: aws_directory_service_shared_directory_accepter"
description: |-
    Accepts a shared directory in a consumer account.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_directory_service_shared_directory_accepter

Accepts a shared directory in a consumer account.

~> **NOTE:** Destroying this resource removes the shared directory from the consumer account only.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.directory_service_shared_directory import DirectoryServiceSharedDirectory
from imports.aws.directory_service_shared_directory_accepter import DirectoryServiceSharedDirectoryAccepter
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        example = DirectoryServiceSharedDirectory(self, "example",
            directory_id=Token.as_string(aws_directory_service_directory_example.id),
            notes="example",
            target=DirectoryServiceSharedDirectoryTarget(
                id=Token.as_string(receiver.account_id)
            )
        )
        aws_directory_service_shared_directory_accepter_example =
        DirectoryServiceSharedDirectoryAccepter(self, "example_1",
            provider="awsalternate",
            shared_directory_id=example.shared_directory_id
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_directory_service_shared_directory_accepter_example.override_logical_id("example")
```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `shared_directory_id` - (Required) Identifier of the directory that is stored in the directory consumer account that corresponds to the shared directory in the owner account.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `id` - Identifier of the shared directory.
* `method` - Method used when sharing a directory (i.e., `ORGANIZATIONS` or `HANDSHAKE`).
* `notes` - Message sent by the directory owner to the directory consumer to help the directory consumer administrator determine whether to approve or reject the share invitation.
* `owner_account_id` - Account identifier of the directory owner.
* `owner_directory_id` - Identifier of the Managed Microsoft AD directory from the perspective of the directory owner.

## Timeouts

`aws_directory_service_shared_directory_accepter` provides the following [Timeouts](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts) configuration options:

- `create` - (Default `60 minutes`) Used for directory creation
- `delete` - (Default `60 minutes`) Used for directory deletion

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import Directory Service Shared Directories using the shared directory ID. For example:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.directory_service_shared_directory_accepter import DirectoryServiceSharedDirectoryAccepter
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        DirectoryServiceSharedDirectoryAccepter.generate_config_for_import(self, "example", "d-9267633ece")
```

Using `terraform import`, import Directory Service Shared Directories using the shared directory ID. For example:

```console
% terraform import aws_directory_service_shared_directory_accepter.example d-9267633ece
```

<!-- cache-key: cdktf-0.20.8 input-2ac5ff691131a0003fa74327614bc5d268200a44810759141daf1edafbe4e1d1 -->