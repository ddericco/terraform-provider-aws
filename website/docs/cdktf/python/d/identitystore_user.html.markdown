---
subcategory: "SSO Identity Store"
layout: "aws"
page_title: "AWS: aws_identitystore_user"
description: |-
  Get information on an Identity Store User
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_identitystore_user

Use this data source to get an Identity Store User.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Fn, Token, TerraformOutput, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_identitystore_user import DataAwsIdentitystoreUser
from imports.aws.data_aws_ssoadmin_instances import DataAwsSsoadminInstances
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        example = DataAwsSsoadminInstances(self, "example")
        data_aws_identitystore_user_example = DataAwsIdentitystoreUser(self, "example_1",
            alternate_identifier=DataAwsIdentitystoreUserAlternateIdentifier(
                unique_attribute=DataAwsIdentitystoreUserAlternateIdentifierUniqueAttribute(
                    attribute_path="UserName",
                    attribute_value="ExampleUser"
                )
            ),
            identity_store_id=Token.as_string(
                Fn.lookup_nested(Fn.tolist(example.identity_store_ids), ["0"]))
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        data_aws_identitystore_user_example.override_logical_id("example")
        TerraformOutput(self, "user_id",
            value=data_aws_identitystore_user_example.user_id
        )
```

## Argument Reference

The following arguments are required:

* `identity_store_id` - (Required) Identity Store ID associated with the Single Sign-On Instance.

The following arguments are optional:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `alternate_identifier` (Optional) A unique identifier for a user or group that is not the primary identifier. Conflicts with `user_id` and `filter`. Detailed below.
* `user_id` - (Optional) The identifier for a user in the Identity Store.

-> Exactly one of the above arguments must be provided. Passing both `filter` and `user_id` is allowed for backwards compatibility.

### `alternate_identifier` Configuration Block

The `alternate_identifier` configuration block supports the following arguments:

* `external_id` - (Optional) Configuration block for filtering by the identifier issued by an external identity provider. Detailed below.
* `unique_attribute` - (Optional) An entity attribute that's unique to a specific entity. Detailed below.

-> Exactly one of the above arguments must be provided.

### `external_id` Configuration Block

The `external_id` configuration block supports the following arguments:

* `id` - (Required) The identifier issued to this resource by an external identity provider.
* `issuer` - (Required) The issuer for an external identifier.

### `unique_attribute` Configuration Block

The `unique_attribute` configuration block supports the following arguments:

* `attribute_path` - (Required) Attribute path that is used to specify which attribute name to search. For example: `UserName`. Refer to the [User data type](https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html).
* `attribute_value` - (Required) Value for an attribute.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `id` - Identifier of the user in the Identity Store.
* `addresses` - List of details about the user's address.
    * `country` - The country that this address is in.
    * `formatted` - The name that is typically displayed when the address is shown for display.
    * `locality` - The address locality.
    * `postal_code` - The postal code of the address.
    * `primary` - When `true`, this is the primary address associated with the user.
    * `region` - The region of the address.
    * `street_address` - The street of the address.
    * `type` - The type of address.
* `display_name` - The name that is typically displayed when the user is referenced.
* `emails` - List of details about the user's email.
    * `primary` - When `true`, this is the primary email associated with the user.
    * `type` - The type of email.
    * `value` - The email address. This value must be unique across the identity store.
* `external_ids` - List of identifiers issued to this resource by an external identity provider.
    * `id` - The identifier issued to this resource by an external identity provider.
    * `issuer` - The issuer for an external identifier.
* `locale` - The user's geographical region or location.
* `name` - Details about the user's full name.
    * `family_name` - The family name of the user.
    * `formatted` - The name that is typically displayed when the name is shown for display.
    * `given_name` - The given name of the user.
    * `honorific_prefix` - The honorific prefix of the user.
    * `honorific_suffix` - The honorific suffix of the user.
    * `middle_name` - The middle name of the user.
* `nickname` - An alternate name for the user.
* `phone_numbers` - List of details about the user's phone number.
    * `primary` - When `true`, this is the primary phone number associated with the user.
    * `type` - The type of phone number.
    * `value` - The user's phone number.
* `preferred_language` - The preferred language of the user.
* `profile_url` - An URL that may be associated with the user.
* `timezone` - The user's time zone.
* `title` - The user's title.
* `user_name` - User's user name value.
* `user_type` - The user type.

<!-- cache-key: cdktf-0.20.8 input-670d9a4ed0f164cbcab3972da4a52d838a4b9a95fb5101bdfade807d743f2eb2 -->