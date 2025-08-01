---
subcategory: "Athena"
layout: "aws"
page_title: "AWS: aws_athena_prepared_statement"
description: |-
  Terraform resource for managing an AWS Athena Prepared Statement.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_athena_prepared_statement

Terraform resource for managing an Athena Prepared Statement.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.athena_database import AthenaDatabase
from imports.aws.athena_prepared_statement import AthenaPreparedStatement
from imports.aws.athena_workgroup import AthenaWorkgroup
from imports.aws.s3_bucket import S3Bucket
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        test = AthenaWorkgroup(self, "test",
            name="tf-test"
        )
        aws_s3_bucket_test = S3Bucket(self, "test_1",
            bucket="tf-test",
            force_destroy=True
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_s3_bucket_test.override_logical_id("test")
        aws_athena_database_test = AthenaDatabase(self, "test_2",
            bucket=Token.as_string(aws_s3_bucket_test.bucket),
            name="example"
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_athena_database_test.override_logical_id("test")
        aws_athena_prepared_statement_test = AthenaPreparedStatement(self, "test_3",
            name="tf_test",
            query_statement="SELECT * FROM ${" + aws_athena_database_test.name + "} WHERE x = ?",
            workgroup=test.name
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_athena_prepared_statement_test.override_logical_id("test")
```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `name` - (Required) The name of the prepared statement. Maximum length of 256.
* `workgroup` - (Required) The name of the workgroup to which the prepared statement belongs.
* `query_statement` - (Required) The query string for the prepared statement.
* `description` - (Optional) Brief explanation of prepared statement. Maximum length of 1024.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `id` - ID of the prepared statement

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

* `create` - (Default `60m`)
* `update` - (Default `180m`)
* `delete` - (Default `90m`)

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import Athena Prepared Statement using the `WORKGROUP-NAME/STATEMENT-NAME`. For example:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.athena_prepared_statement import AthenaPreparedStatement
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        AthenaPreparedStatement.generate_config_for_import(self, "example", "12345abcde/example")
```

Using `terraform import`, import Athena Prepared Statement using the `WORKGROUP-NAME/STATEMENT-NAME`. For example:

```console
% terraform import aws_athena_prepared_statement.example 12345abcde/example 
```

<!-- cache-key: cdktf-0.20.8 input-a8ebfad972a5d4f66549bec6fba9e395d8d77edc3c40429b47501598dbe9a621 -->