---
subcategory: "API Gateway V2"
layout: "aws"
page_title: "AWS: aws_apigatewayv2_export"
description: |-
  Exports a definition of an API in a particular output format and specification.
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_apigatewayv2_export

Exports a definition of an API in a particular output format and specification.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_apigatewayv2_export import DataAwsApigatewayv2Export
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        DataAwsApigatewayv2Export(self, "test",
            api_id=Token.as_string(aws_apigatewayv2_route_test.api_id),
            output_type="JSON",
            specification="OAS30"
        )
```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `api_id` - (Required) API identifier.
* `specification` - (Required) Version of the API specification to use. `OAS30`, for OpenAPI 3.0, is the only supported value.
* `output_type` - (Required) Output type of the exported definition file. Valid values are `JSON` and `YAML`.
* `export_version` - (Optional) Version of the API Gateway export algorithm. API Gateway uses the latest version by default. Currently, the only supported version is `1.0`.
* `include_extensions` - (Optional) Whether to include API Gateway extensions in the exported API definition. API Gateway extensions are included by default.
* `stage_name` - (Optional) Name of the API stage to export. If you don't specify this property, a representation of the latest API configuration is exported.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `id` - API identifier.
* `body` - ID of the API.

<!-- cache-key: cdktf-0.20.8 input-dbf7bc0698ebb63fadc2f51104034579ded79be567ced66ab72f836f382dc8ef -->