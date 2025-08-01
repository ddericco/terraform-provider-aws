---
subcategory: "AppConfig"
layout: "aws"
page_title: "AWS: aws_appconfig_deployment"
description: |-
  Provides an AppConfig Deployment resource.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_appconfig_deployment

Provides an AppConfig Deployment resource for an [`aws_appconfig_application` resource](appconfig_application.html.markdown).

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.appconfig_deployment import AppconfigDeployment
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        AppconfigDeployment(self, "example",
            application_id=Token.as_string(aws_appconfig_application_example.id),
            configuration_profile_id=Token.as_string(aws_appconfig_configuration_profile_example.configuration_profile_id),
            configuration_version=Token.as_string(aws_appconfig_hosted_configuration_version_example.version_number),
            deployment_strategy_id=Token.as_string(aws_appconfig_deployment_strategy_example.id),
            description="My example deployment",
            environment_id=Token.as_string(aws_appconfig_environment_example.environment_id),
            kms_key_identifier=Token.as_string(aws_kms_key_example.arn),
            tags={
                "Type": "AppConfig Deployment"
            }
        )
```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `application_id` - (Required, Forces new resource) Application ID. Must be between 4 and 7 characters in length.
* `configuration_profile_id` - (Required, Forces new resource) Configuration profile ID. Must be between 4 and 7 characters in length.
* `configuration_version` - (Required, Forces new resource) Configuration version to deploy. Can be at most 1024 characters.
* `deployment_strategy_id` - (Required, Forces new resource) Deployment strategy ID or name of a predefined deployment strategy. See [Predefined Deployment Strategies](https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-creating-deployment-strategy.html#appconfig-creating-deployment-strategy-predefined) for more details.
* `description` - (Optional, Forces new resource) Description of the deployment. Can be at most 1024 characters.
* `environment_id` - (Required, Forces new resource) Environment ID. Must be between 4 and 7 characters in length.
* `kms_key_identifier` - (Optional, Forces new resource) The KMS key identifier (key ID, key alias, or key ARN). AppConfig uses this to encrypt the configuration data using a customer managed key.
* `tags` - (Optional) Map of tags to assign to the resource. If configured with a provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `id` - AppConfig application ID, environment ID, and deployment number separated by a slash (`/`).
* `arn` - ARN of the AppConfig Deployment.
* `deployment_number` - Deployment number.
* `kms_key_arn` - ARN of the KMS key used to encrypt configuration data.
* `state` - State of the deployment.
* `tags_all` - Map of tags assigned to the resource, including those inherited from the provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block).

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import AppConfig Deployments using the application ID, environment ID, and deployment number separated by a slash (`/`). For example:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.appconfig_deployment import AppconfigDeployment
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        AppconfigDeployment.generate_config_for_import(self, "example", "71abcde/11xxxxx/1")
```

Using `terraform import`, import AppConfig Deployments using the application ID, environment ID, and deployment number separated by a slash (`/`). For example:

```console
% terraform import aws_appconfig_deployment.example 71abcde/11xxxxx/1
```

<!-- cache-key: cdktf-0.20.8 input-143392904ed7e5f5acf7d8bd83f5b10c66b6368b56da700f38961d00a8db11a3 -->