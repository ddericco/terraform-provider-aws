---
subcategory: "DevOps Guru"
layout: "aws"
page_title: "AWS: aws_devopsguru_event_sources_config"
description: |-
  Terraform resource for managing an AWS DevOps Guru Event Sources Config.
---

<!-- Please do not edit this file, it is generated. -->
# Resource: aws_devopsguru_event_sources_config

Terraform resource for managing an AWS DevOps Guru Event Sources Config. Currently the only service that can be integrated with DevOps Guru is Amazon CodeGuru Profiler, which can produce proactive recommendations which can be stored and viewed in DevOps Guru.

~> Destruction of this resource will set the CodeGuru profiler status to `DISABLED`. If you wish to preserve an `ENABLED` configuration while removing the Terraform resource, utilize a [`removed` block](https://developer.hashicorp.com/terraform/language/resources/syntax#removing-resources) (available in Terraform 1.7+).

~> Event sources are configured at the account level. To avoid persistent differences, this resource should be defined only once.

## Example Usage

### Basic Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.devopsguru_event_sources_config import DevopsguruEventSourcesConfig
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        DevopsguruEventSourcesConfig(self, "example",
            event_sources=[DevopsguruEventSourcesConfigEventSources(
                amazon_code_guru_profiler=[DevopsguruEventSourcesConfigEventSourcesAmazonCodeGuruProfiler(
                    status="ENABLED"
                )
                ]
            )
            ]
        )
```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `event_sources` - (Required) Configuration information about the integration of DevOps Guru as the Consumer via EventBridge with another AWS Service. See [`event_sources`](#event_sources-argument-reference) below.

### `event_sources` Argument Reference

* `amazon_code_guru_profiler` - (Required) Stores whether DevOps Guru is configured to consume recommendations which are generated from AWS CodeGuru Profiler. See [`amazon_code_guru_profiler`](#amazon_code_guru_profiler-argument-reference) below.

### `amazon_code_guru_profiler` Argument Reference

* `status` - (Required) Status of the CodeGuru Profiler integration. Valid values are `ENABLED` and `DISABLED`.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `id` - AWS region.

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import DevOps Guru Event Sources Config using the region. For example:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.devopsguru_event_sources_config import DevopsguruEventSourcesConfig
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        DevopsguruEventSourcesConfig.generate_config_for_import(self, "example", "us-east-1")
```

Using `terraform import`, import DevOps Guru Event Sources Config using the region. For example:

```console
% terraform import aws_devopsguru_event_sources_config.example us-east-1
```

<!-- cache-key: cdktf-0.20.8 input-6cdd1fb53efc6b6afca93238f814d6fb280917f2d9914cf8d6d7873e13a79701 -->