---
subcategory: "ECS (Elastic Container)"
layout: "aws"
page_title: "AWS: aws_ecs_cluster"
description: |-
  Provides an ECS cluster.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_ecs_cluster

Provides an ECS cluster.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.ecs_cluster import EcsCluster
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        EcsCluster(self, "foo",
            name="white-hart",
            setting=[EcsClusterSetting(
                name="containerInsights",
                value="enabled"
            )
            ]
        )
```

### Execute Command Configuration with Override Logging

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.cloudwatch_log_group import CloudwatchLogGroup
from imports.aws.ecs_cluster import EcsCluster
from imports.aws.kms_key import KmsKey
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        example = CloudwatchLogGroup(self, "example",
            name="example"
        )
        aws_kms_key_example = KmsKey(self, "example_1",
            deletion_window_in_days=7,
            description="example"
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_kms_key_example.override_logical_id("example")
        EcsCluster(self, "test",
            configuration=EcsClusterConfiguration(
                execute_command_configuration=EcsClusterConfigurationExecuteCommandConfiguration(
                    kms_key_id=Token.as_string(aws_kms_key_example.arn),
                    log_configuration=EcsClusterConfigurationExecuteCommandConfigurationLogConfiguration(
                        cloud_watch_encryption_enabled=True,
                        cloud_watch_log_group_name=example.name
                    ),
                    logging="OVERRIDE"
                )
            ),
            name="example"
        )
```

### Fargate Ephemeral Storage Encryption with Customer-Managed KMS Key

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Fn, Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_caller_identity import DataAwsCallerIdentity
from imports.aws.ecs_cluster import EcsCluster
from imports.aws.kms_key import KmsKey
from imports.aws.kms_key_policy import KmsKeyPolicy
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        example = KmsKey(self, "example",
            deletion_window_in_days=7,
            description="example"
        )
        current = DataAwsCallerIdentity(self, "current")
        aws_kms_key_policy_example = KmsKeyPolicy(self, "example_2",
            key_id=example.id,
            policy=Token.as_string(
                Fn.jsonencode({
                    "Id": "ECSClusterFargatePolicy",
                    "Statement": [{
                        "Action": "kms:*",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "*"
                        },
                        "Resource": "*",
                        "Sid": "Enable IAM User Permissions"
                    }, {
                        "Action": ["kms:GenerateDataKeyWithoutPlaintext"],
                        "Condition": {
                            "StringEquals": {
                                "kms:_encryption_context:aws:ecs:cluster_account": [current.account_id
                                ],
                                "kms:_encryption_context:aws:ecs:cluster_name": ["example"]
                            }
                        },
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "fargate.amazonaws.com"
                        },
                        "Resource": "*",
                        "Sid": "Allow generate data key access for Fargate tasks."
                    }, {
                        "Action": ["kms:CreateGrant"],
                        "Condition": {
                            "ForAllValues:StringEquals": {
                                "kms:_grant_operations": ["Decrypt"]
                            },
                            "StringEquals": {
                                "kms:_encryption_context:aws:ecs:cluster_account": [current.account_id
                                ],
                                "kms:_encryption_context:aws:ecs:cluster_name": ["example"]
                            }
                        },
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "fargate.amazonaws.com"
                        },
                        "Resource": "*",
                        "Sid": "Allow grant creation permission for Fargate tasks."
                    }
                    ],
                    "Version": "2012-10-17"
                }))
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_kms_key_policy_example.override_logical_id("example")
        EcsCluster(self, "test",
            configuration=EcsClusterConfiguration(
                managed_storage_configuration=EcsClusterConfigurationManagedStorageConfiguration(
                    fargate_ephemeral_storage_kms_key_id=example.id
                )
            ),
            depends_on=[aws_kms_key_policy_example],
            name="example"
        )
```

## Argument Reference

The following arguments are required:

* `name` - (Required) Name of the cluster (up to 255 letters, numbers, hyphens, and underscores)

The following arguments are optional:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `configuration` - (Optional) Execute command configuration for the cluster. See [`configuration` Block](#configuration-block) for details.
* `service_connect_defaults` - (Optional) Default Service Connect namespace. See [`service_connect_defaults` Block](#service_connect_defaults-block) for details.
* `setting` - (Optional) Configuration block(s) with cluster settings. For example, this can be used to enable CloudWatch Container Insights for a cluster. See [`setting` Block](#setting-block) for details.
* `tags` - (Optional) Key-value map of resource tags. If configured with a provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.

### `configuration` Block

The `configuration` configuration block supports the following arguments:

* `execute_command_configuration` - (Optional) Details of the execute command configuration. See [`execute_command_configuration` Block](#execute_command_configuration-block) for details.
* `managed_storage_configuration` - (Optional) Details of the managed storage configuration. See [`managed_storage_configuration` Block](#managed_storage_configuration-block) for details.

### `execute_command_configuration` Block

The `execute_command_configuration` configuration block supports the following arguments:

* `kms_key_id` - (Optional) AWS Key Management Service key ID to encrypt the data between the local client and the container.
* `log_configuration` - (Optional) Log configuration for the results of the execute command actions. Required when `logging` is `OVERRIDE`. See [`log_configuration` Block](#log_configuration-block) for details.
* `logging` - (Optional) Log setting to use for redirecting logs for your execute command results. Valid values: `NONE`, `DEFAULT`, `OVERRIDE`.

#### `log_configuration` Block

The `log_configuration` configuration block supports the following arguments:

* `cloud_watch_encryption_enabled` - (Optional) Whether to enable encryption on the CloudWatch logs. If not specified, encryption will be disabled.
* `cloud_watch_log_group_name` - (Optional) The name of the CloudWatch log group to send logs to.
* `s3_bucket_name` - (Optional) Name of the S3 bucket to send logs to.
* `s3_bucket_encryption_enabled` - (Optional) Whether to enable encryption on the logs sent to S3. If not specified, encryption will be disabled.
* `s3_key_prefix` - (Optional) Optional folder in the S3 bucket to place logs in.

### `managed_storage_configuration` Block

The `managed_storage_configuration` configuration block supports the following arguments:

* `fargate_ephemeral_storage_kms_key_id` - (Optional) AWS Key Management Service key ID for the Fargate ephemeral storage.
* `kms_key_id` - (Optional) AWS Key Management Service key ID to encrypt the managed storage.

### `service_connect_defaults` Block

The `service_connect_defaults` configuration block supports the following arguments:

* `namespace` - (Required) ARN of the [`aws_service_discovery_http_namespace`](/docs/providers/aws/r/service_discovery_http_namespace.html) that's used when you create a service and don't specify a Service Connect configuration.

### `setting` Block

The `setting` configuration block supports the following arguments:

* `name` - (Required) Name of the setting to manage. Valid values: `containerInsights`.
* `value` -  (Required) Value to assign to the setting. Valid values: `enhanced`, `enabled`, `disabled`.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - ARN that identifies the cluster.
* `tags_all` - Map of tags assigned to the resource, including those inherited from the provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block).

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import ECS clusters using the cluster name. For example:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.ecs_cluster import EcsCluster
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        EcsCluster.generate_config_for_import(self, "stateless", "stateless-app")
```

Using `terraform import`, import ECS clusters using the cluster name. For example:

```console
% terraform import aws_ecs_cluster.stateless stateless-app
```

<!-- cache-key: cdktf-0.20.8 input-e367a347aeed7ca364c486ddb6273745fd543ff092421952bc06e05858ddf421 -->