---
subcategory: "Lambda"
layout: "aws"
page_title: "AWS: aws_lambda_invocation"
description: |-
  Invokes an AWS Lambda Function as an ephemeral resource.
---


<!-- Please do not edit this file, it is generated. -->
# Ephemeral: aws_lambda_invocation

Invokes an AWS Lambda Function as an ephemeral resource. Use this ephemeral resource to execute Lambda functions during Terraform operations without persisting results in state, ideal for generating sensitive data or performing lightweight operations.

The Lambda function is invoked with [RequestResponse](https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax) invocation type.

~> **Note:** Ephemeral resources are a new feature and may evolve as we continue to explore their most effective uses. [Learn more](https://developer.hashicorp.com/terraform/language/resources/ephemeral).

~> **Note:** The `aws_lambda_invocation` ephemeral resource invokes the function during every `plan` and `apply` when the function is known. A common use case for this functionality is when invoking a lightweight function—where repeated invocations are acceptable—that produces sensitive information you do not want to store in the state.

~> **Note:** If you get a `KMSAccessDeniedException: Lambda was unable to decrypt the environment variables because KMS access was denied` error when invoking a Lambda function with environment variables, the IAM role associated with the function may have been deleted and recreated after the function was created. You can fix the problem two ways: 1) updating the function's role to another role and then updating it back again to the recreated role, or 2) by using Terraform to `taint` the function and `apply` your configuration again to recreate the function. (When you create a function, Lambda grants permissions on the KMS key to the function's IAM role. If the IAM role is recreated, the grant is no longer valid. Changing the function's role or recreating the function causes Lambda to update the grant.)

## Example Usage

### Generate Sensitive Configuration

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import VariableType, TerraformVariable, TerraformOutput, Fn, Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.ssm_parameter import SsmParameter
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        # Terraform Variables are not always the best fit for getting inputs in the context of Terraform CDK.
        #     You can read more about this at https://cdk.tf/variables
        environment = TerraformVariable(self, "environment",
            description="The environment name (e.g., dev, prod)",
            type=VariableType.STRING
        )
        TerraformOutput(self, "key_generated",
            value="API key generated and stored in Parameter Store"
        )
        SsmParameter(self, "api_key",
            name="/app/${" + environment.value + "}/api-key",
            tags={
                "Environment": environment.string_value,
                "Generated": "ephemeral-lambda"
            },
            type="SecureString",
            value=Token.as_string(
                Fn.lookup_nested(
                    Fn.jsondecode(aws_lambda_invocation.secret_generator.result), ["api_key"]))
        )
```

### Dynamic Resource Configuration

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Fn, Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.autoscaling_group import AutoscalingGroup
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        sizing = Fn.jsondecode(aws_lambda_invocation.resource_calculator.result)
        AutoscalingGroup(self, "example",
            desired_capacity=Token.as_number(
                Fn.lookup_nested(sizing, ["desired_instances"])),
            health_check_type="ELB",
            launch_template=AutoscalingGroupLaunchTemplate(
                id=Token.as_string(aws_launch_template_example.id),
                version="$Latest"
            ),
            max_size=Token.as_number(Fn.lookup_nested(sizing, ["max_instances"])),
            min_size=Token.as_number(Fn.lookup_nested(sizing, ["min_instances"])),
            name="optimized-asg",
            tag=[AutoscalingGroupTag(
                key="OptimizedBy",
                propagate_at_launch=True,
                value="ephemeral-lambda"
            )
            ],
            target_group_arns=[Token.as_string(aws_lb_target_group_example.arn)],
            vpc_zone_identifier=subnet_ids.list_value
        )
```

### Validation and Compliance Checks

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from cdktf import FileProvisioner
from constructs import Construct
from cdktf import VariableType, TerraformVariable, conditional, Token, TerraformCount, Fn, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.null.resource import Resource
from imports.aws.instance import Instance
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        # Terraform Variables are not always the best fit for getting inputs in the context of Terraform CDK.
        #     You can read more about this at https://cdk.tf/variables
        instance_type = TerraformVariable(self, "instance_type",
            description="The EC2 instance type to use",
            type=VariableType.STRING
        )
        is_compliant = compliant
        violations = validation_result_violations
        # In most cases loops should be handled in the programming language context and
        #     not inside of the Terraform context. If you are looping over something external, e.g. a variable or a file input
        #     you should consider using a for loop. If you are looping over something only known to Terraform, e.g. a result of a data source
        #     you need to keep this like it is.
        example_count = TerraformCount.of(
            Token.as_number(conditional(is_compliant, 1, 0)))
        Instance(self, "example",
            ami=Token.as_string(data_aws_ami_example.id),
            instance_type=instance_type.string_value,
            root_block_device=InstanceRootBlockDevice(
                encrypted=encrypt_storage.boolean_value
            ),
            tags={
                "ComplianceCheck": "passed",
                "Environment": environment.string_value
            },
            count=example_count
        )
        # In most cases loops should be handled in the programming language context and
        #     not inside of the Terraform context. If you are looping over something external, e.g. a variable or a file input
        #     you should consider using a for loop. If you are looping over something only known to Terraform, e.g. a result of a data source
        #     you need to keep this like it is.
        compliance_gate_count = TerraformCount.of(
            Token.as_number(conditional(is_compliant, 0, 1)))
        Resource(self, "compliance_gate",
            count=compliance_gate_count,
            provisioners=[FileProvisioner(
                type="local-exec",
                command="echo 'Compliance violations: " +
                Token.as_string(Fn.join(", ", Token.as_list(violations))) + "' && exit 1"
            )
            ]
        )
```

### External API Integration

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Fn, Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.ecs_service import EcsService
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        external_config = Fn.jsondecode(aws_lambda_invocation.external_config.result)
        EcsService(self, "example",
            cluster=Token.as_string(aws_ecs_cluster_example.id),
            deployment_configuration=EcsServiceDeploymentConfiguration(
                maximum_percent=Fn.lookup_nested(external_config, ["max_percent"]),
                minimum_healthy_percent=Fn.lookup_nested(external_config, ["min_healthy_percent"
                ])
            ),
            desired_count=Token.as_number(
                Fn.lookup_nested(external_config, ["replica_count"])),
            name="web-app",
            tags={
                "ConfigSource": "external-api",
                "Environment": environment.string_value
            },
            task_definition=Token.as_string(aws_ecs_task_definition_example.arn)
        )
```

## Argument Reference

The following arguments are required:

* `function_name` - (Required) Name or ARN of the Lambda function, version, or alias. You can append a version number or alias. If you specify only the function name, it is limited to 64 characters in length.
* `payload` - (Required) JSON that you want to provide to your Lambda function as input.

The following arguments are optional:

* `client_context` - (Optional) Up to 3583 bytes of base64-encoded data about the invoking client to pass to the function in the context object.
* `log_type` - (Optional) Set to `Tail` to include the execution log in the response. Valid values: `None` and `Tail`.
* `qualifier` - (Optional) Version or alias to invoke a published version of the function. Defaults to `$LATEST`.
* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).

## Attribute Reference

This ephemeral resource exports the following attributes in addition to the arguments above:

* `executed_version` - Version of the function that executed. When you invoke a function with an alias, this shows the version the alias resolved to.
* `function_error` - If present, indicates that an error occurred during function execution. Details about the error are included in `result`.
* `log_result` - Last 4 KB of the execution log, which is base64-encoded.
* `result` - String result of the Lambda function invocation.
* `status_code` - HTTP status code is in the 200 range for a successful request.

## Usage Notes

### Handling Sensitive Data

Since ephemeral resources are designed to not persist data in state, they are ideal for handling sensitive information:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.secretsmanager_secret_version import SecretsmanagerSecretVersion
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        SecretsmanagerSecretVersion(self, "example",
            secret_id=Token.as_string(aws_secretsmanager_secret_example.id),
            secret_string=aws_lambda_invocation.credentials.result
        )
```

### Error Handling

Always check for function errors in your configuration:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Op, Fn, Token, conditional, TerraformCount, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.null.resource import Resource
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        has_error = Op.neq(aws_lambda_invocation.example.function_error, "null")
        invocation_result = Fn.jsondecode(aws_lambda_invocation.example.result)
        # In most cases loops should be handled in the programming language context and
        #     not inside of the Terraform context. If you are looping over something external, e.g. a variable or a file input
        #     you should consider using a for loop. If you are looping over something only known to Terraform, e.g. a result of a data source
        #     you need to keep this like it is.
        validation_count = TerraformCount.of(
            Token.as_number(
                conditional(has_error,
                    fail("Lambda function error: " +
                        Token.as_string(
                            Fn.lookup_nested(invocation_result, ["errorMessage"]))), 0)))
        Resource(self, "validation",
            count=validation_count
        )
```

### Logging

Enable detailed logging for debugging:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformOutput, Fn, TerraformStack
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        TerraformOutput(self, "execution_logs",
            value=Fn.base64decode(aws_lambda_invocation.example.log_result)
        )
```

<!-- cache-key: cdktf-0.20.8 input-be30ef92373442009830424f096e3a034510eb688acf4a1eea5533b5570b08bc -->