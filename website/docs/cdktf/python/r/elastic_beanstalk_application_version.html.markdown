---
subcategory: "Elastic Beanstalk"
layout: "aws"
page_title: "AWS: aws_elastic_beanstalk_application_version"
description: |-
  Provides an Elastic Beanstalk Application Version Resource
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_elastic_beanstalk_application_version

Provides an Elastic Beanstalk Application Version Resource. Elastic Beanstalk allows
you to deploy and manage applications in the AWS cloud without worrying about
the infrastructure that runs those applications.

This resource creates a Beanstalk Application Version that can be deployed to a Beanstalk
Environment.

~> **NOTE on Application Version Resource:**  When using the Application Version resource with multiple
[Elastic Beanstalk Environments](elastic_beanstalk_environment.html) it is possible that an error may be returned
when attempting to delete an Application Version while it is still in use by a different environment.
To work around this you can either create each environment in a separate AWS account or create your `aws_elastic_beanstalk_application_version` resources with a unique names in your Elastic Beanstalk Application. For example &lt;revision&gt;-&lt;environment&gt;.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.elastic_beanstalk_application import ElasticBeanstalkApplication
from imports.aws.elastic_beanstalk_application_version import ElasticBeanstalkApplicationVersion
from imports.aws.s3_bucket import S3Bucket
from imports.aws.s3_object import S3Object
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        ElasticBeanstalkApplication(self, "default",
            description="tf-test-desc",
            name="tf-test-name"
        )
        aws_s3_bucket_default = S3Bucket(self, "default_1",
            bucket="tftest.applicationversion.bucket"
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_s3_bucket_default.override_logical_id("default")
        aws_s3_object_default = S3Object(self, "default_2",
            bucket=Token.as_string(aws_s3_bucket_default.id),
            key="beanstalk/go-v1.zip",
            source="go-v1.zip"
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_s3_object_default.override_logical_id("default")
        aws_elastic_beanstalk_application_version_default =
        ElasticBeanstalkApplicationVersion(self, "default_3",
            application="tf-test-name",
            bucket=Token.as_string(aws_s3_bucket_default.id),
            description="application version created by terraform",
            key=Token.as_string(aws_s3_object_default.key),
            name="tf-test-version-label"
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_elastic_beanstalk_application_version_default.override_logical_id("default")
```

## Argument Reference

The following arguments are required:

* `application` - (Required) Name of the Beanstalk Application the version is associated with.
* `bucket` - (Required) S3 bucket that contains the Application Version source bundle.
* `key` - (Required) S3 object that is the Application Version source bundle.
* `name` - (Required) Unique name for the this Application Version.

The following arguments are optional:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `description` - (Optional) Short description of the Application Version.
* `force_delete` - (Optional) On delete, force an Application Version to be deleted when it may be in use by multiple Elastic Beanstalk Environments.
* `process` - (Optional) Pre-processes and validates the environment manifest (env.yaml ) and configuration files (*.config files in the .ebextensions folder) in the source bundle. Validating configuration files can identify issues prior to deploying the application version to an environment. You must turn processing on for application versions that you create using AWS CodeBuild or AWS CodeCommit. For application versions built from a source bundle in Amazon S3, processing is optional. It validates Elastic Beanstalk configuration files. It doesn’t validate your application’s configuration files, like proxy server or Docker configuration.
* `tags` - (Optional) Key-value map of tags for the Elastic Beanstalk Application Version. If configured with a provider [`default_tags` configuration block](https://www.terraform.io/docs/providers/aws/index.html#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - ARN assigned by AWS for this Elastic Beanstalk Application.
* `tags_all` - Map of tags assigned to the resource, including those inherited from the provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block).

<!-- cache-key: cdktf-0.20.8 input-5842d548570f5bde5f23ea961b4e7f4778cf076094d5cebf0b90969386ce5e3d -->