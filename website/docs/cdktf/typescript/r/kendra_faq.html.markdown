---
subcategory: "Kendra"
layout: "aws"
page_title: "AWS: aws_kendra_faq"
description: |-
  Terraform resource for managing an AWS Kendra FAQ.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_kendra_faq

Terraform resource for managing an AWS Kendra FAQ.

## Example Usage

### Basic

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { KendraFaq } from "./.gen/providers/aws/kendra-faq";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new KendraFaq(this, "example", {
      indexId: Token.asString(awsKendraIndexExample.id),
      name: "Example",
      roleArn: Token.asString(awsIamRoleExample.arn),
      s3Path: {
        bucket: Token.asString(awsS3BucketExample.id),
        key: Token.asString(awsS3ObjectExample.key),
      },
      tags: {
        Name: "Example Kendra Faq",
      },
    });
  }
}

```

### With File Format

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { KendraFaq } from "./.gen/providers/aws/kendra-faq";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new KendraFaq(this, "example", {
      fileFormat: "CSV",
      indexId: Token.asString(awsKendraIndexExample.id),
      name: "Example",
      roleArn: Token.asString(awsIamRoleExample.arn),
      s3Path: {
        bucket: Token.asString(awsS3BucketExample.id),
        key: Token.asString(awsS3ObjectExample.key),
      },
    });
  }
}

```

### With Language Code

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { KendraFaq } from "./.gen/providers/aws/kendra-faq";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new KendraFaq(this, "example", {
      indexId: Token.asString(awsKendraIndexExample.id),
      languageCode: "en",
      name: "Example",
      roleArn: Token.asString(awsIamRoleExample.arn),
      s3Path: {
        bucket: Token.asString(awsS3BucketExample.id),
        key: Token.asString(awsS3ObjectExample.key),
      },
    });
  }
}

```

## Argument Reference

The following arguments are required:

* `indexId`- (Required, Forces new resource) The identifier of the index for a FAQ.
* `name` - (Required, Forces new resource) The name that should be associated with the FAQ.
* `roleArn` - (Required, Forces new resource) The Amazon Resource Name (ARN) of a role with permission to access the S3 bucket that contains the FAQs. For more information, see [IAM Roles for Amazon Kendra](https://docs.aws.amazon.com/kendra/latest/dg/iam-roles.html).
* `s3Path` - (Required, Forces new resource) The S3 location of the FAQ input data. Detailed below.

The `s3Path` configuration block supports the following arguments:

* `bucket` - (Required, Forces new resource) The name of the S3 bucket that contains the file.
* `key` - (Required, Forces new resource) The name of the file.

The following arguments are optional:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `description` - (Optional, Forces new resource) The description for a FAQ.
* `fileFormat` - (Optional, Forces new resource) The file format used by the input files for the FAQ. Valid Values are `CSV`, `CSV_WITH_HEADER`, `JSON`.
* `languageCode` - (Optional, Forces new resource) The code for a language. This shows a supported language for the FAQ document. English is supported by default. For more information on supported languages, including their codes, see [Adding documents in languages other than English](https://docs.aws.amazon.com/kendra/latest/dg/in-adding-languages.html).
* `tags` - (Optional) Key-value map of resource tags. If configured with a provider [`defaultTags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - ARN of the FAQ.
* `createdAt` - The Unix datetime that the FAQ was created.
* `errorMessage` - When the Status field value is `FAILED`, this contains a message that explains why.
* `faqId` - The identifier of the FAQ.
* `id` - The unique identifiers of the FAQ and index separated by a slash (`/`)
* `status` - The status of the FAQ. It is ready to use when the status is ACTIVE.
* `updatedAt` - The date and time that the FAQ was last updated.
* `tagsAll` - A map of tags assigned to the resource, including those inherited from the provider [`defaultTags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block).

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

* `create` - (Default `30m`)
* `delete` - (Default `30m`)

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import `aws_kendra_faq` using the unique identifiers of the FAQ and index separated by a slash (`/`). For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { KendraFaq } from "./.gen/providers/aws/kendra-faq";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    KendraFaq.generateConfigForImport(
      this,
      "example",
      "faq-123456780/idx-8012925589"
    );
  }
}

```

Using `terraform import`, import `aws_kendra_faq` using the unique identifiers of the FAQ and index separated by a slash (`/`). For example:

```console
% terraform import aws_kendra_faq.example faq-123456780/idx-8012925589
```

<!-- cache-key: cdktf-0.20.8 input-485317c2b3c379728ee38ca33f994068863bfb93fc45d7c6b43a90df3cbdccd7 -->