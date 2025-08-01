---
subcategory: "Comprehend"
layout: "aws"
page_title: "AWS: aws_comprehend_entity_recognizer"
description: |-
  Terraform resource for managing an AWS Comprehend Entity Recognizer.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_comprehend_entity_recognizer

Terraform resource for managing an AWS Comprehend Entity Recognizer.

## Example Usage

### Basic Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { ComprehendEntityRecognizer } from "./.gen/providers/aws/comprehend-entity-recognizer";
import { S3Object } from "./.gen/providers/aws/s3-object";
interface MyConfig {
  bucket: any;
  key: any;
  bucket1: any;
  key1: any;
}
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string, config: MyConfig) {
    super(scope, name);
    const documents = new S3Object(this, "documents", {
      bucket: config.bucket,
      key: config.key,
    });
    const entities = new S3Object(this, "entities", {
      bucket: config.bucket1,
      key: config.key1,
    });
    new ComprehendEntityRecognizer(this, "example", {
      dataAccessRoleArn: Token.asString(awsIamRoleExample.arn),
      dependsOn: [awsIamRolePolicyExample],
      inputDataConfig: {
        documents: {
          s3Uri:
            "s3://${" +
            awsS3BucketDocuments.bucket +
            "}/${" +
            documents.key +
            "}",
        },
        entityList: {
          s3Uri:
            "s3://${" +
            awsS3BucketEntities.bucket +
            "}/${" +
            entities.key +
            "}",
        },
        entityTypes: [
          {
            type: "ENTITY_1",
          },
          {
            type: "ENTITY_2",
          },
        ],
      },
      languageCode: "en",
      name: "example",
    });
  }
}

```

## Argument Reference

The following arguments are required:

* `dataAccessRoleArn` - (Required) The ARN for an IAM Role which allows Comprehend to read the training and testing data.
* `inputDataConfig` - (Required) Configuration for the training and testing data.
  See the [`inputDataConfig` Configuration Block](#input_data_config-configuration-block) section below.
* `languageCode` - (Required) Two-letter language code for the language.
  One of `en`, `es`, `fr`, `it`, `de`, or `pt`.
* `name` - (Required) Name for the Entity Recognizer.
  Has a maximum length of 63 characters.
  Can contain upper- and lower-case letters, numbers, and hypen (`-`).

The following arguments are optional:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `modelKmsKeyId` - (Optional) The ID or ARN of a KMS Key used to encrypt trained Entity Recognizers.
* `tags` - (Optional) A map of tags to assign to the resource. If configured with a provider [`defaultTags` Configuration Block](/docs/providers/aws/index.html#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.
* `versionName` - (Optional) Name for the version of the Entity Recognizer.
  Each version must have a unique name within the Entity Recognizer.
  If omitted, Terraform will assign a random, unique version name.
  If explicitly set to `""`, no version name will be set.
  Has a maximum length of 63 characters.
  Can contain upper- and lower-case letters, numbers, and hypen (`-`).
  Conflicts with `versionNamePrefix`.
* `versionNamePrefix` - (Optional) Creates a unique version name beginning with the specified prefix.
  Has a maximum length of 37 characters.
  Can contain upper- and lower-case letters, numbers, and hypen (`-`).
  Conflicts with `versionName`.
* `volumeKmsKeyId` - (Optional) ID or ARN of a KMS Key used to encrypt storage volumes during job processing.
* `vpcConfig` - (Optional) Configuration parameters for VPC to contain Entity Recognizer resources.
  See the [`vpcConfig` Configuration Block](#vpc_config-configuration-block) section below.

### `inputDataConfig` Configuration Block

* `annotations` - (Optional) Specifies location of the document annotation data.
  See the [`annotations` Configuration Block](#annotations-configuration-block) section below.
  One of `annotations` or `entityList` is required.
* `augmentedManifests` - (Optional) List of training datasets produced by Amazon SageMaker AI Ground Truth.
  Used if `dataFormat` is `AUGMENTED_MANIFEST`.
  See the [`augmentedManifests` Configuration Block](#augmented_manifests-configuration-block) section below.
* `dataFormat` - (Optional, Default: `COMPREHEND_CSV`) The format for the training data.
  One of `COMPREHEND_CSV` or `AUGMENTED_MANIFEST`.
* `documents` - (Optional) Specifies a collection of training documents.
  Used if `dataFormat` is `COMPREHEND_CSV`.
  See the [`documents` Configuration Block](#documents-configuration-block) section below.
* `entityList` - (Optional) Specifies location of the entity list data.
  See the [`entityList` Configuration Block](#entity_list-configuration-block) section below.
  One of `entityList` or `annotations` is required.
* `entityTypes` - (Required) Set of entity types to be recognized.
  Has a maximum of 25 items.
  See the [`entityTypes` Configuration Block](#entity_types-configuration-block) section below.

### `annotations` Configuration Block

* `s3Uri` - (Required) Location of training annotations.
* `test_s3uri` - (Optional) Location of test annotations.

### `augmentedManifests` Configuration Block

* `annotationDataS3Uri` - (Optional) Location of annotation files.
* `attributeNames` - (Required) The JSON attribute that contains the annotations for the training documents.
* `documentType` - (Optional, Default: `PLAIN_TEXT_DOCUMENT`) Type of augmented manifest.
  One of `PLAIN_TEXT_DOCUMENT` or `SEMI_STRUCTURED_DOCUMENT`.
* `s3Uri` - (Required) Location of augmented manifest file.
* `sourceDocumentsS3Uri` - (Optional) Location of source PDF files.
* `split` - (Optional, Default: `TRAIN`) Purpose of data in augmented manifest.
  One of `TRAIN` or `TEST`.

### `documents` Configuration Block

* `inputFormat` - (Optional, Default: `ONE_DOC_PER_LINE`) Specifies how the input files should be processed.
  One of `ONE_DOC_PER_LINE` or `ONE_DOC_PER_FILE`.
* `s3Uri` - (Required) Location of training documents.
* `test_s3uri` - (Optional) Location of test documents.

### `entityList` Configuration Block

* `s3Uri` - (Required) Location of entity list.

### `entityTypes` Configuration Block

* `type` - (Required) An entity type to be matched by the Entity Recognizer.
  Cannot contain a newline (`\n`), carriage return (`\r`), or tab (`\t`).

### `vpcConfig` Configuration Block

* `securityGroupIds` - (Required) List of security group IDs.
* `subnets` - (Required) List of VPC subnets.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - ARN of the Entity Recognizer version.
* `tagsAll` - A map of tags assigned to the resource, including those inherited from the provider [`defaultTags` configuration block](/docs/providers/aws/index.html#default_tags-configuration-block).

## Timeouts

`aws_comprehend_entity_recognizer` provides the following [Timeouts](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts) configuration options:

* `create` - (Optional, Default: `60m`)
* `update` - (Optional, Default: `60m`)
* `delete` - (Optional, Default: `30m`)

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import Comprehend Entity Recognizer using the ARN. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { ComprehendEntityRecognizer } from "./.gen/providers/aws/comprehend-entity-recognizer";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    ComprehendEntityRecognizer.generateConfigForImport(
      this,
      "example",
      "arn:aws:comprehend:us-west-2:123456789012:entity-recognizer/example"
    );
  }
}

```

Using `terraform import`, import Comprehend Entity Recognizer using the ARN. For example:

```console
% terraform import aws_comprehend_entity_recognizer.example arn:aws:comprehend:us-west-2:123456789012:entity-recognizer/example
```

<!-- cache-key: cdktf-0.20.8 input-a322b23d77ddec60dd96293537854094550b4b3142e94fd0a14ebac19e3ef22e -->