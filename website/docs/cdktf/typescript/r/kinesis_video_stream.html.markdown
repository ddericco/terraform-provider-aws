---
subcategory: "Kinesis Video"
layout: "aws"
page_title: "AWS: aws_kinesis_video_stream"
description: |-
  Provides a AWS Kinesis Video Stream
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_kinesis_video_stream

Provides a Kinesis Video Stream resource. Amazon Kinesis Video Streams makes it easy to securely stream video from connected devices to AWS for analytics, machine learning (ML), playback, and other processing.

For more details, see the [Amazon Kinesis Documentation][1].

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { KinesisVideoStream } from "./.gen/providers/aws/kinesis-video-stream";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new KinesisVideoStream(this, "default", {
      dataRetentionInHours: 1,
      deviceName: "kinesis-video-device-name",
      mediaType: "video/h264",
      name: "terraform-kinesis-video-stream",
      tags: {
        Name: "terraform-kinesis-video-stream",
      },
    });
  }
}

```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `name` - (Required) A name to identify the stream. This is unique to the
AWS account and region the Stream is created in.
* `dataRetentionInHours` - (Optional) The number of hours that you want to retain the data in the stream. Kinesis Video Streams retains the data in a data store that is associated with the stream. The default value is `0`, indicating that the stream does not persist data.
* `deviceName` - (Optional) The name of the device that is writing to the stream. **In the current implementation, Kinesis Video Streams does not use this name.**
* `kmsKeyId` - (Optional) The ID of the AWS Key Management Service (AWS KMS) key that you want Kinesis Video Streams to use to encrypt stream data. If no key ID is specified, the default, Kinesis Video-managed key (`aws/kinesisvideo`) is used.
* `mediaType` - (Optional) The media type of the stream. Consumers of the stream can use this information when processing the stream. For more information about media types, see [Media Types][2]. If you choose to specify the MediaType, see [Naming Requirements][3] for guidelines.
* `tags` - (Optional) A map of tags to assign to the resource. If configured with a provider [`defaultTags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `id` - The unique Stream id
* `arn` - The Amazon Resource Name (ARN) specifying the Stream (same as `id`)
* `creationTime` - A time stamp that indicates when the stream was created.
* `version` - The version of the stream.
* `tagsAll` - A map of tags assigned to the resource, including those inherited from the provider [`defaultTags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block).

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

- `create` - (Default `5m`)
- `update` - (Default `120m`)
- `delete` - (Default `120m`)

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import Kinesis Streams using the `arn`. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { KinesisVideoStream } from "./.gen/providers/aws/kinesis-video-stream";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    KinesisVideoStream.generateConfigForImport(
      this,
      "testStream",
      "arn:aws:kinesisvideo:us-west-2:123456789012:stream/terraform-kinesis-test/1554978910975"
    );
  }
}

```

Using `terraform import`, import Kinesis Streams using the `arn`. For example:

```console
% terraform import aws_kinesis_video_stream.test_stream arn:aws:kinesisvideo:us-west-2:123456789012:stream/terraform-kinesis-test/1554978910975
```

[1]: https://aws.amazon.com/documentation/kinesis/
[2]: http://www.iana.org/assignments/media-types/media-types.xhtml
[3]: https://tools.ietf.org/html/rfc6838#section-4.2

<!-- cache-key: cdktf-0.20.8 input-dedf5ff090614f76ad9a3502507f844f57c0a5ebef980e5a8691535940df0ebe -->