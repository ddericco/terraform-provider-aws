---
subcategory: "S3 (Simple Storage)"
layout: "aws"
page_title: "AWS: aws_s3_bucket_public_access_block"
description: |-
  Manages S3 bucket-level Public Access Block Configuration
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_s3_bucket_public_access_block

Manages S3 bucket-level Public Access Block configuration. For more information about these settings, see the [AWS S3 Block Public Access documentation](https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html).

-> This resource cannot be used with S3 directory buckets.

~> Setting `skipDestroy` to `true` means that the AWS Provider will not destroy a public access block, even when running `terraform destroy`. The configuration is thus an intentional dangling resource that is not managed by Terraform and will remain in-place in your AWS account.

## Example Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { S3Bucket } from "./.gen/providers/aws/s3-bucket";
import { S3BucketPublicAccessBlock } from "./.gen/providers/aws/s3-bucket-public-access-block";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    const example = new S3Bucket(this, "example", {
      bucket: "example",
    });
    const awsS3BucketPublicAccessBlockExample = new S3BucketPublicAccessBlock(
      this,
      "example_1",
      {
        blockPublicAcls: true,
        blockPublicPolicy: true,
        bucket: example.id,
        ignorePublicAcls: true,
        restrictPublicBuckets: true,
      }
    );
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    awsS3BucketPublicAccessBlockExample.overrideLogicalId("example");
  }
}

```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `bucket` - (Required) S3 Bucket to which this Public Access Block configuration should be applied.
* `blockPublicAcls` - (Optional) Whether Amazon S3 should block public ACLs for this bucket. Defaults to `false`. Enabling this setting does not affect existing policies or ACLs. When set to `true` causes the following behavior:
    * PUT Bucket ACL and PUT Object ACL calls will fail if the specified ACL allows public access.
    * PUT Object calls will fail if the request includes an object ACL.
* `blockPublicPolicy` - (Optional) Whether Amazon S3 should block public bucket policies for this bucket. Defaults to `false`. Enabling this setting does not affect the existing bucket policy. When set to `true` causes Amazon S3 to:
    * Reject calls to PUT Bucket policy if the specified bucket policy allows public access.
* `ignorePublicAcls` - (Optional) Whether Amazon S3 should ignore public ACLs for this bucket. Defaults to `false`. Enabling this setting does not affect the persistence of any existing ACLs and doesn't prevent new public ACLs from being set. When set to `true` causes Amazon S3 to:
    * Ignore public ACLs on this bucket and any objects that it contains.
* `restrictPublicBuckets` - (Optional) Whether Amazon S3 should restrict public bucket policies for this bucket. Defaults to `false`. Enabling this setting does not affect the previously stored bucket policy, except that public and cross-account access within the public bucket policy, including non-public delegation to specific accounts, is blocked. When set to `true`:
    * Only the bucket owner and AWS Services can access this buckets if it has a public policy.
* `skipDestroy` - (Optional) Whether to retain the public access block upon destruction. If set to `true`, the resource is simply removed from state instead. This may be desirable in certain scenarios to prevent the removal of a public access block before deletion of the associated bucket.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `id` - Name of the S3 bucket the configuration is attached to

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import `aws_s3_bucket_public_access_block` using the bucket name. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { S3BucketPublicAccessBlock } from "./.gen/providers/aws/s3-bucket-public-access-block";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    S3BucketPublicAccessBlock.generateConfigForImport(
      this,
      "example",
      "my-bucket"
    );
  }
}

```

Using `terraform import`, import `aws_s3_bucket_public_access_block` using the bucket name. For example:

```console
% terraform import aws_s3_bucket_public_access_block.example my-bucket
```

<!-- cache-key: cdktf-0.20.8 input-bd43df664e3914c56c85483d9189abab41acce8fcff0d888e7c1ecf318bbbf55 -->