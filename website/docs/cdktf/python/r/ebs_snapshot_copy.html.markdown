---
subcategory: "EBS (EC2)"
layout: "aws"
page_title: "AWS: aws_ebs_snapshot_copy"
description: |-
  Duplicates an existing Amazon snapshot
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_ebs_snapshot_copy

Creates a Snapshot of a snapshot.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.ebs_snapshot import EbsSnapshot
from imports.aws.ebs_snapshot_copy import EbsSnapshotCopy
from imports.aws.ebs_volume import EbsVolume
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        example = EbsVolume(self, "example",
            availability_zone="us-west-2a",
            size=40,
            tags={
                "Name": "HelloWorld"
            }
        )
        example_snapshot = EbsSnapshot(self, "example_snapshot",
            tags={
                "Name": "HelloWorld_snap"
            },
            volume_id=example.id
        )
        EbsSnapshotCopy(self, "example_copy",
            source_region="us-west-2",
            source_snapshot_id=example_snapshot.id,
            tags={
                "Name": "HelloWorld_copy_snap"
            }
        )
```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `description` - (Optional) A description of what the snapshot is.
* `encrypted` - Whether the snapshot is encrypted.
* `kms_key_id` - The ARN for the KMS encryption key.
* `source_snapshot_id` The ARN for the snapshot to be copied.
* `source_region` The region of the source snapshot.
* `storage_tier` - (Optional) The name of the storage tier. Valid values are `archive` and `standard`. Default value is `standard`.
* `permanent_restore` - (Optional) Indicates whether to permanently restore an archived snapshot.
* `temporary_restore_days` - (Optional) Specifies the number of days for which to temporarily restore an archived snapshot. Required for temporary restores only. The snapshot will be automatically re-archived after this period.
* `completion_duration_minutes` - (Optional) Specifies a completion duration to initiate a time-based snapshot copy. Time-based snapshot copy operations complete within the specified duration.  Value must be between 15 and 2880 minutes, in 15 minute increments only.
* `tags` - A map of tags for the snapshot. If configured with a provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - Amazon Resource Name (ARN) of the EBS Snapshot.
* `id` - The snapshot ID (e.g., snap-59fcb34e).
* `owner_id` - The AWS account ID of the snapshot owner.
* `owner_alias` - Value from an Amazon-maintained list (`amazon`, `aws-marketplace`, `microsoft`) of snapshot owners.
* `volume_size` - The size of the drive in GiBs.
* `data_encryption_key_id` - The data encryption key identifier for the snapshot.
* `tags_all` - A map of tags assigned to the resource, including those inherited from the provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block).

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

- `create` - (Default `10m`)
- `delete` - (Default `10m`)

<!-- cache-key: cdktf-0.20.8 input-722c74d0d5a78eb9cff24e7224bcd1a9e20c90f7576cc3ece5546db5df37998f -->