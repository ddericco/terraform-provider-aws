---
subcategory: "RDS (Relational Database)"
layout: "aws"
page_title: "AWS: aws_db_cluster_snapshot"
description: |-
  Get information on a DB Cluster Snapshot.
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_db_cluster_snapshot

Use this data source to get information about a DB Cluster Snapshot for use when provisioning DB clusters.

~> **NOTE:** This data source does not apply to snapshots created on DB Instances.
See the [`aws_db_snapshot` data source](/docs/providers/aws/d/db_snapshot.html) for DB Instance snapshots.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from cdktf import TerraformResourceLifecycle
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_db_cluster_snapshot import DataAwsDbClusterSnapshot
from imports.aws.rds_cluster import RdsCluster
from imports.aws.rds_cluster_instance import RdsClusterInstance
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name, *, engine, engine1):
        super().__init__(scope, name)
        development_final_snapshot = DataAwsDbClusterSnapshot(self, "development_final_snapshot",
            db_cluster_identifier="development_cluster",
            most_recent=True
        )
        aurora = RdsCluster(self, "aurora",
            cluster_identifier="development_cluster",
            db_subnet_group_name="my_db_subnet_group",
            lifecycle=TerraformResourceLifecycle(
                ignore_changes=[snapshot_identifier]
            ),
            snapshot_identifier=Token.as_string(development_final_snapshot.id),
            engine=engine
        )
        aws_rds_cluster_instance_aurora = RdsClusterInstance(self, "aurora_2",
            cluster_identifier=aurora.id,
            db_subnet_group_name="my_db_subnet_group",
            instance_class="db.t2.small",
            engine=engine1
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_rds_cluster_instance_aurora.override_logical_id("aurora")
```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `most_recent` - (Optional) If more than one result is returned, use the most recent Snapshot.
* `db_cluster_identifier` - (Optional) Returns the list of snapshots created by the specific db_cluster
* `db_cluster_snapshot_identifier` - (Optional) Returns information on a specific snapshot_id.
* `snapshot_type` - (Optional) Type of snapshots to be returned. If you don't specify a SnapshotType
value, then both automated and manual DB cluster snapshots are returned. Shared and public DB Cluster Snapshots are not
included in the returned results by default. Possible values are, `automated`, `manual`, `shared`, `public` and `awsbackup`.
* `include_shared` - (Optional) Set this value to true to include shared manual DB Cluster Snapshots from other
AWS accounts that this AWS account has been given permission to copy or restore, otherwise set this value to false.
The default is `false`.
* `include_public` - (Optional) Set this value to true to include manual DB Cluster Snapshots that are public and can be
copied or restored by any AWS account, otherwise set this value to false. The default is `false`.
* `tags` - (Optional) Mapping of tags, each pair of which must exactly match
  a pair on the desired DB cluster snapshot.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `allocated_storage` - Allocated storage size in gigabytes (GB).
* `availability_zones` - List of EC2 Availability Zones that instances in the DB cluster snapshot can be restored in.
* `db_cluster_identifier` - Specifies the DB cluster identifier of the DB cluster that this DB cluster snapshot was created from.
* `db_cluster_snapshot_arn` - The ARN for the DB Cluster Snapshot.
* `engine_version` - Version of the database engine for this DB cluster snapshot.
* `engine` - Name of the database engine.
* `id` - Snapshot ID.
* `kms_key_id` - If storage_encrypted is true, the AWS KMS key identifier for the encrypted DB cluster snapshot.
* `license_model` - License model information for the restored DB cluster.
* `port` - Port that the DB cluster was listening on at the time of the snapshot.
* `snapshot_create_time` - Time when the snapshot was taken, in Universal Coordinated Time (UTC).
* `source_db_cluster_snapshot_identifier` - DB Cluster Snapshot ARN that the DB Cluster Snapshot was copied from. It only has value in case of cross customer or cross region copy.
* `status` - Status of this DB Cluster Snapshot.
* `storage_encrypted` - Whether the DB cluster snapshot is encrypted.
* `vpc_id` - VPC ID associated with the DB cluster snapshot.
* `tags` - Map of tags for the resource.

<!-- cache-key: cdktf-0.20.8 input-cba4bad9cc90ba77a0dac1d30c48b643991f8cf9a3ebcd57cb34bfe86acc8b51 -->