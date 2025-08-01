---
subcategory: "Lake Formation"
layout: "aws"
page_title: "AWS: aws_lakeformation_permissions"
description: |-
    Grants permissions to the principal to access metadata in the Data Catalog and data organized in underlying data storage such as Amazon S3.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_lakeformation_permissions

Grants permissions to the principal to access metadata in the Data Catalog and data organized in underlying data storage such as Amazon S3. Permissions are granted to a principal, in a Data Catalog, relative to a Lake Formation resource, which includes the Data Catalog, databases, tables, LF-tags, and LF-tag policies. For more information, see [Security and Access Control to Metadata and Data in Lake Formation](https://docs.aws.amazon.com/lake-formation/latest/dg/security-data-access.html).

!> **WARNING:** Lake Formation permissions are not in effect by default within AWS. Using this resource will not secure your data and will result in errors if you do not change the security settings for existing resources and the default security settings for new resources. See [Default Behavior and `IAMAllowedPrincipals`](#default-behavior-and-iamallowedprincipals) for additional details.

~> **NOTE:** In general, the `principal` should _NOT_ be a Lake Formation administrator or the entity (e.g., IAM role) that is running Terraform. Administrators have implicit permissions. These should be managed by granting or not granting administrator rights using `aws_lakeformation_data_lake_settings`, _not_ with this resource.

## Default Behavior and `IAMAllowedPrincipals`

**_Lake Formation permissions are not in effect by default within AWS._** `IAMAllowedPrincipals` (i.e., `IAM_ALLOWED_PRINCIPALS`) conflicts with individual Lake Formation permissions (i.e., non-`IAMAllowedPrincipals` permissions), will cause unexpected behavior, and may result in errors.

When using Lake Formation, choose ONE of the following options as they are mutually exclusive:

1. Use this resource (`aws_lakeformation_permissions`), change the default security settings using [`aws_lakeformation_data_lake_settings`](/docs/providers/aws/r/lakeformation_data_lake_settings.html), and remove existing `IAMAllowedPrincipals` permissions
2. Use `IAMAllowedPrincipals` without `aws_lakeformation_permissions`

This example shows removing the `IAMAllowedPrincipals` default security settings and making the caller a Lake Formation admin. Since `createDatabaseDefaultPermissions` and `createTableDefaultPermissions` are not set in the [`aws_lakeformation_data_lake_settings`](/docs/providers/aws/r/lakeformation_data_lake_settings.html) resource, they are cleared.

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsCallerIdentity } from "./.gen/providers/aws/data-aws-caller-identity";
import { DataAwsIamSessionContext } from "./.gen/providers/aws/data-aws-iam-session-context";
import { LakeformationDataLakeSettings } from "./.gen/providers/aws/lakeformation-data-lake-settings";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    const current = new DataAwsCallerIdentity(this, "current", {});
    const dataAwsIamSessionContextCurrent = new DataAwsIamSessionContext(
      this,
      "current_1",
      {
        arn: Token.asString(current.arn),
      }
    );
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    dataAwsIamSessionContextCurrent.overrideLogicalId("current");
    new LakeformationDataLakeSettings(this, "test", {
      admins: [Token.asString(dataAwsIamSessionContextCurrent.issuerArn)],
    });
  }
}

```

To remove existing `IAMAllowedPrincipals` permissions, use the [AWS Lake Formation Console](https://console.aws.amazon.com/lakeformation/) or [AWS CLI](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/lakeformation/batch-revoke-permissions.html).

`IAMAllowedPrincipals` is a hook to maintain backwards compatibility with AWS Glue. `IAMAllowedPrincipals` is a pseudo-entity group that acts like a Lake Formation principal. The group includes any IAM users and roles that are allowed access to your Data Catalog resources by your IAM policies.

This is Lake Formation's default behavior:

* Lake Formation grants `Super` permission to `IAMAllowedPrincipals` on all existing AWS Glue Data Catalog resources.
* Lake Formation enables "Use only IAM access control" for new Data Catalog resources.

For more details, see [Changing the Default Security Settings for Your Data Lake](https://docs.aws.amazon.com/lake-formation/latest/dg/change-settings.html).

### Problem Using `IAMAllowedPrincipals`

AWS does not support combining `IAMAllowedPrincipals` permissions and non-`IAMAllowedPrincipals` permissions. Doing so results in unexpected permissions and behaviors. For example, this configuration grants a user `SELECT` on a column in a table.

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { GlueCatalogDatabase } from "./.gen/providers/aws/glue-catalog-database";
import { GlueCatalogTable } from "./.gen/providers/aws/glue-catalog-table";
import { LakeformationPermissions } from "./.gen/providers/aws/lakeformation-permissions";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new GlueCatalogDatabase(this, "example", {
      name: "sadabate",
    });
    const awsGlueCatalogTableExample = new GlueCatalogTable(this, "example_1", {
      databaseName: test.name,
      name: "abelt",
      storageDescriptor: {
        columns: [
          {
            name: "event",
            type: "string",
          },
        ],
      },
    });
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    awsGlueCatalogTableExample.overrideLogicalId("example");
    const awsLakeformationPermissionsExample = new LakeformationPermissions(
      this,
      "example_2",
      {
        permissions: ["SELECT"],
        principal: "arn:aws:iam:us-east-1:123456789012:user/SanHolo",
        tableWithColumns: {
          columnNames: ["event"],
          databaseName: Token.asString(awsGlueCatalogTableExample.databaseName),
          name: Token.asString(awsGlueCatalogTableExample.name),
        },
      }
    );
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    awsLakeformationPermissionsExample.overrideLogicalId("example");
  }
}

```

The resulting permissions depend on whether the table had `IAMAllowedPrincipals` (IAP) permissions or not.

| Result With IAP | Result Without IAP |
| ---- | ---- |
| `SELECT` column wildcard (i.e., all columns) | `SELECT` on `"event"` (as expected) |

## `ALLIAMPrincipals` group

AllIAMPrincipals is a pseudo-entity group that acts like a Lake Formation principal. The group includes all IAMs in the account that is defined.

resource "aws_lakeformation_permissions" "example" {
  permissions = ["SELECT"]
  principal   = "123456789012:IAMPrincipals"

  table_with_columns {
    database_name = aws_glue_catalog_table.example.database_name
    name          = aws_glue_catalog_table.example.name
    column_names  = ["event"]
  }
}

## Using Lake Formation Permissions

Lake Formation grants implicit permissions to data lake administrators, database creators, and table creators. These implicit permissions cannot be revoked _per se_. If this resource reads implicit permissions, it will attempt to revoke them, which causes an error when the resource is destroyed.

There are two ways to avoid these errors. First, and the way we recommend, is to avoid using this resource with principals that have implicit permissions. A second, error-prone option, is to grant explicit permissions (and `permissionsWithGrantOption`) to "overwrite" a principal's implicit permissions, which you can then revoke with this resource. For more information, see [Implicit Lake Formation Permissions](https://docs.aws.amazon.com/lake-formation/latest/dg/implicit-permissions.html).

If the `principal` is also a data lake administrator, AWS grants implicit permissions that can cause errors using this resource. For example, AWS implicitly grants a `principal`/administrator `permissions` and `permissionsWithGrantOption` of `ALL`, `ALTER`, `DELETE`, `DESCRIBE`, `DROP`, `INSERT`, and `SELECT` on a table. If you use this resource to explicitly grant the `principal`/administrator `permissions` but _not_ `permissionsWithGrantOption` of `ALL`, `ALTER`, `DELETE`, `DESCRIBE`, `DROP`, `INSERT`, and `SELECT` on the table, this resource will read the implicit `permissionsWithGrantOption` and attempt to revoke them when the resource is destroyed. Doing so will cause an `InvalidInputException: No permissions revoked` error because you cannot revoke implicit permissions _per se_. To workaround this problem, explicitly grant the `principal`/administrator `permissions` _and_ `permissionsWithGrantOption`, which can then be revoked. Similarly, granting a `principal`/administrator permissions on a table with columns and providing `columnNames`, will result in a `InvalidInputException: Permissions modification is invalid` error because you are narrowing the implicit permissions. Instead, set `wildcard` to `true` and remove the `columnNames`.

## Example Usage

### Grant Permissions For A Lake Formation S3 Resource

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { LakeformationPermissions } from "./.gen/providers/aws/lakeformation-permissions";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new LakeformationPermissions(this, "example", {
      dataLocation: {
        arn: Token.asString(awsLakeformationResourceExample.arn),
      },
      permissions: ["DATA_LOCATION_ACCESS"],
      principal: workflowRole.arn,
    });
  }
}

```

### Grant Permissions For A Glue Catalog Database

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { Token, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { LakeformationPermissions } from "./.gen/providers/aws/lakeformation-permissions";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new LakeformationPermissions(this, "example", {
      database: {
        catalogId: "110376042874",
        name: Token.asString(awsGlueCatalogDatabaseExample.name),
      },
      permissions: ["CREATE_TABLE", "ALTER", "DROP"],
      principal: workflowRole.arn,
    });
  }
}

```

### Grant Permissions Using Tag-Based Access Control

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { LakeformationPermissions } from "./.gen/providers/aws/lakeformation-permissions";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new LakeformationPermissions(this, "test", {
      lfTagPolicy: {
        expression: [
          {
            key: "Team",
            values: ["Sales"],
          },
          {
            key: "Environment",
            values: ["Dev", "Production"],
          },
        ],
        resourceType: "DATABASE",
      },
      permissions: ["CREATE_TABLE", "ALTER", "DROP"],
      principal: salesRole.arn,
    });
  }
}

```

## Argument Reference

The following arguments are required:

* `permissions` - (Required) List of permissions granted to the principal. Valid values may include `ALL`, `ALTER`, `ASSOCIATE`, `CREATE_DATABASE`, `CREATE_TABLE`, `DATA_LOCATION_ACCESS`, `DELETE`, `DESCRIBE`, `DROP`, `INSERT`, and `SELECT`. For details on each permission, see [Lake Formation Permissions Reference](https://docs.aws.amazon.com/lake-formation/latest/dg/lf-permissions-reference.html).
* `principal` - (Required) Principal to be granted the permissions on the resource. Supported principals include `IAM_ALLOWED_PRINCIPALS` (see [Default Behavior and `IAMAllowedPrincipals`](#default-behavior-and-iamallowedprincipals) above), IAM roles, users, groups, Federated Users, SAML groups and users, QuickSight groups, OUs, and organizations as well as AWS account IDs for cross-account permissions. For more information, see [Lake Formation Permissions Reference](https://docs.aws.amazon.com/lake-formation/latest/dg/lf-permissions-reference.html).

~> **NOTE:** We highly recommend that the `principal` _NOT_ be a Lake Formation administrator (granted using `aws_lakeformation_data_lake_settings`). The entity (e.g., IAM role) running Terraform will most likely need to be a Lake Formation administrator. As such, the entity will have implicit permissions and does not need permissions granted through this resource.

One of the following is required:

* `catalogResource` - (Optional) Whether the permissions are to be granted for the Data Catalog. Defaults to `false`.
* `dataCellsFilter` - (Optional) Configuration block for a data cells filter resource. Detailed below.
* `dataLocation` - (Optional) Configuration block for a data location resource. Detailed below.
* `database` - (Optional) Configuration block for a database resource. Detailed below.
* `lfTag` - (Optional) Configuration block for an LF-tag resource. Detailed below.
* `lfTagPolicy` - (Optional) Configuration block for an LF-tag policy resource. Detailed below.
* `table` - (Optional) Configuration block for a table resource. Detailed below.
* `tableWithColumns` - (Optional) Configuration block for a table with columns resource. Detailed below.

The following arguments are optional:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `catalogId` - (Optional) Identifier for the Data Catalog. By default, the account ID. The Data Catalog is the persistent metadata store. It contains database definitions, table definitions, and other control information to manage your Lake Formation environment.
* `permissionsWithGrantOption` - (Optional) Subset of `permissions` which the principal can pass.

### data_cells_filter

* `databaseName` - (Required) The name of the database.
* `name` - (Required) The name of the data cells filter.
* `tableCatalogId` - (Required) The ID of the Data Catalog.
* `tableName` - (Required) The name of the table.

### data_location

The following argument is required:

* `arn` - (Required) Amazon Resource Name (ARN) that uniquely identifies the data location resource.

The following argument is optional:

* `catalogId` - (Optional) Identifier for the Data Catalog where the location is registered with Lake Formation. By default, it is the account ID of the caller.

### database

The following argument is required:

* `name` - (Required) Name of the database resource. Unique to the Data Catalog.

The following argument is optional:

* `catalogId` - (Optional) Identifier for the Data Catalog. By default, it is the account ID of the caller.

### lf_tag

The following arguments are required:

* `key` - (Required) The key-name for the tag.
* `values` - (Required) A list of possible values an attribute can take.

The following argument is optional:

* `catalogId` - (Optional) Identifier for the Data Catalog. By default, it is the account ID of the caller.

### lf_tag_policy

The following arguments are required:

* `resourceType` - (Required) The resource type for which the tag policy applies. Valid values are `DATABASE` and `TABLE`.
* `expression` - (Required) A list of tag conditions that apply to the resource's tag policy. Configuration block for tag conditions that apply to the policy. See [`expression`](#expression) below.

The following argument is optional:

* `catalogId` - (Optional) Identifier for the Data Catalog. By default, it is the account ID of the caller.

#### expression

* `key` - (Required) The key-name of an LF-Tag.
* `values` - (Required) A list of possible values of an LF-Tag.

### table

The following argument is required:

* `databaseName` - (Required) Name of the database for the table. Unique to a Data Catalog.
* `name` - (Required, at least one of `name` or `wildcard`) Name of the table.
* `wildcard` - (Required, at least one of `name` or `wildcard`) Whether to use a wildcard representing every table under a database. Defaults to `false`.

The following arguments are optional:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `catalogId` - (Optional) Identifier for the Data Catalog. By default, it is the account ID of the caller.

### table_with_columns

The following arguments are required:

* `columnNames` - (Required, at least one of `columnNames` or `wildcard`) Set of column names for the table.
* `databaseName` - (Required) Name of the database for the table with columns resource. Unique to the Data Catalog.
* `name` - (Required) Name of the table resource.
* `wildcard` - (Required, at least one of `columnNames` or `wildcard`) Whether to use a column wildcard. If `excludedColumnNames` is included, `wildcard` must be set to `true` to avoid Terraform reporting a difference.

The following arguments are optional:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `catalogId` - (Optional) Identifier for the Data Catalog. By default, it is the account ID of the caller.
* `excludedColumnNames` - (Optional) Set of column names for the table to exclude. If `excludedColumnNames` is included, `wildcard` must be set to `true` to avoid Terraform reporting a difference.

## Attribute Reference

This resource exports no additional attributes.

<!-- cache-key: cdktf-0.20.8 input-2c405703dee16bf8c7ac2afec5d33511359006715bb0227e7fbad5c59234beaf -->