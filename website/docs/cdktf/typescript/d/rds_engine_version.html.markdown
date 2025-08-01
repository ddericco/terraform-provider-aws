---
subcategory: "RDS (Relational Database)"
layout: "aws"
page_title: "AWS: aws_rds_engine_version"
description: |-
  Information about an RDS engine version.
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_rds_engine_version

Information about an RDS engine version.

## Example Usage

### Basic Usage

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsRdsEngineVersion } from "./.gen/providers/aws/data-aws-rds-engine-version";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new DataAwsRdsEngineVersion(this, "test", {
      engine: "mysql",
      preferredVersions: ["8.0.27", "8.0.26"],
    });
  }
}

```

### With `filter`

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsRdsEngineVersion } from "./.gen/providers/aws/data-aws-rds-engine-version";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new DataAwsRdsEngineVersion(this, "test", {
      engine: "aurora-postgresql",
      filter: [
        {
          name: "engine-mode",
          values: ["serverless"],
        },
      ],
      includeAll: true,
      version: "10.14",
    });
  }
}

```

## Argument Reference

The following arguments are required:

* `engine` - (Required) Database engine. Engine values include `aurora`, `aurora-mysql`, `aurora-postgresql`, `docdb`, `mariadb`, `mysql`, `neptune`, `oracle-ee`, `oracle-se`, `oracle-se1`, `oracle-se2`, `postgres`, `sqlserver-ee`, `sqlserver-ex`, `sqlserver-se`, and `sqlserver-web`.

The following arguments are optional:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `defaultOnly` - (Optional) Whether the engine version must be an AWS-defined default version. Some engines have multiple default versions, such as for each major version. Using `defaultOnly` may help avoid `multiple RDS engine versions` errors. See also `latest`.
* `filter` - (Optional) One or more name/value pairs to use in filtering versions. There are several valid keys; for a full reference, check out [describe-db-engine-versions in the AWS CLI reference](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/describe-db-engine-versions.html).
* `hasMajorTarget` - (Optional) Whether the engine version must have one or more major upgrade targets. Not including `hasMajorTarget` or setting it to `false` doesn't imply that there's no corresponding major upgrade target for the engine version.
* `hasMinorTarget` - (Optional) Whether the engine version must have one or more minor upgrade targets. Not including `hasMinorTarget` or setting it to `false` doesn't imply that there's no corresponding minor upgrade target for the engine version.
* `includeAll` - (Optional) Whether the engine version `status` can either be `deprecated` or `available`. When not set or set to `false`, the engine version `status` will always be `available`.
* `latest` - (Optional) Whether the engine version is the most recent version matching the other criteria. This is different from `defaultOnly` in important ways: "default" relies on AWS-defined defaults, the latest version isn't always the default, and AWS might have multiple default versions for an engine. As a result, `defaultOnly` might not prevent errors from `multiple RDS engine versions`, while `latest` will. (`latest` can be used with `defaultOnly`.) **Note:** The data source uses a best-effort approach at selecting the latest version. Due to the complexity of version identifiers across engines and incomplete version date information provided by AWS, using `latest` may not always result in the engine version being the actual latest version.
* `parameterGroupFamily` - (Optional) Name of a specific database parameter group family. Examples of parameter group families are `mysql8.0`, `mariadb10.4`, and `postgres12`.
* `preferredMajorTargets` - (Optional) Ordered list of preferred major version upgrade targets. The engine version will be the first match in the list unless the `latest` parameter is set to `true`. The engine version will be the default version if you don't include any criteria, such as `preferredMajorTargets`.
* `preferredUpgradeTargets` - (Optional) Ordered list of preferred version upgrade targets. The engine version will be the first match in this list unless the `latest` parameter is set to `true`. The engine version will be the default version if you don't include any criteria, such as `preferredUpgradeTargets`.
* `preferredVersions` - (Optional) Ordered list of preferred versions. The engine version will be the first match in this list unless the `latest` parameter is set to `true`. The engine version will be the default version if you don't include any criteria, such as `preferredVersions`.
* `version` - (Optional) Engine version. For example, `5.7.22`, `10.1.34`, or `12.3`. `version` can be a partial version identifier which can result in `multiple RDS engine versions` errors unless the `latest` parameter is set to `true`. The engine version will be the default version if you don't include any criteria, such as `version`. **NOTE:** In a future Terraform AWS provider version, `version` will only contain the version information you configure and not the complete version information that the data source gets from AWS. Instead, that version information will be available in the `versionActual` attribute.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `defaultCharacterSet` - Default character set for new instances of the engine version.
* `engineDescription` - Description of the engine.
* `exportableLogTypes` - Set of log types that the engine version has available for export to CloudWatch Logs.
* `status` - Status of the engine version, either `available` or `deprecated`.
* `supportedCharacterSets` - Set of character sets supported by th engine version.
* `supportedFeatureNames` - Set of features supported by the engine version.
* `supportedModes` - Set of supported engine version modes.
* `supportedTimezones` - Set of the time zones supported by the engine version.
* `supportsCertificateRotationWithoutRestart` - Whether the certificates can be rotated without restarting the Aurora instance.
* `supportsGlobalDatabases` - Whether you can use Aurora global databases with the engine version.
* `supportsIntegrations` - Whether the engine version supports integrations with other AWS services.
* `supportsLogExportsToCloudwatch` - Whether the engine version supports exporting the log types specified by `exportableLogTypes` to CloudWatch Logs.
* `supportsLocalWriteForwarding` - Whether the engine version supports local write forwarding or not.
* `supportsLimitlessDatabase` - Whether the engine version supports Aurora Limitless Database.
* `supportsParallelQuery` - Whether you can use Aurora parallel query with the engine version.
* `supportsReadReplica` - Whether the engine version supports read replicas.
* `validMajorTargets` - Set of versions that are valid major version upgrades for the engine version.
* `validMinorTargets` - Set of versions that are valid minor version upgrades for the engine version.
* `validUpgradeTargets` - Set of versions that are valid major or minor upgrades for the engine version.
* `versionActual` - Complete engine version.
* `versionDescription` - Description of the engine version.

<!-- cache-key: cdktf-0.20.8 input-b058d00a50498da6f75c0d50123bc1a7dcb6dfd555683625d54c3688c9a76d67 -->