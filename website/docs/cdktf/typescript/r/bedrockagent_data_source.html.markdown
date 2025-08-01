---
subcategory: "Bedrock Agents"
layout: "aws"
page_title: "AWS: aws_bedrockagent_data_source"
description: |-
  Terraform resource for managing an AWS Agents for Amazon Bedrock Data Source.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_bedrockagent_data_source

Terraform resource for managing an AWS Agents for Amazon Bedrock Data Source.

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
import { BedrockagentDataSource } from "./.gen/providers/aws/bedrockagent-data-source";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    new BedrockagentDataSource(this, "example", {
      dataSourceConfiguration: [
        {
          s3Configuration: [
            {
              bucketArn: "arn:aws:s3:::example-bucket",
            },
          ],
          type: "S3",
        },
      ],
      knowledgeBaseId: "EMDPPAYPZI",
      name: "example",
    });
  }
}

```

## Argument Reference

The following arguments are required:

* `dataSourceConfiguration` - (Required) Details about how the data source is stored. See [`dataSourceConfiguration` block](#data_source_configuration-block) for details.
* `knowledgeBaseId` - (Required) Unique identifier of the knowledge base to which the data source belongs.
* `name` - (Required, Forces new resource) Name of the data source.

The following arguments are optional:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `dataDeletionPolicy` - (Optional) Data deletion policy for a data source. Valid values: `RETAIN`, `DELETE`.
* `description` - (Optional) Description of the data source.
* `serverSideEncryptionConfiguration` - (Optional) Details about the configuration of the server-side encryption. See [`serverSideEncryptionConfiguration` block](#server_side_encryption_configuration-block) for details.
* `vectorIngestionConfiguration` - (Optional, Forces new resource) Details about the configuration of the server-side encryption. See [`vectorIngestionConfiguration` block](#vector_ingestion_configuration-block) for details.

### `dataSourceConfiguration` block

The `dataSourceConfiguration` configuration block supports the following arguments:

* `type` - (Required) Type of storage for the data source. Valid values: `S3`, `WEB`, `CONFLUENCE`, `SALESFORCE`, `SHAREPOINT`, `CUSTOM`, `REDSHIFT_METADATA`.
* `confluenceConfiguration` - (Optional) Details about the configuration of the Confluence data source. See [`confluence_data_source_configuration` block](#confluence_data_source_configuration-block) for details.
* `s3Configuration` - (Optional) Details about the configuration of the S3 object containing the data source. See [`s3_data_source_configuration` block](#s3_data_source_configuration-block) for details.
* `salesforceConfiguration` - (Optional) Details about the configuration of the Salesforce data source. See [`salesforce_data_source_configuration` block](#salesforce_data_source_configuration-block) for details.
* `sharePointConfiguration` - (Optional) Details about the configuration of the SharePoint data source. See [`share_point_data_source_configuration` block](#share_point_data_source_configuration-block) for details.
* `webConfiguration` - (Optional) Details about the configuration of the web data source. See [`web_data_source_configuration` block](#web_data_source_configuration-block) for details.

### `confluence_data_source_configuration` block

The `confluence_data_source_configuration` configuration block supports the following arguments:

* `sourceConfiguration` - (Required) The endpoint information to connect to your Confluence data source. See [`sourceConfiguration` block](#confluence-source_configuration-block) for details.
* `crawlerConfiguration` - (Optional) Configuration for Confluence content. See [`crawlerConfiguration` block](#crawler_configuration-block) for details.

For more details, see the [Amazon BedrockAgent Confluence documentation][1].

### Confluence `sourceConfiguration` block

The `sourceConfiguration` configuration block supports the following arguments:

* `authType` - (Required) The supported authentication type to authenticate and connect to your Confluence instance. Valid values: `BASIC`, `OAUTH2_CLIENT_CREDENTIALS`.
* `credentialsSecretArn` - (Required) The Amazon Resource Name of an AWS Secrets Manager secret that stores your authentication credentials for your Confluence instance URL. For more information on the key-value pairs that must be included in your secret, depending on your authentication type, see Confluence connection configuration. Pattern: ^arn:aws(|-cn|-us-gov):secretsmanager:[a-z0-9-]{1,20}:([0-9]{12}|):secret:[a-zA-Z0-9!/_+=.@-]{1,512}$.
* `hostType` - (Required) The supported host type, whether online/cloud or server/on-premises. Valid values: `SAAS`.
* `hostUrl` - (Required) The Confluence host URL or instance URL. Pattern: `^https://[A-Za-z0-9][^\s]*$`.

### `s3_data_source_configuration` block

The `s3_data_source_configuration` configuration block supports the following arguments:

* `bucketArn` - (Required) ARN of the bucket that contains the data source.
* `bucketOwnerAccountId` - (Optional) Bucket account owner ID for the S3 bucket.
* `inclusionPrefixes` - (Optional) List of S3 prefixes that define the object containing the data sources. For more information, see [Organizing objects using prefixes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-prefixes.html).

### `salesforce_data_source_configuration` block

The `salesforce_data_source_configuration` configuration block supports the following arguments:

* `sourceConfiguration` - (Required) The endpoint information to connect to your Salesforce data source. See [`sourceConfiguration` block](#salesforce-source_configuration-block) for details.
* `crawlerConfiguration` - (Optional) Configuration for Salesforce content. See [`crawlerConfiguration` block](#crawler_configuration-block) for details.

For more details, see the [Amazon BedrockAgent Salesforce documentation][2].

### Salesforce `sourceConfiguration` block

The `sourceConfiguration` configuration block supports the following arguments:

* `authType` - (Required) The supported authentication type to authenticate and connect to your Salesforce instance. Valid values: OAUTH2_CLIENT_CREDENTIALS.
* `credentialsSecretArn` - (Required) The Amazon Resource Name of an AWS Secrets Manager secret that stores your authentication credentials for your Salesforce instance URL. For more information on the key-value pairs that must be included in your secret, depending on your authentication type, see Salesforce connection configuration. Pattern: ^arn:aws(|-cn|-us-gov):secretsmanager:[a-z0-9-]{1,20}:([0-9]{12}|):secret:[a-zA-Z0-9!/_+=.@-]{1,512}$.
* `hostUrl` - (Required) The Salesforce host URL or instance URL. Pattern: `^https://[A-Za-z0-9][^\s]*$`.

### `crawlerConfiguration` block

The `crawlerConfiguration` configuration block supports the following arguments:

* `filterConfiguration` - (Optional) The Salesforce standard object configuration. See [`filterConfiguration` block](#filter_configuration-block) for details.

### `filterConfiguration` block

The `filterConfiguration` configuration block supports the following arguments:

* `type` - (Required) The type of filtering that you want to apply to certain objects or content of the data source. For example, the PATTERN type is regular expression patterns you can apply to filter your content.
* `patternObjectFilter` - (Optional) The configuration of filtering certain objects or content types of the data source. See [`patternObjectFilter` block](#pattern_object_filter-block) for details.

### `patternObjectFilter` block

The `patternObjectFilter` configuration block supports the following arguments:

* `filters` - (Required) The configuration of specific filters applied to your data source content. Minimum of 1 filter and maximum of 25 filters.

Each filter object should contain the following configuration:

* `objectType` - (Required) The supported object type or content type of the data source.
* `exclusionFilters` - (Optional) A list of one or more exclusion regular expression patterns to exclude certain object types that adhere to the pattern.
* `inclusionFilters` - (Optional) A list of one or more inclusion regular expression patterns to include certain object types that adhere to the pattern.

### `share_point_data_source_configuration` block

The `share_point_data_source_configuration` configuration block supports the following arguments:

* `sourceConfiguration` - (Required) The endpoint information to connect to your SharePoint data source. See [`sourceConfiguration` block](#sharepoint-source_configuration-block) for details.
* `crawlerConfiguration` - (Optional) Configuration for SharePoint content. See [`crawlerConfiguration` block](#crawler_configuration-block) for details.

For more details, see the [Amazon BedrockAgent SharePoint documentation][3].

### SharePoint `sourceConfiguration` block

The `sourceConfiguration` configuration block supports the following arguments:

* `authType` - (Required) The supported authentication type to authenticate and connect to your SharePoint site. Valid values: `OAUTH2_CLIENT_CREDENTIALS`, `OAUTH2_SHAREPOINT_APP_ONLY_CLIENT_CREDENTIALS`.
* `credentialsSecretArn` - (Required) The Amazon Resource Name of an AWS Secrets Manager secret that stores your authentication credentials for your SharePoint site. For more information on the key-value pairs that must be included in your secret, depending on your authentication type, see SharePoint connection configuration. Pattern: ^arn:aws(|-cn|-us-gov):secretsmanager:[a-z0-9-]{1,20}:([0-9]{12}|):secret:[a-zA-Z0-9!/_+=.@-]{1,512}$.
* `domain` - (Required) The domain of your SharePoint instance or site URL/URLs.
* `hostType` - (Required) The supported host type, whether online/cloud or server/on-premises. Valid values: `ONLINE`.
* `siteUrls` - (Required) A list of one or more SharePoint site URLs.
* `tenantId` - (Optional) The identifier of your Microsoft 365 tenant.

### `web_data_source_configuration` block

The `web_data_source_configuration` configuration block supports the following arguments:

* `sourceConfiguration` - (Required) Endpoint information to connect to your web data source. See [`sourceConfiguration` block](#web-source_configuration-block) for details.
* `crawlerConfiguration` - (Optional) Configuration for web content. See [`crawlerConfiguration` block](#web-crawler_configuration-block) for details.

### Web `sourceConfiguration` block

The `sourceConfiguration` configuration block supports the following arguments:

* `urlConfiguration` - (Required) The URL configuration of your web data source. See [`urlConfiguration` block](#url_configuration-block) for details.

### `urlConfiguration` block

The `urlConfiguration` configuration block supports the following arguments:

* `seedUrls` - (Optional) List of one or more seed URLs to crawl. See [`seedUrls` block](#seed_urls-block) for details.

### `seedUrls` block

The `seedUrls` configuration block supports the following arguments:

* `url` - (Optional) Seed or starting point URL. Must match the pattern `^https?://[A-Za-z0-9][^\s]*$`.

### Web `crawlerConfiguration` block

The `crawlerConfiguration` configuration block supports the following arguments:

* `exclusionFilters` - (Optional) List of one or more exclusion regular expression patterns to exclude certain object types that adhere to the pattern.
* `inclusionFilters` - (Optional) List of one or more inclusion regular expression patterns to include certain object types that adhere to the pattern.
* `scope` - (Optional) Scope of what is crawled for your URLs.
* `userAgent` - (Optional) String used for identifying the crawler or a bot when it accesses a web server. Default value is `bedrockbot_UUID`.
* `crawlerLimits` - (Optional) Configuration of crawl limits for the web URLs. See [`crawlerLimits` block](#crawler_limits-block) for details.

### `crawlerLimits` block

The `crawlerLimits` configuration block supports the following arguments:

* `maxPages` - (Optional) Max number of web pages crawled from your source URLs, up to 25,000 pages.
* `rateLimit` - (Optional) Max rate at which pages are crawled, up to 300 per minute per host.

### `serverSideEncryptionConfiguration` block

The `serverSideEncryptionConfiguration` configuration block supports the following arguments:

* `kmsKeyArn` - (Optional) ARN of the AWS KMS key used to encrypt the resource.

### `vectorIngestionConfiguration` block

The `vectorIngestionConfiguration` configuration block supports the following arguments:

* `chunkingConfiguration` - (Optional, Forces new resource) Details about how to chunk the documents in the data source. A chunk refers to an excerpt from a data source that is returned when the knowledge base that it belongs to is queried. See [`chunkingConfiguration` block](#chunking_configuration-block) for details.
* `customTransformationConfiguration`- (Optional, Forces new resource) Configuration for custom transformation of data source documents.
* `parsingConfiguration` - (Optional, Forces new resource) Configuration for custom parsing of data source documents. See [`parsingConfiguration` block](#parsing_configuration-block) for details.

### `chunkingConfiguration` block

 The `chunkingConfiguration` configuration block supports the following arguments:

* `chunkingStrategy` - (Required, Forces new resource) Option for chunking your source data, either in fixed-sized chunks or as one chunk. Valid values: `FIXED_SIZE`, `HIERARCHICAL`, `SEMANTIC`, `NONE`.
* `fixedSizeChunkingConfiguration` - (Optional, Forces new resource) Configurations for when you choose fixed-size chunking. Requires chunking_strategy as `FIXED_SIZE`. See [`fixedSizeChunkingConfiguration`](#fixed_size_chunking_configuration-block) for details.
* `hierarchicalChunkingConfiguration` - (Optional, Forces new resource) Configurations for when you choose hierarchical chunking. Requires chunking_strategy as `HIERARCHICAL`. See [`hierarchicalChunkingConfiguration`](#hierarchical_chunking_configuration-block) for details.
* `semanticChunkingConfiguration` - (Optional, Forces new resource) Configurations for when you choose semantic chunking. Requires chunking_strategy as `SEMANTIC`. See [`semanticChunkingConfiguration`](#semantic_chunking_configuration-block) for details.

### `fixedSizeChunkingConfiguration` block

The `fixedSizeChunkingConfiguration` block supports the following arguments:

* `maxTokens` - (Required, Forces new resource) Maximum number of tokens to include in a chunk.
* `overlapPercentage` - (Optional, Forces new resource) Percentage of overlap between adjacent chunks of a data source.

### `hierarchicalChunkingConfiguration` block

The `hierarchicalChunkingConfiguration` block supports the following arguments:

* `levelConfiguration` - (Required, Forces new resource) Maximum number of tokens to include in a chunk. Must contain two `level_configurations`. See [`level_configurations`](#level_configuration-block) for details.
* `overlapTokens` - (Required, Forces new resource) The number of tokens to repeat across chunks in the same layer.

### `levelConfiguration` block

The `levelConfiguration` block supports the following arguments:

* `maxTokens` - (Required) The maximum number of tokens that a chunk can contain in this layer.

### `semanticChunkingConfiguration` block

The `semanticChunkingConfiguration` block supports the following arguments:

* `breakpointPercentileThreshold` - (Required, Forces new resource) The dissimilarity threshold for splitting chunks.
* `bufferSize` - (Required, Forces new resource) The buffer size.
* `maxToken` - (Required, Forces new resource) The maximum number of tokens a chunk can contain.

### `customTransformationConfiguration` block

The `customTransformationConfiguration` block supports the following arguments:

* `intermediateStorage` - (Required, Forces new resource) The intermediate storage for custom transformation.
* `transformation` - (Required) A custom processing step for documents moving through the data source ingestion pipeline.

### `intermediateStorage` block

The `intermediateStorage` block supports the following arguments:

* `s3Location` - (Required, Forces new resource) Configuration block for intermedia S3 storage.

### `s3Location` block

The `s3Location` block supports the following arguments:

* `uri` - (Required, Forces new resource) S3 URI for intermediate storage.

### `transformation` block

The `transformation` block supports the following arguments:

* `stepToApply` - (Required, Forces new resource) When the service applies the transformation. Currently only `POST_CHUNKING` is supported.
* `transformationFunction` - (Required) The lambda function that processes documents.

### `transformationFunction` block

The `transformationFunction` block supports the following arguments:

* `transformationLambdaConfiguration` - (Required, Forces new resource) The configuration of the lambda function.

### `transformationLambdaConfiguration` block

The `transformationLambdaConfiguration` block supports the following arguments:

* `lambdaArn` - (Required, Forces new resource) The ARN of the lambda to use for custom transformation.

### `parsingConfiguration` block

The `parsingConfiguration` configuration block supports the following arguments:

* `parsingStrategy` - (Required) Currently only `BEDROCK_FOUNDATION_MODEL` is supported
* `bedrockFoundationModelConfiguration` - (Optional) Settings for a foundation model used to parse documents in a data source. See [`bedrockFoundationModelConfiguration` block](#bedrock_foundation_model_configuration-block) for details.

### `bedrockFoundationModelConfiguration` block

The `bedrockFoundationModelConfiguration` configuration block supports the following arguments:

* `modelArn` - (Required) The ARN of the model used to parse documents
* `parsingPrompt` - (Optional) Instructions for interpreting the contents of the document. See [`parsingPrompt` block](#parsing_prompt-block) for details.

### `parsingPrompt` block

The `parsingPrompt` configuration block supports the following arguments:

* `parsingPromptString` - (Required) Instructions for interpreting the contents of the document.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `dataSourceId` -  Unique identifier of the data source.
* `id` -  Identifier of the data source which consists of the data source ID and the knowledge base ID.

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

* `create` - (Default `30m`)
* `delete` - (Default `30m`)

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import Agents for Amazon Bedrock Data Source using the data source ID and the knowledge base ID. For example:

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { BedrockagentDataSource } from "./.gen/providers/aws/bedrockagent-data-source";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    BedrockagentDataSource.generateConfigForImport(
      this,
      "example",
      "GWCMFMQF6T,EMDPPAYPZI"
    );
  }
}

```

Using `terraform import`, import Agents for Amazon Bedrock Data Source using the data source ID and the knowledge base ID. For example:

```console
% terraform import aws_bedrockagent_data_source.example GWCMFMQF6T,EMDPPAYPZI
```

[1]: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_ConfluenceDataSourceConfiguration.html
[2]: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_SalesforceDataSourceConfiguration.html
[3]: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_SharePointDataSourceConfiguration.html
[4]: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_WebDataSourceConfiguration.html

<!-- cache-key: cdktf-0.20.8 input-6c5d65619f26f4664cb0988d2b1b6935663c952fb48ce89395b8908c00666e96 -->