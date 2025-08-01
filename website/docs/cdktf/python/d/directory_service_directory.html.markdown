---
subcategory: "Directory Service"
layout: "aws"
page_title: "AWS: aws_directory_service_directory"
description: |-
  AWS Directory Service Directory
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_directory_service_directory

Get attributes of AWS Directory Service directory (SimpleAD, Managed AD, AD Connector). It's especially useful to refer AWS Managed AD or on-premise AD in AD Connector configuration.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.data_aws_directory_service_directory import DataAwsDirectoryServiceDirectory
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        DataAwsDirectoryServiceDirectory(self, "example",
            directory_id=main.id
        )
```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `directory_id` - (Required) ID of the directory.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `type` - Directory type (`SimpleAD`, `ADConnector` or `MicrosoftAD`).
* `edition` - (for `MicrosoftAD`) Microsoft AD edition (`Standard` or `Enterprise`).
* `name` - Fully qualified name for the directory/connector.
* `password` - Password for the directory administrator or connector user.
* `size` - (for `SimpleAD` and `ADConnector`) Size of the directory/connector (`Small` or `Large`).
* `alias` - Alias for the directory/connector, such as `d-991708b282.awsapps.com`.
* `description` - Textual description for the directory/connector.
* `short_name` - Short name of the directory/connector, such as `CORP`.
* `enable_sso` - Directory/connector single-sign on status.
* `access_url` - Access URL for the directory/connector, such as http://alias.awsapps.com.
* `dns_ip_addresses` - List of IP addresses of the DNS servers for the directory/connector.
* `security_group_id` - ID of the security group created by the directory/connector.
* `tags` - A map of tags assigned to the directory/connector.

 `vpc_settings` (for `SimpleAD` and `MicrosoftAD`) is also exported with the following attributes:

* `subnet_ids` - Identifiers of the subnets for the directory servers (2 subnets in 2 different AZs).
* `vpc_id` - ID of the VPC that the directory is in.

`connect_settings` (for `ADConnector`) is also exported with the following attributes:

* `connect_ips` - IP addresses of the AD Connector servers.
* `customer_username` - Username corresponding to the password provided.
* `customer_dns_ips` - DNS IP addresses of the domain to connect to.
* `subnet_ids` - Identifiers of the subnets for the connector servers (2 subnets in 2 different AZs).
* `vpc_id` - ID of the VPC that the connector is in.

`radius_settings` is also exported with the following attributes:

* `authentication_protocol` - The protocol specified for your RADIUS endpoints.
* `display_label` - Display label.
* `radius_port` - Port that your RADIUS server is using for communications.
* `radius_retries` - Maximum number of times that communication with the RADIUS server is attempted.
* `radius_servers` - Set of strings that contains the fully qualified domain name (FQDN) or IP addresses of the RADIUS server endpoints, or the FQDN or IP addresses of your RADIUS server load balancer.
* `radius_timeout` - Amount of time, in seconds, to wait for the RADIUS server to respond.
* `use_same_username` - Not currently used.

<!-- cache-key: cdktf-0.20.8 input-9d2500770538a9038268faf84e026bd3c309468f69ba821c0684b89d59d4be0e -->