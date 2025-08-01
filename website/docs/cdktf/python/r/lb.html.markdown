---
subcategory: "ELB (Elastic Load Balancing)"
layout: "aws"
page_title: "AWS: aws_lb"
description: |-
  Provides a Load Balancer resource.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_lb

Provides a Load Balancer resource.

~> **Note:** `aws_alb` is known as `aws_lb`. The functionality is identical.

## Example Usage

### Application Load Balancer

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.lb import Lb
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        Lb(self, "test",
            access_logs=LbAccessLogs(
                bucket=lb_logs.id,
                enabled=True,
                prefix="test-lb"
            ),
            enable_deletion_protection=True,
            internal=False,
            load_balancer_type="application",
            name="test-lb-tf",
            security_groups=[lb_sg.id],
            subnets=Token.as_list("${[ for subnet in ${" + public.fqn + "} : subnet.id]}"),
            tags={
                "Environment": "production"
            }
        )
```

### Network Load Balancer

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.lb import Lb
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        Lb(self, "test",
            enable_deletion_protection=True,
            internal=False,
            load_balancer_type="network",
            name="test-lb-tf",
            subnets=Token.as_list("${[ for subnet in ${" + public.fqn + "} : subnet.id]}"),
            tags={
                "Environment": "production"
            }
        )
```

### Specifying Elastic IPs

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.lb import Lb
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        Lb(self, "example",
            load_balancer_type="network",
            name="example",
            subnet_mapping=[LbSubnetMapping(
                allocation_id=example1.id,
                subnet_id=Token.as_string(aws_subnet_example1.id)
            ), LbSubnetMapping(
                allocation_id=example2.id,
                subnet_id=Token.as_string(aws_subnet_example2.id)
            )
            ]
        )
```

### Specifying private IP addresses for an internal-facing load balancer

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.lb import Lb
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        Lb(self, "example",
            load_balancer_type="network",
            name="example",
            subnet_mapping=[LbSubnetMapping(
                private_ipv4_address="10.0.1.15",
                subnet_id=example1.id
            ), LbSubnetMapping(
                private_ipv4_address="10.0.2.15",
                subnet_id=example2.id
            )
            ]
        )
```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `access_logs` - (Optional) Access Logs block. See below.
* `connection_logs` - (Optional) Connection Logs block. See below. Only valid for Load Balancers of type `application`.
* `client_keep_alive` - (Optional) Client keep alive value in seconds. The valid range is 60-604800 seconds. The default is 3600 seconds.
* `customer_owned_ipv4_pool` - (Optional) ID of the customer owned ipv4 pool to use for this load balancer.
* `desync_mitigation_mode` - (Optional) How the load balancer handles requests that might pose a security risk to an application due to HTTP desync. Valid values are `monitor`, `defensive` (default), `strictest`.
* `dns_record_client_routing_policy` - (Optional) How traffic is distributed among the load balancer Availability Zones. Possible values are `any_availability_zone` (default), `availability_zone_affinity`, or `partial_availability_zone_affinity`. See   [Availability Zone DNS affinity](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/network-load-balancers.html#zonal-dns-affinity) for additional details. Only valid for `network` type load balancers.
* `drop_invalid_header_fields` - (Optional) Whether HTTP headers with header fields that are not valid are removed by the load balancer (true) or routed to targets (false). The default is false. Elastic Load Balancing requires that message header names contain only alphanumeric characters and hyphens. Only valid for Load Balancers of type `application`.
* `enable_cross_zone_load_balancing` - (Optional) If true, cross-zone load balancing of the load balancer will be enabled. For `network` and `gateway` type load balancers, this feature is disabled by default (`false`). For `application` load balancer this feature is always enabled (`true`) and cannot be disabled. Defaults to `false`.
* `enable_deletion_protection` - (Optional) If true, deletion of the load balancer will be disabled via the AWS API. This will prevent Terraform from deleting the load balancer. Defaults to `false`.
* `enable_http2` - (Optional) Whether HTTP/2 is enabled in `application` load balancers. Defaults to `true`.
* `enable_tls_version_and_cipher_suite_headers` - (Optional) Whether the two headers (`x-amzn-tls-version` and `x-amzn-tls-cipher-suite`), which contain information about the negotiated TLS version and cipher suite, are added to the client request before sending it to the target. Only valid for Load Balancers of type `application`. Defaults to `false`
* `enable_xff_client_port` - (Optional) Whether the X-Forwarded-For header should preserve the source port that the client used to connect to the load balancer in `application` load balancers. Defaults to `false`.
* `enable_waf_fail_open` - (Optional) Whether to allow a WAF-enabled load balancer to route requests to targets if it is unable to forward the request to AWS WAF. Defaults to `false`.
* `enable_zonal_shift` - (Optional) Whether zonal shift is enabled. Defaults to `false`.
* `enforce_security_group_inbound_rules_on_private_link_traffic` - (Optional) Whether inbound security group rules are enforced for traffic originating from a PrivateLink. Only valid for Load Balancers of type `network`. The possible values are `on` and `off`.
* `idle_timeout` - (Optional) Time in seconds that the connection is allowed to be idle. Only valid for Load Balancers of type `application`. Default: 60.
* `internal` - (Optional) If true, the LB will be internal. Defaults to `false`.
* `ip_address_type` - (Optional) Type of IP addresses used by the subnets for your load balancer. The possible values depend upon the load balancer type: `ipv4` (all load balancer types), `dualstack` (all load balancer types), and `dualstack-without-public-ipv4` (type `application` only).
* `ipam_pools` (Optional). The IPAM pools to use with the load balancer.  Only valid for Load Balancers of type `application`. See [ipam_pools](#ipam_pools) for more information.
* `load_balancer_type` - (Optional) Type of load balancer to create. Possible values are `application`, `gateway`, or `network`. The default value is `application`.
* `minimum_load_balancer_capacity` - (Optional) Minimum capacity for a load balancer. Only valid for Load Balancers of type `application` or `network`.
* `name` - (Optional) Name of the LB. This name must be unique within your AWS account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen. If not specified, Terraform will autogenerate a name beginning with `tf-lb`.
* `name_prefix` - (Optional) Creates a unique name beginning with the specified prefix. Conflicts with `name`.
* `security_groups` - (Optional) List of security group IDs to assign to the LB. Only valid for Load Balancers of type `application` or `network`. For load balancers of type `network` security groups cannot be added if none are currently present, and cannot all be removed once added. If either of these conditions are met, this will force a recreation of the resource.
* `preserve_host_header` - (Optional) Whether the Application Load Balancer should preserve the Host header in the HTTP request and send it to the target without any change. Defaults to `false`.
* `subnet_mapping` - (Optional) Subnet mapping block. See below. For Load Balancers of type `network` subnet mappings can only be added.
* `subnets` - (Optional) List of subnet IDs to attach to the LB. For Load Balancers of type `network` subnets can only be added (see [Availability Zones](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/network-load-balancers.html#availability-zones)), deleting a subnet for load balancers of type `network` will force a recreation of the resource.
* `tags` - (Optional) Map of tags to assign to the resource. If configured with a provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.
* `xff_header_processing_mode` - (Optional) Determines how the load balancer modifies the `X-Forwarded-For` header in the HTTP request before sending the request to the target. The possible values are `append`, `preserve`, and `remove`. Only valid for Load Balancers of type `application`. The default is `append`.

~> **NOTE:** Please note that internal LBs can only use `ipv4` as the `ip_address_type`. You can only change to `dualstack` `ip_address_type` if the selected subnets are IPv6 enabled.

~> **NOTE:** Please note that one of either `subnets` or `subnet_mapping` is required.

### access_logs

* `bucket` - (Required) S3 bucket name to store the logs in.
* `enabled` - (Optional) Boolean to enable / disable `access_logs`. Defaults to `false`, even when `bucket` is specified.
* `prefix` - (Optional) S3 bucket prefix. Logs are stored in the root if not configured.

### connection_logs

* `bucket` - (Required) S3 bucket name to store the logs in.
* `enabled` - (Optional) Boolean to enable / disable `connection_logs`. Defaults to `false`, even when `bucket` is specified.
* `prefix` - (Optional) S3 bucket prefix. Logs are stored in the root if not configured.

### ipam_pools

* `ipv4_ipam_pool_id` - (Required) The ID of the IPv4 IPAM pool.

### minimum_load_balancer_capacity

* `capacity_units` - (Required) The number of capacity units.

### subnet_mapping

* `subnet_id` - (Required) ID of the subnet of which to attach to the load balancer. You can specify only one subnet per Availability Zone.
* `allocation_id` - (Optional) Allocation ID of the Elastic IP address for an internet-facing load balancer.
* `ipv6_address` - (Optional) IPv6 address. You associate IPv6 CIDR blocks with your VPC and choose the subnets where you launch both internet-facing and internal Application Load Balancers or Network Load Balancers.
* `private_ipv4_address` - (Optional) Private IPv4 address for an internal load balancer.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - ARN of the load balancer.
* `arn_suffix` - ARN suffix for use with CloudWatch Metrics.
* `dns_name` - DNS name of the load balancer.
* `subnet_mapping.*.outpost_id` - ID of the Outpost containing the load balancer.
* `tags_all` - Map of tags assigned to the resource, including those inherited from the provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block).
* `zone_id` - Canonical hosted zone ID of the load balancer (to be used in a Route 53 Alias record).

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

- `create` - (Default `10m`)
- `update` - (Default `10m`)
- `delete` - (Default `10m`)

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import LBs using their ARN. For example:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.lb import Lb
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        Lb.generate_config_for_import(self, "bar", "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188")
```

Using `terraform import`, import LBs using their ARN. For example:

```console
% terraform import aws_lb.bar arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188
```

<!-- cache-key: cdktf-0.20.8 input-b3dc733a11ff63c9438ae99e9ea31b6a7ac6d77ac6ea9f33f210128ccff80986 -->