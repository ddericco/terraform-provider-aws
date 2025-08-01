---
subcategory: "ACM PCA (Certificate Manager Private Certificate Authority)"
layout: "aws"
page_title: "AWS: aws_acmpca_certificate_authority_certificate"
description: |-
  Associates a certificate with an AWS Certificate Manager Private Certificate Authority
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_acmpca_certificate_authority_certificate

Associates a certificate with an AWS Certificate Manager Private Certificate Authority (ACM PCA Certificate Authority). An ACM PCA Certificate Authority is unable to issue certificates until it has a certificate associated with it. A root level ACM PCA Certificate Authority is able to self-sign its own root certificate.

## Example Usage

### Self-Signed Root Certificate Authority Certificate

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.acmpca_certificate import AcmpcaCertificate
from imports.aws.acmpca_certificate_authority import AcmpcaCertificateAuthority
from imports.aws.acmpca_certificate_authority_certificate import AcmpcaCertificateAuthorityCertificate
from imports.aws.data_aws_partition import DataAwsPartition
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        example = AcmpcaCertificateAuthority(self, "example",
            certificate_authority_configuration=AcmpcaCertificateAuthorityCertificateAuthorityConfiguration(
                key_algorithm="RSA_4096",
                signing_algorithm="SHA512WITHRSA",
                subject=AcmpcaCertificateAuthorityCertificateAuthorityConfigurationSubject(
                    common_name="example.com"
                )
            ),
            type="ROOT"
        )
        current = DataAwsPartition(self, "current")
        aws_acmpca_certificate_example = AcmpcaCertificate(self, "example_2",
            certificate_authority_arn=example.arn,
            certificate_signing_request=example.certificate_signing_request,
            signing_algorithm="SHA512WITHRSA",
            template_arn="arn:${" + current.partition + "}:acm-pca:::template/RootCACertificate/V1",
            validity=AcmpcaCertificateValidity(
                type="YEARS",
                value=Token.as_string(1)
            )
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_acmpca_certificate_example.override_logical_id("example")
        aws_acmpca_certificate_authority_certificate_example =
        AcmpcaCertificateAuthorityCertificate(self, "example_3",
            certificate=Token.as_string(aws_acmpca_certificate_example.certificate),
            certificate_authority_arn=example.arn,
            certificate_chain=Token.as_string(aws_acmpca_certificate_example.certificate_chain)
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_acmpca_certificate_authority_certificate_example.override_logical_id("example")
```

### Certificate for Subordinate Certificate Authority

Note that the certificate for the subordinate certificate authority must be issued by the root certificate authority using a signing request from the subordinate certificate authority.

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import Token, TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.acmpca_certificate import AcmpcaCertificate
from imports.aws.acmpca_certificate_authority import AcmpcaCertificateAuthority
from imports.aws.acmpca_certificate_authority_certificate import AcmpcaCertificateAuthorityCertificate
from imports.aws.data_aws_partition import DataAwsPartition
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name, *, certificateAuthorityArn, certificateSigningRequest, signingAlgorithm, validity, certificateAuthorityConfiguration, certificate, certificateAuthorityArn1):
        super().__init__(scope, name)
        AcmpcaCertificate(self, "root",
            certificate_authority_arn=certificate_authority_arn,
            certificate_signing_request=certificate_signing_request,
            signing_algorithm=signing_algorithm,
            validity=validity
        )
        aws_acmpca_certificate_authority_root = AcmpcaCertificateAuthority(self, "root_1",
            certificate_authority_configuration=certificate_authority_configuration
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_acmpca_certificate_authority_root.override_logical_id("root")
        subordinate = AcmpcaCertificateAuthority(self, "subordinate",
            certificate_authority_configuration=AcmpcaCertificateAuthorityCertificateAuthorityConfiguration(
                key_algorithm="RSA_2048",
                signing_algorithm="SHA512WITHRSA",
                subject=AcmpcaCertificateAuthorityCertificateAuthorityConfigurationSubject(
                    common_name="sub.example.com"
                )
            ),
            type="SUBORDINATE"
        )
        aws_acmpca_certificate_authority_certificate_root =
        AcmpcaCertificateAuthorityCertificate(self, "root_3",
            certificate=certificate,
            certificate_authority_arn=certificate_authority_arn1
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_acmpca_certificate_authority_certificate_root.override_logical_id("root")
        current = DataAwsPartition(self, "current")
        aws_acmpca_certificate_subordinate = AcmpcaCertificate(self, "subordinate_5",
            certificate_authority_arn=Token.as_string(aws_acmpca_certificate_authority_root.arn),
            certificate_signing_request=subordinate.certificate_signing_request,
            signing_algorithm="SHA512WITHRSA",
            template_arn="arn:${" + current.partition + "}:acm-pca:::template/SubordinateCACertificate_PathLen0/V1",
            validity=AcmpcaCertificateValidity(
                type="YEARS",
                value=Token.as_string(1)
            )
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_acmpca_certificate_subordinate.override_logical_id("subordinate")
        aws_acmpca_certificate_authority_certificate_subordinate =
        AcmpcaCertificateAuthorityCertificate(self, "subordinate_6",
            certificate=Token.as_string(aws_acmpca_certificate_subordinate.certificate),
            certificate_authority_arn=subordinate.arn,
            certificate_chain=Token.as_string(aws_acmpca_certificate_subordinate.certificate_chain)
        )
        # This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.
        aws_acmpca_certificate_authority_certificate_subordinate.override_logical_id("subordinate")
```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `certificate` - (Required) PEM-encoded certificate for the Certificate Authority.
* `certificate_authority_arn` - (Required) ARN of the Certificate Authority.
* `certificate_chain` - (Optional) PEM-encoded certificate chain that includes any intermediate certificates and chains up to root CA. Required for subordinate Certificate Authorities. Not allowed for root Certificate Authorities.

## Attribute Reference

This resource exports no additional attributes.

<!-- cache-key: cdktf-0.20.8 input-422b7ffcfa1cfe91b04035d95233eeaf9e0497240f1245b6c366dbd00bae2aff -->