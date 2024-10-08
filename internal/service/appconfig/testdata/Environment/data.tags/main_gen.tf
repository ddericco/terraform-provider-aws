# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# tflint-ignore: terraform_unused_declarations
data "aws_appconfig_environment" "test" {
  application_id = aws_appconfig_application.test.id
  environment_id = aws_appconfig_environment.test.environment_id
}

resource "aws_appconfig_environment" "test" {
  name           = var.rName
  application_id = aws_appconfig_application.test.id

  tags = var.resource_tags
}

resource "aws_appconfig_application" "test" {
  name = var.rName
}

variable "rName" {
  description = "Name for resource"
  type        = string
  nullable    = false
}

variable "resource_tags" {
  description = "Tags to set on resource. To specify no tags, set to `null`"
  # Not setting a default, so that this must explicitly be set to `null` to specify no tags
  type     = map(string)
  nullable = true
}
