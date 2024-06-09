// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package wafv2_test

import (
	"fmt"
	"testing"

	"github.com/YakDriver/regexache"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestAccWAFV2RegexPatternSetDataSource_basic(t *testing.T) {
	ctx := acctest.Context(t)
	name := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_wafv2_regex_pattern_set.test"
	datasourceName := "data.aws_wafv2_regex_pattern_set.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheckScopeRegional(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.WAFV2ServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccRegexPatternSetDataSourceConfig_nonExistent(name),
				ExpectError: regexache.MustCompile(`WAFv2 RegexPatternSet not found`),
			},
			{
				Config: testAccRegexPatternSetDataSourceConfig_name(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(datasourceName, names.AttrARN, resourceName, names.AttrARN),
					acctest.MatchResourceAttrRegionalARN(datasourceName, names.AttrARN, "wafv2", regexache.MustCompile(fmt.Sprintf("regional/regexpatternset/%v/.+$", name))),
					resource.TestCheckResourceAttrPair(datasourceName, names.AttrDescription, resourceName, names.AttrDescription),
					resource.TestCheckResourceAttrPair(datasourceName, names.AttrID, resourceName, names.AttrID),
					resource.TestCheckResourceAttrPair(datasourceName, names.AttrName, resourceName, names.AttrName),
					resource.TestCheckResourceAttrPair(datasourceName, "regular_expression", resourceName, "regular_expression"),
					resource.TestCheckResourceAttrPair(datasourceName, names.AttrScope, resourceName, names.AttrScope),
				),
			},
		},
	})
}

func testAccRegexPatternSetDataSourceConfig_name(name string) string {
	return fmt.Sprintf(`
resource "aws_wafv2_regex_pattern_set" "test" {
  name  = "%s"
  scope = "REGIONAL"

  regular_expression {
    regex_string = "one"
  }
}

data "aws_wafv2_regex_pattern_set" "test" {
  name  = aws_wafv2_regex_pattern_set.test.name
  scope = "REGIONAL"
}
`, name)
}

func testAccRegexPatternSetDataSourceConfig_nonExistent(name string) string {
	return fmt.Sprintf(`
resource "aws_wafv2_regex_pattern_set" "test" {
  name  = "%s"
  scope = "REGIONAL"

  regular_expression {
    regex_string = "one"
  }
}

data "aws_wafv2_regex_pattern_set" "test" {
  name  = "tf-acc-test-does-not-exist"
  scope = "REGIONAL"
}
`, name)
}
