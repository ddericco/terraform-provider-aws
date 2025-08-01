// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package organizations_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/YakDriver/regexache"
	awstypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	tforganizations "github.com/hashicorp/terraform-provider-aws/internal/service/organizations"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func testAccOrganizationalUnit_basic(t *testing.T) {
	ctx := acctest.Context(t)
	var unit awstypes.OrganizationalUnit
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_organizations_organizational_unit.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckOrganizationManagementAccount(ctx, t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.OrganizationsServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckOrganizationalUnitDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccOrganizationalUnitConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckOrganizationalUnitExists(ctx, resourceName, &unit),
					resource.TestCheckResourceAttr(resourceName, "accounts.#", "0"),
					acctest.MatchResourceAttrGlobalARN(ctx, resourceName, names.AttrARN, "organizations", regexache.MustCompile("ou/"+organizationIDRegexPattern+"/ou-[0-9a-z]{4}-[0-9a-z]{8}$")),
					resource.TestCheckResourceAttr(resourceName, names.AttrName, rName),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsPercent, "0"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccOrganizationalUnit_disappears(t *testing.T) {
	ctx := acctest.Context(t)
	var unit awstypes.OrganizationalUnit
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_organizations_organizational_unit.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckOrganizationManagementAccount(ctx, t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.OrganizationsServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckOrganizationalUnitDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccOrganizationalUnitConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckOrganizationalUnitExists(ctx, resourceName, &unit),
					acctest.CheckResourceDisappears(ctx, acctest.Provider, tforganizations.ResourceOrganizationalUnit(), resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccOrganizationalUnit_update(t *testing.T) {
	ctx := acctest.Context(t)
	var unit awstypes.OrganizationalUnit
	rName1 := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	rName2 := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_organizations_organizational_unit.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckOrganizationManagementAccount(ctx, t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.OrganizationsServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckOrganizationalUnitDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccOrganizationalUnitConfig_basic(rName1),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckOrganizationalUnitExists(ctx, resourceName, &unit),
					resource.TestCheckResourceAttr(resourceName, names.AttrName, rName1),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccOrganizationalUnitConfig_basic(rName2),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckOrganizationalUnitExists(ctx, resourceName, &unit),
					resource.TestCheckResourceAttr(resourceName, names.AttrName, rName2),
				),
			},
		},
	})
}

func testAccCheckOrganizationalUnitDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).OrganizationsClient(ctx)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_organizations_organizational_unit" {
				continue
			}

			_, err := tforganizations.FindOrganizationalUnitByID(ctx, conn, rs.Primary.ID)

			if tfresource.NotFound(err) {
				continue
			}

			if err != nil {
				return err
			}

			return fmt.Errorf("Organizations Organizational Unit %s still exists", rs.Primary.ID)
		}

		return nil
	}
}

func testAccCheckOrganizationalUnitExists(ctx context.Context, n string, v *awstypes.OrganizationalUnit) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).OrganizationsClient(ctx)

		output, err := tforganizations.FindOrganizationalUnitByID(ctx, conn, rs.Primary.ID)

		if err != nil {
			return err
		}

		*v = *output

		return nil
	}
}

func testAccOrganizationalUnitConfig_basic(rName string) string {
	return fmt.Sprintf(`
data "aws_organizations_organization" "current" {}

resource "aws_organizations_organizational_unit" "test" {
  name      = %[1]q
  parent_id = data.aws_organizations_organization.current.roots[0].id
}
`, rName)
}
