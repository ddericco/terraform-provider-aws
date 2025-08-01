// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package networkmanager_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/YakDriver/regexache"
	awstypes "github.com/aws/aws-sdk-go-v2/service/networkmanager/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	tfnetworkmanager "github.com/hashicorp/terraform-provider-aws/internal/service/networkmanager"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestAccNetworkManagerCoreNetwork_basic(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_networkmanager_core_network.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.NetworkManagerServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckCoreNetworkDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccCoreNetworkConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCoreNetworkExists(ctx, resourceName),
					acctest.MatchResourceAttrGlobalARN(ctx, resourceName, names.AttrARN, "networkmanager", regexache.MustCompile(`core-network/core-network-.+`)),
					resource.TestCheckResourceAttrSet(resourceName, names.AttrCreatedAt),
					resource.TestCheckResourceAttr(resourceName, names.AttrDescription, ""),
					resource.TestMatchResourceAttr(resourceName, names.AttrID, regexache.MustCompile(`core-network-.+`)),
					resource.TestCheckResourceAttr(resourceName, names.AttrState, string(awstypes.CoreNetworkStateAvailable)),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsPercent, "0"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"create_base_policy"},
			},
		},
	})
}

func TestAccNetworkManagerCoreNetwork_disappears(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_networkmanager_core_network.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.NetworkManagerServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckCoreNetworkDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccCoreNetworkConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCoreNetworkExists(ctx, resourceName),
					acctest.CheckResourceDisappears(ctx, acctest.Provider, tfnetworkmanager.ResourceCoreNetwork(), resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccNetworkManagerCoreNetwork_description(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_networkmanager_core_network.test"
	originalDescription := "description1"
	updatedDescription := "description2"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.NetworkManagerServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckCoreNetworkDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccCoreNetworkConfig_description(originalDescription),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCoreNetworkExists(ctx, resourceName),
					resource.TestCheckResourceAttr(resourceName, names.AttrDescription, originalDescription),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"create_base_policy"},
			},
			{
				Config: testAccCoreNetworkConfig_description(updatedDescription),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCoreNetworkExists(ctx, resourceName),
					resource.TestCheckResourceAttr(resourceName, names.AttrDescription, updatedDescription),
				),
			},
		},
	})
}

func TestAccNetworkManagerCoreNetwork_createBasePolicyDocumentWithoutRegion(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_networkmanager_core_network.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.NetworkManagerServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckCoreNetworkDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccCoreNetworkConfig_basePolicyDocumentWithoutRegion(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCoreNetworkExists(ctx, resourceName),
					resource.TestCheckResourceAttr(resourceName, "create_base_policy", acctest.CtTrue),
					resource.TestCheckNoResourceAttr(resourceName, "base_policy_regions"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "edges.*", map[string]string{
						"asn":                  "64512",
						"edge_location":        acctest.Region(),
						"inside_cidr_blocks.#": "0",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "segments.*", map[string]string{
						"edge_locations.#":  "1",
						"edge_locations.0":  acctest.Region(),
						names.AttrName:      "segment",
						"shared_segments.#": "0",
					}),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"create_base_policy"},
			},
		},
	})
}

func TestAccNetworkManagerCoreNetwork_createBasePolicyDocumentWithMultiRegion(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_networkmanager_core_network.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.NetworkManagerServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckCoreNetworkDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccCoreNetworkConfig_basePolicyDocumentWithMultiRegion(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCoreNetworkExists(ctx, resourceName),
					resource.TestCheckResourceAttr(resourceName, "create_base_policy", acctest.CtTrue),
					resource.TestCheckResourceAttr(resourceName, "base_policy_regions.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "base_policy_regions.*", acctest.AlternateRegion()),
					resource.TestCheckTypeSetElemAttr(resourceName, "base_policy_regions.*", acctest.Region()),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "edges.*", map[string]string{
						"asn":                  "64512",
						"edge_location":        acctest.AlternateRegion(),
						"inside_cidr_blocks.#": "0",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "edges.*", map[string]string{
						"asn":                  "64513",
						"edge_location":        acctest.Region(),
						"inside_cidr_blocks.#": "0",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "segments.*", map[string]string{
						"edge_locations.#":  "2",
						names.AttrName:      "segment",
						"shared_segments.#": "0",
					}),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"base_policy_regions", "create_base_policy"},
			},
		},
	})
}

func TestAccNetworkManagerCoreNetwork_createBasePolicyDocumentWithPolicyDocument(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_networkmanager_core_network.test"
	edgeAsn1 := "65500"
	edgeAsn2 := "65501"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.NetworkManagerServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckCoreNetworkDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccCoreNetworkConfig_basePolicyDocumentWithPolicyDocument(edgeAsn1, edgeAsn2),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCoreNetworkExists(ctx, resourceName),
					resource.TestCheckResourceAttr(resourceName, "create_base_policy", acctest.CtTrue),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "edges.*", map[string]string{
						"asn":                  edgeAsn1,
						"edge_location":        acctest.AlternateRegion(),
						"inside_cidr_blocks.#": "0",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "edges.*", map[string]string{
						"asn":                  edgeAsn2,
						"edge_location":        acctest.Region(),
						"inside_cidr_blocks.#": "0",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "segments.*", map[string]string{
						"edge_locations.#":  "2",
						names.AttrName:      "segment",
						"shared_segments.#": "0",
					}),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"base_policy_document", "create_base_policy"},
			},
		},
	})
}

func TestAccNetworkManagerCoreNetwork_withoutPolicyDocumentUpdateToCreateBasePolicyDocument(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_networkmanager_core_network.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.NetworkManagerServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckCoreNetworkDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccCoreNetworkConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCoreNetworkExists(ctx, resourceName),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"create_base_policy"},
			},
			{
				Config: testAccCoreNetworkConfig_basePolicyDocumentWithoutRegion(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCoreNetworkExists(ctx, resourceName),
					resource.TestCheckResourceAttr(resourceName, "create_base_policy", acctest.CtTrue),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "edges.*", map[string]string{
						"asn":                  "64512",
						"edge_location":        acctest.Region(),
						"inside_cidr_blocks.#": "0",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "segments.*", map[string]string{
						"edge_locations.#":  "1",
						"edge_locations.0":  acctest.Region(),
						names.AttrName:      "segment",
						"shared_segments.#": "0",
					}),
				),
			},
		},
	})
}

func testAccCheckCoreNetworkDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).NetworkManagerClient(ctx)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_networkmanager_core_network" {
				continue
			}

			_, err := tfnetworkmanager.FindCoreNetworkByID(ctx, conn, rs.Primary.ID)

			if tfresource.NotFound(err) {
				continue
			}

			if err != nil {
				return err
			}

			return fmt.Errorf("Network Manager Core Network %s still exists", rs.Primary.ID)
		}

		return nil
	}
}

func testAccCheckCoreNetworkExists(ctx context.Context, n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No Network Manager Core Network ID is set")
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).NetworkManagerClient(ctx)

		_, err := tfnetworkmanager.FindCoreNetworkByID(ctx, conn, rs.Primary.ID)

		return err
	}
}

func testAccCoreNetworkConfig_basic() string {
	return `
resource "aws_networkmanager_global_network" "test" {}

resource "aws_networkmanager_core_network" "test" {
  global_network_id = aws_networkmanager_global_network.test.id
}`
}

func testAccCoreNetworkConfig_description(description string) string {
	return fmt.Sprintf(`
resource "aws_networkmanager_global_network" "test" {}

resource "aws_networkmanager_core_network" "test" {
  global_network_id = aws_networkmanager_global_network.test.id
  description       = %[1]q
}
`, description)
}

func testAccCoreNetworkConfig_basePolicyDocumentWithoutRegion() string {
	return `
resource "aws_networkmanager_global_network" "test" {}

resource "aws_networkmanager_core_network" "test" {
  global_network_id  = aws_networkmanager_global_network.test.id
  create_base_policy = true
}
`
}

func testAccCoreNetworkConfig_basePolicyDocumentWithMultiRegion() string {
	return fmt.Sprintf(`
resource "aws_networkmanager_global_network" "test" {}

resource "aws_networkmanager_core_network" "test" {
  global_network_id   = aws_networkmanager_global_network.test.id
  base_policy_regions = [%[1]q, %[2]q]
  create_base_policy  = true
}
`, acctest.AlternateRegion(), acctest.Region())
}

func testAccCoreNetworkConfig_basePolicyDocumentWithPolicyDocument(edgeAsn1, edgeAsn2 string) string {
	return fmt.Sprintf(`
resource "aws_networkmanager_global_network" "test" {}

data "aws_networkmanager_core_network_policy_document" "test" {
  core_network_configuration {
    asn_ranges = ["65022-65534"]

    edge_locations {
      location = %[1]q
      asn      = %[2]q
    }

    edge_locations {
      location = %[3]q
      asn      = %[4]q
    }
  }

  segments {
    name = "segment"
  }
}

resource "aws_networkmanager_core_network" "test" {
  global_network_id    = aws_networkmanager_global_network.test.id
  create_base_policy   = true
  base_policy_document = data.aws_networkmanager_core_network_policy_document.test.json
}
`, acctest.AlternateRegion(), edgeAsn1, acctest.Region(), edgeAsn2)
}
