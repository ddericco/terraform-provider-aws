package networkfirewall_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/service/networkfirewall"
	sdkacctest "github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
)

func TestFirewallRuleGroup_arn(t *testing.T) {

}

func TestAccNetworkFirewallRuleDataSource_Basic_rulesSourceList(t *testing.T) {
	var ruleGroup networkfirewall.DescribeRuleGroupOutput
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_networkfirewall_rule_group.test"
	datasourceName := "data.aws_networkfirewall_rule_group.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:          func() { acctest.PreCheck(t); testAccPreCheck(t) },
		ErrorCheck:        acctest.ErrorCheck(t, networkfirewall.EndpointsID),
		ProviderFactories: acctest.ProviderFactories,
		CheckDestroy:      testAccCheckRuleGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testFirewallRuleGroupDataSource(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRuleGroupExists(resourceName, &ruleGroup),
					acctest.CheckResourceAttrRegionalARN(datasourceName, "arn", "network-firewall", fmt.Sprintf("stateful-rulegroup/%s", rName)),
					resource.TestCheckResourceAttrPair(datasourceName, "capacity", resourceName, "capacity"),
					resource.TestCheckResourceAttrPair(datasourceName, "name", resourceName, "name"),
					resource.TestCheckResourceAttrPair(datasourceName, "type", resourceName, "type"),
					resource.TestCheckResourceAttrPair(datasourceName, "rule_group.#", resourceName, "rule_group.#"),
					resource.TestCheckResourceAttrPair(datasourceName, "rule_group.0.rules_source.#", resourceName, "rule_group.0.rules_source.#"),
					resource.TestCheckResourceAttrPair(datasourceName, "rule_group.0.rules_source.0.rules_source_list.#", resourceName, "rule_group.0.rules_source.0.rules_source_list.#"),
					resource.TestCheckResourceAttrPair(datasourceName, "rule_group.0.rules_source.0.rules_source_list.0.generated_rules_type", resourceName, "rule_group.0.rules_source.0.rules_source_list.0.generated_rules_type"),
					resource.TestCheckResourceAttrPair(datasourceName, "rule_group.0.rules_source.0.rules_source_list.0.target_types.#", resourceName, "rule_group.0.rules_source.0.rules_source_list.0.target_types.#"),
					resource.TestCheckTypeSetElemAttrPair(datasourceName, "rule_group.0.rules_source.0.rules_source_list.0.target_types.*", resourceName, "rule_group.0.rules_source.0.rules_source_list.0.target_types.*"),
					resource.TestCheckResourceAttrPair(datasourceName, "rule_group.0.rules_source.0.rules_source_list.0.targets.#", resourceName, "rule_group.0.rules_source.0.rules_source_list.0.targets.#"),
					resource.TestCheckTypeSetElemAttrPair(datasourceName, "rule_group.0.rules_source.0.rules_source_list.0.targets.*", resourceName, "rule_group.0.rules_source.0.rules_source_list.0.targets.*"),
					resource.TestCheckResourceAttrPair(datasourceName, "rule_group.0.stateful_rule_options.#", resourceName, "rule_group.0.stateful_rule_options.#"),
					resource.TestCheckResourceAttrPair(datasourceName, "tags.%", resourceName, "tags.%"),
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

func testFirewallRuleGroupDataSource(rName string) string {
	return fmt.Sprintf(`
data "aws_networkfirewall_rule_group" "test" {
	arn = aws_networkfirewall_rule_group.test.arn
}

resource "aws_networkfirewall_rule_group" "test" {
	capacity = 100
	name     = %[1]q
	type     = "STATEFUL"
	rule_group {
		rules_source {
			stateful_rule {
			  action = "DROP"
			  header {
				destination      = "124.1.1.24/32"
				destination_port = 53
				direction        = "ANY"
				protocol         = "TCP"
				source           = "1.2.3.4/32"
				source_port      = 53
			  }
			  rule_option {
				keyword = "sid:1"
			  }
			}
		}  
	}
}  
`, rName)
}
