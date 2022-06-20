package networkfirewall_test

import (
	"fmt"
	"testing"
)

func TestFirewallRuleGroup_arn(t *testing.T) {

}

func testFirewallRuleGroupDataSource(rName string) string {
	return fmt.Sprintf(`

data "aws_networkfirewall_rule_group" "test" {
	arn = aws_networkfirewall_rule_group.test.arn
}

resource "aws_networkfirewall_rule_group" "test" {
	capacity = 100
	name     = "test"
	type     = "STATEFUL"
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
  
	tags = {
	  Tag1 = "Value1"
	  Tag2 = "Value2"
	}
  }

	`, rName)
}
