package auth0

import (
	"log"
	"strings"
	"testing"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/random"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func init() {
	resource.AddTestSweepers("auth0_rule_config", &resource.Sweeper{
		Name: "auth0_rule_config",
		F: func(_ string) error {
			api := testAuth0ApiClient()
			configurations, err := api.RuleConfig.List()
			if err != nil {
				return err
			}
			for _, c := range configurations {
				log.Printf("[DEBUG] ➝ %s", c.GetKey())
				if strings.Contains(c.GetKey(), "test") {
					if e := api.RuleConfig.Delete(c.GetKey()); e != nil {
						_ = multierror.Append(err, e)
					}
					log.Printf("[DEBUG] ✗ %s", c.GetKey())
				}
			}
			return err
		},
	})
}

func TestAccRuleConfig(t *testing.T) {

	rand := random.String(4)

	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`

resource "auth0_rule_config" "foo" {
  key = "acc_test_{{.random}}"
  value = "bar"
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_rule_config.foo", "id", "acc_test_{{.random}}", rand),
					random.TestCheckResourceAttr("auth0_rule_config.foo", "key", "acc_test_{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_rule_config.foo", "value", "bar"),
				),
			},
			{
				Config: random.Template(`

resource "auth0_rule_config" "foo" {
  key = "acc_test_{{.random}}"
  value = "foo"
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_rule_config.foo", "id", "acc_test_{{.random}}", rand),
					random.TestCheckResourceAttr("auth0_rule_config.foo", "key", "acc_test_{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_rule_config.foo", "value", "foo"),
				),
			},
			{
				Config: random.Template(`

resource "auth0_rule_config" "foo" {
  key = "acc_test_key_{{.random}}"
  value = "foo"
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_rule_config.foo", "id", "acc_test_key_{{.random}}", rand),
					random.TestCheckResourceAttr("auth0_rule_config.foo", "key", "acc_test_key_{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_rule_config.foo", "value", "foo"),
				),
			},
		},
	})
}
