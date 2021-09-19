package auth0

import (
	"testing"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/random"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccFlow_Common(t *testing.T) {
	rand := random.String(6)
	data := map[string]string{"random": rand, "trigger_id": "post-login"}
	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.TemplateMap(`
resource "auth0_action" "myaction" {
	name = "Acceptance Test - Action - {{.random}}"
	trigger {
		id = "{{ .trigger_id }}"
	}
	code = "exports.onExecutePostLogin = async (event, api) => {};"
	deploy = true
}
resource "auth0_action" "myaction2" {
	name = "Acceptance Test - Action2 - {{.random}}"
	trigger {
		id = "{{ .trigger_id }}"
	}
	code = "exports.onExecutePostLogin = async (event, api) => {};"
	deploy = true
}
resource "auth0_flow" "bind"{
	trigger_id =  "{{ .trigger_id }}"
	action {
		display_name = "action1"
		id = "${auth0_action.myaction.id}"
	}
	action {
		display_name = "action2"
		name = "${auth0_action.myaction2.name}"
	}
}
`, data),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_flow.bind", "trigger_id", "post-login"),
					resource.TestCheckResourceAttr("auth0_flow.bind", "action.#", "2"),
					resource.TestCheckResourceAttr("auth0_flow.bind", "action.0.display_name", "action1"),
					random.TestCheckResourceAttr("auth0_flow.bind", "action.0.name", "Acceptance Test - Action - {{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_flow.bind", "action.1.display_name", "action2"),
					random.TestCheckResourceAttr("auth0_flow.bind", "action.1.name", "Acceptance Test - Action2 - {{.random}}", rand),
				),
			},
		},
	})
}
