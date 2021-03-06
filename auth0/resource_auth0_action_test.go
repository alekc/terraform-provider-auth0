package auth0

import (
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/random"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

func init() {
	resource.AddTestSweepers("auth0_action", &resource.Sweeper{
		Name: "auth0_action",
		F: func(_ string) error {
			api := testAuth0ApiClient()
			var page int
			for {
				l, err := api.Action.List(management.Page(page))
				if err != nil {
					return err
				}
				for _, action := range l.Actions {
					log.Printf("[DEBUG] ➝ %s", action.GetName())
					if strings.Contains(action.GetName(), "Test") {
						if e := api.Action.Delete(action.GetID()); e != nil {
							_ = multierror.Append(err, e)
						}
						log.Printf("[DEBUG] ✗ %s", action.GetName())
					}
				}
				if err != nil {
					return err
				}
				if !l.HasNext() {
					break
				}
				page++
			}
			return nil
		},
	})
}

func TestAccAction_Common(t *testing.T) {
	rand := random.String(6)
	const objectName = "auth0_action.myaction"
	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_action" "myaction" {
	name = "Acceptance Test - Action - {{.random}}"
	trigger {
		id = "post-login"
	}
	dependency {
		name = "lodash"
		version = "1.0.0"
	}
	dependency {
		name = "glob"
		version = "7.1.7"
	}
	secret {
		name = "foo"
		value = "fooval"
	}
	secret {
		name = "bar"
		value = "barval"
	}
	
	code = "exports.onExecutePostLogin = async (event, api) => {};"
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr(objectName, "name",
						"Acceptance Test - Action - {{.random}}", rand),
					resource.TestCheckResourceAttr(objectName, "trigger.0.id", "post-login"),
					resource.TestCheckResourceAttr(
						objectName,
						"code",
						"exports.onExecutePostLogin = async (event, api) => {};",
					),
					resource.TestCheckResourceAttr(
						objectName,
						"dependency.1.name",
						"lodash",
					),
					resource.TestCheckResourceAttr(
						objectName,
						"dependency.1.version",
						"1.0.0",
					),
					resource.TestCheckResourceAttr(
						objectName,
						"dependency.0.name",
						"glob",
					),
					resource.TestCheckResourceAttr(
						objectName,
						"dependency.0.version",
						"7.1.7",
					),
					resource.TestCheckResourceAttr(
						objectName,
						"secret.0.name",
						"foo",
					),
					resource.TestCheckResourceAttr(
						objectName,
						"secret.0.value",
						"fooval",
					),
					resource.TestCheckResourceAttr(
						objectName,
						"secret.1.name",
						"bar",
					),
					resource.TestCheckResourceAttr(
						objectName,
						"secret.1.value",
						"barval",
					),
				),
			},
		},
	})
}

func TestAccAction_Deploy(t *testing.T) {
	rand := random.String(6)
	const objectName = "auth0_action.myaction"
	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_action" "myaction" {
	name = "Acceptance Test - Action - {{.random}}"
	trigger {
		id = "post-login"
	}		
	code = "exports.onExecutePostLogin = async (event, api) => {};"
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						objectName,
						"status",
						"built",
					),
					resource.TestCheckResourceAttr(
						objectName,
						"all_changes_deployed",
						"false",
					),
				),
			},
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_action" "myaction" {
	name = "Acceptance Test - Action - {{.random}}"
	trigger {
		id = "post-login"
	}		
	code = "exports.onExecutePostLogin = async (event, api) => {};"
	deploy  = true
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						objectName,
						"status",
						"built",
					),
					resource.TestCheckResourceAttr(
						objectName,
						"all_changes_deployed",
						"true",
					),
				),
			},
		},
	})
}
func TestAccAction_Secrets(t *testing.T) {
	rand := random.String(6)
	updatedSecretConfigPlan := random.Template(`
resource "auth0_action" "myaction" {
	name = "Acceptance Test - Action - {{.random}}"
	trigger {
		id = "post-login"
	}
	code = "exports.onExecutePostLogin = async (event, api) => {};"
	secret {
		name = "foo2"
		value = "topsecret"		
	}
}
`, rand)
	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_action" "myaction" {
	name = "Acceptance Test - Action - {{.random}}"
	trigger {
		id = "post-login"
	}
	code = "exports.onExecutePostLogin = async (event, api) => {};"
	secret {
		name = "foo"
		value = "secret"		
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_action.myaction", "name",
						"Acceptance Test - Action - {{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_action.myaction", "secret.0.name", "foo"),
					resource.TestCheckResourceAttr("auth0_action.myaction", "secret.0.value", "secret"),
				),
			},
			{
				Config: updatedSecretConfigPlan,
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_action.myaction", "name",
						"Acceptance Test - Action - {{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_action.myaction", "secret.0.name", "foo2"),
					resource.TestCheckResourceAttr("auth0_action.myaction", "secret.0.value", "topsecret"),
				),
			},
			{
				Config: updatedSecretConfigPlan,
				Check: resource.ComposeAggregateTestCheckFunc(
					func(state *terraform.State) error {
						// patch manually the secret
						api := testAuth0ApiClient()
						secretName := fmt.Sprintf(`Acceptance Test - Action - %s`, rand)
						actionList, err := api.Action.List()
						if err != nil {
							return err
						}
						for _, action := range actionList.Actions {
							if action.GetName() != secretName {
								continue
							}
							patchAction := &management.Action{
								Name:              action.Name,
								Code:              action.Code,
								SupportedTriggers: action.SupportedTriggers,
								Secrets:           action.Secrets,
							}
							patchAction.Secrets[0].Value = auth0.String("xxxxxxxx")
							if err = api.Action.Update(*action.ID, patchAction); err != nil {
								return err
							}
							break
						}
						return nil
					},
				),
				ExpectNonEmptyPlan: true,
			},
			{
				Config: updatedSecretConfigPlan,
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_action.myaction", "name",
						"Acceptance Test - Action - {{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_action.myaction", "secret.0.name", "foo2"),
					resource.TestCheckResourceAttr("auth0_action.myaction", "secret.0.value", "topsecret"),
				),
			},
		},
	})
}
