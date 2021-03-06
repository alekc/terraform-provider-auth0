package auth0

import (
	"log"
	"strings"
	"testing"

	"github.com/hashicorp/go-multierror"
	"gopkg.in/auth0.v5/management"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/random"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func init() {
	resource.AddTestSweepers("auth0_resource_server", &resource.Sweeper{
		Name: "auth0_resource_server",
		F: func(_ string) error {
			api := testAuth0ApiClient()
			fn := func(rs *management.ResourceServer) {
				log.Printf("[DEBUG] ➝ %s", rs.GetName())
				if strings.Contains(rs.GetName(), "Test") {
					if e := api.ResourceServer.Delete(rs.GetID()); e != nil {
						_ = multierror.Append(e)
					}
					log.Printf("[DEBUG] ✗ %s", rs.GetName())
				}
			}
			return api.ResourceServer.Stream(fn, management.IncludeFields("id", "name"))
		},
	})
}

func TestAccResourceServer(t *testing.T) {

	rand := random.String(6)

	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`

resource "auth0_resource_server" "my_resource_server" {
	name = "Acceptance Test - {{.random}}"
	identifier = "https://uat.api.alexkappa.com/{{.random}}"
	signing_alg = "RS256"
	scopes {
		value = "create:foo"
		description = "Create foos"
	}
	scopes {
		value = "create:bar"
		description = "Create bars"
	}
	allow_offline_access = true
	token_lifetime = 7200
	token_lifetime_for_web = 3600
	skip_consent_for_verifiable_first_party_clients = true
	enforce_policies = true
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "name", "Acceptance Test - {{.random}}", rand),
					random.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "identifier", "https://uat.api.alexkappa.com/{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "signing_alg", "RS256"),
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "allow_offline_access", "true"),
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "token_lifetime", "7200"),
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "token_lifetime_for_web", "3600"),
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "skip_consent_for_verifiable_first_party_clients", "true"),
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "enforce_policies", "true"),
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "scopes.#", "2"),
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "scopes.1.value", "create:foo"),
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "scopes.1.description", "Create foos"),
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "scopes.0.value", "create:bar"),
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "scopes.0.description", "Create bars"),
				),
			},
			{
				Config: random.Template(`

resource "auth0_resource_server" "my_resource_server" {
	name = "Acceptance Test - {{.random}}"
	identifier = "https://uat.api.alexkappa.com/{{.random}}"
	signing_alg = "RS256"
	scopes {
		value = "create:foo"
		description = "Create foos"
	}
	scopes {
		value = "create:bar"
		description = "Create bars for bar reasons"
	}
	allow_offline_access = false # <--- set to false
	token_lifetime = 7200
	token_lifetime_for_web = 3600
	skip_consent_for_verifiable_first_party_clients = true
	enforce_policies = true
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "allow_offline_access", "false"),
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "scopes.#", "2"),
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "scopes.0.value", "create:bar"), // set id changes
					resource.TestCheckResourceAttr("auth0_resource_server.my_resource_server", "scopes.0.description", "Create bars for bar reasons"),
				),
			},
		},
	})
}
