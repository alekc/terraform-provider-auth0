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
	resource.AddTestSweepers("data_auth0_resource_server", &resource.Sweeper{
		Name: "data_auth0_resource_server",
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

func TestAccDataSourceResourceServer(t *testing.T) {

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

data "auth0_resource_server" "my_resource_server" {
	id = auth0_resource_server.my_resource_server.id
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "name", "Acceptance Test - {{.random}}", rand),
					random.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "identifier", "https://uat.api.alexkappa.com/{{.random}}", rand),
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "signing_alg", "RS256"),
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "allow_offline_access", "true"),
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "token_lifetime", "7200"),
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "token_lifetime_for_web", "3600"),
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "skip_consent_for_verifiable_first_party_clients", "true"),
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "enforce_policies", "true"),
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "scopes.#", "2"),
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "scopes.1.value", "create:foo"),
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "scopes.1.description", "Create foos"),
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "scopes.0.value", "create:bar"),
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "scopes.0.description", "Create bars"),
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

data "auth0_resource_server" "my_resource_server" {
	id = auth0_resource_server.my_resource_server.id
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "allow_offline_access", "false"),
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "scopes.#", "2"),
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "scopes.0.value", "create:bar"), // set id changes
					resource.TestCheckResourceAttr("data.auth0_resource_server.my_resource_server", "scopes.0.description", "Create bars for bar reasons"),
				),
			},
		},
	})
}
