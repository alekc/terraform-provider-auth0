package auth0

import (
	"log"
	"regexp"
	"strings"
	"testing"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/random"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"gopkg.in/auth0.v5/management"
)

func init() {
	resource.AddTestSweepers("data_auth0_connections", &resource.Sweeper{
		Name: "data_auth0_connections",
		F: func(_ string) error {
			api := testAuth0ApiClient()
			var page int
			for {
				l, err := api.Connection.List(
					management.IncludeFields("id", "name"),
					management.Page(page))
				if err != nil {
					return err
				}
				for _, connection := range l.Connections {
					log.Printf("[DEBUG] ➝ %s", connection.GetName())
					if strings.Contains(connection.GetName(), "Test") {
						if e := api.Connection.Delete(connection.GetID()); e != nil {
							_ = multierror.Append(err, e)
						}
						log.Printf("[DEBUG] ✗ %s", connection.GetName())
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

func TestAccDataSourceConnections_NoConnections(t *testing.T) {
	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`data "auth0_connections" "cons" {}`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.#", "0"),
				),
			},
		},
	})
}

func TestAccDataSourceConnections_InvalidStrategy(t *testing.T) {
	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
data "auth0_connections" "cons" {
	strategy = ["not-real"]
}
				`, rand),
				ExpectError: regexp.MustCompile(`Error: expected strategy\.0 to be one of \[`),
			},
		},
	})
}

func TestAccDataSourceConnections_NoFilter(t *testing.T) {
	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "con1" {
	name = "Acceptance-Test-Connection-1-{{.random}}"
	strategy = "auth0"
	options {}
}

resource "auth0_connection" "con2" {
	name = "Acceptance-Test-Connection-2-{{.random}}"
	strategy = "auth0"
	options {}
}

resource "auth0_connection" "con3" {
	name = "Acceptance-Test-Connection-sfc-{{.random}}"
	strategy = "salesforce-community"

	options {
		client_id = "client-id"
		client_secret = "client-secret"
		community_base_url = "https://salesforce.example.com"
	}
}

data "auth0_connections" "cons" {
	# To ensure the resources are created before the data source tries to fetch the information
	depends_on = [auth0_connection.con1, auth0_connection.con2, auth0_connection.con3]
}
				`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.#", "3"),
					random.TestCheckTypeSetElemNestedAttrs("data.auth0_connections.cons", "connections.*", map[string]string{
						"name":     "Acceptance-Test-Connection-1-{{.random}}",
						"strategy": "auth0",
					}, rand),
					random.TestCheckTypeSetElemNestedAttrs("data.auth0_connections.cons", "connections.*", map[string]string{
						"name":     "Acceptance-Test-Connection-1-{{.random}}",
						"strategy": "auth0",
					}, rand),
					random.TestCheckTypeSetElemNestedAttrs("data.auth0_connections.cons", "connections.*", map[string]string{
						"name":     "Acceptance-Test-Connection-sfc-{{.random}}",
						"strategy": "salesforce-community",
					}, rand),
				),
			},
		},
	})
}

func TestAccDataSourceConnections_ByName(t *testing.T) {
	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "con1" {
	name = "Acceptance-Test-Connection-1-{{.random}}"
	is_domain_connection = true
	strategy = "auth0"
	options {
		password_policy = "fair"
		password_history {
			enable = true
			size = 5
		}
		password_no_personal_info {
			enable = true
		}
		password_dictionary {
			enable = true
			dictionary = [ "password", "admin", "1234" ]
		}
		password_complexity_options {
			min_length = 6
		}
		validation {
			username {
				min = 10
				max = 40
			}
		}
		enabled_database_customization = false
		brute_force_protection = true
		import_mode = false
		requires_username = true
		disable_signup = false
		custom_scripts = {
			get_user = "myFunction"
		}
		configuration = {
			foo = "bar"
		}
		mfa {
			active                 = true
			return_enroll_settings = true
		}
	}
}

resource "auth0_connection" "con2" {
	name = "Acceptance-Test-Connection-2-{{.random}}"
	strategy = "auth0"
	options {}
}

data "auth0_connections" "cons" {
	name = auth0_connection.con1.name

	# To ensure the resources are created before the data source tries to fetch the information
	depends_on = [auth0_connection.con1, auth0_connection.con2]
}
				`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.#", "1"),
					random.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.name", "Acceptance-Test-Connection-1-{{.random}}", rand),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.is_domain_connection", "true"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.strategy", "auth0"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.password_policy", "fair"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.password_no_personal_info.0.enable", "true"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.password_dictionary.0.enable", "true"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.password_complexity_options.0.min_length", "6"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.enabled_database_customization", "false"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.brute_force_protection", "true"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.import_mode", "false"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.disable_signup", "false"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.requires_username", "true"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.validation.0.username.0.min", "10"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.validation.0.username.0.max", "40"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.custom_scripts.get_user", "myFunction"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.mfa.0.active", "true"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.mfa.0.return_enroll_settings", "true"),
					// NOTE: The configuration is currently empty because the values retrieved from auth0 are encrypted
					//       The resource uses the original values from the state, however the data source can't do that
					//resource.TestCheckResourceAttrSet("data.auth0_connections.cons", "connections.0.options.0.configuration.foo"),
				),
			},
		},
	})
}

func TestAccDataSourceConnections_BySingleStrategy(t *testing.T) {
	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "con1" {
	name = "Acceptance-Test-Connection-auth0-{{.random}}"
	is_domain_connection = true
	strategy = "auth0"
	options {
		password_policy = "fair"
		password_history {
			enable = true
			size = 5
		}
		password_no_personal_info {
			enable = true
		}
		password_dictionary {
			enable = true
			dictionary = [ "password", "admin", "1234" ]
		}
		password_complexity_options {
			min_length = 6
		}
		validation {
			username {
				min = 10
				max = 40
			}
		}
		enabled_database_customization = false
		brute_force_protection = true
		import_mode = false
		requires_username = true
		disable_signup = false
		custom_scripts = {
			get_user = "myFunction"
		}
		configuration = {
			foo = "bar"
		}
		mfa {
			active                 = true
			return_enroll_settings = true
		}
	}
}

resource "auth0_connection" "con2" {
	name = "Acceptance-Test-Connection-sfc-{{.random}}"
	strategy = "salesforce-community"

	options {
		client_id = "client-id"
		client_secret = "client-secret"
		community_base_url = "https://salesforce.example.com"
	}
}

data "auth0_connections" "cons" {
	strategy = ["auth0"]

	# To ensure the resources are created before the data source tries to fetch the information
	depends_on = [auth0_connection.con1, auth0_connection.con2]
}
				`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.#", "1"),
					random.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.name", "Acceptance-Test-Connection-auth0-{{.random}}", rand),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.is_domain_connection", "true"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.strategy", "auth0"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.password_policy", "fair"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.password_no_personal_info.0.enable", "true"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.password_dictionary.0.enable", "true"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.password_complexity_options.0.min_length", "6"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.enabled_database_customization", "false"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.brute_force_protection", "true"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.import_mode", "false"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.disable_signup", "false"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.requires_username", "true"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.validation.0.username.0.min", "10"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.validation.0.username.0.max", "40"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.custom_scripts.get_user", "myFunction"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.mfa.0.active", "true"),
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.0.options.0.mfa.0.return_enroll_settings", "true"),
					// NOTE: The configuration is currently empty because the values retrieved from auth0 are encrypted
					//       The resource uses the original values from the state, however the data source can't do that
					//resource.TestCheckResourceAttrSet("data.auth0_connections.cons", "connections.0.options.0.configuration.foo"),
				),
			},
		},
	})
}

func TestAccDataSourceConnections_ByMultipleStrategies(t *testing.T) {
	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "con1" {
	name = "Acceptance-Test-Connection-auth0-{{.random}}"
	is_domain_connection = true
	strategy = "auth0"
	options {}
}

resource "auth0_connection" "con2" {
	name = "Acceptance-Test-Connection-sfc-{{.random}}"
	strategy = "salesforce-community"

	options {
		client_id = "client-id"
		client_secret = "client-secret"
		community_base_url = "https://salesforce.example.com"
	}
}

data "auth0_connections" "cons" {
	strategy = ["auth0", "salesforce-community"]

	# To ensure the resources are created before the data source tries to fetch the information
	depends_on = [auth0_connection.con1, auth0_connection.con2]
}
				`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.#", "2"),
					random.TestCheckTypeSetElemNestedAttrs("data.auth0_connections.cons", "connections.*", map[string]string{
						"name":     "Acceptance-Test-Connection-auth0-{{.random}}",
						"strategy": "auth0",
					}, rand),
					random.TestCheckTypeSetElemNestedAttrs("data.auth0_connections.cons", "connections.*", map[string]string{
						"name":     "Acceptance-Test-Connection-sfc-{{.random}}",
						"strategy": "salesforce-community",
					}, rand),
				),
			},
		},
	})
}

func TestAccDataSourceConnections_ByNameAndStrategy(t *testing.T) {
	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "con1" {
	name = "Acceptance-Test-Connection-1-{{.random}}"
	strategy = "auth0"
	options {}
}

resource "auth0_connection" "con2" {
	name = "Acceptance-Test-Connection-2-{{.random}}"
	strategy = "auth0"
	options {}
}

data "auth0_connections" "cons" {
	name = auth0_connection.con1.name
	strategy = ["auth0"]

	# To ensure the resources are created before the data source tries to fetch the information
	depends_on = [auth0_connection.con1, auth0_connection.con2]
}
				`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.auth0_connections.cons", "connections.#", "1"),
					random.TestCheckTypeSetElemNestedAttrs("data.auth0_connections.cons", "connections.*", map[string]string{
						"name":     "Acceptance-Test-Connection-1-{{.random}}",
						"strategy": "auth0",
					}, rand),
				),
			},
		},
	})
}
