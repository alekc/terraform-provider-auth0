package auth0

import (
	"log"
	"strings"
	"testing"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/random"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"gopkg.in/auth0.v5/management"
)

func init() {
	resource.AddTestSweepers("auth0_connection", &resource.Sweeper{
		Name: "auth0_connection",
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

func TestAccConnection_Auth0(t *testing.T) {

	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
			resource "auth0_connection" "my_connection" {
				name = "Acceptance-Test-Connection-{{.random}}"
				auth0 {}
			}
						`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.my_connection", "name", "Acceptance-Test-Connection-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "auth0.0.mfa_active", "true"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.mfa_return_enroll_settings",
						"true"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "auth0.0.brute_force_protection",
						"true"),
				),
			},
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "my_connection" {
  name                 = "Acceptance-Test-Connection-{{.random}}"
  display_name         = "Display-{{.random}}"
  is_domain_connection = false
  realms               = ["foo", "bar"]
  auth0 {
    validation {
      username {
        min = 1
        max = 10
      }
    }
    password_policy      = "excellent"
    non_persistent_attrs = ["foo", "bar"]
    password_history {
      enable = true
      size   = 3
    }
    password_no_personal_info {
      enable = true
    }
    password_dictionary {
      enable     = true
      dictionary = ["password"]
    }
    password_complexity_options {
      min_length = 5
    }
    mfa_active                     = false
    mfa_return_enroll_settings     = false
    enabled_database_customization = true
    brute_force_protection         = false
    import_mode                    = true
    disable_signup                 = true
    requires_username              = true
    custom_scripts = {
      get_user = "myFunction"
    }
    configuration = {
      "foo" = "secretbar"
    }
  }
}
			`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.my_connection", "name", "Acceptance-Test-Connection-{{.random}}", rand),
					random.TestCheckResourceAttr("auth0_connection.my_connection", "display_name",
						"Display-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "is_domain_connection", "false"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "realms.#", "2"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "realms.0", "foo"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "realms.1", "bar"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.validation.0.username.0.min", "1"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.validation.0.username.0.max", "10"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.password_policy", "excellent"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.non_persistent_attrs.0", "bar"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.non_persistent_attrs.1", "foo"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.password_history.0.enable", "true"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.password_history.0.size", "3"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.password_no_personal_info.0.enable", "true"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.password_dictionary.0.enable", "true"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.password_dictionary.0.dictionary.0", "password"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.password_complexity_options.0.min_length", "5"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.mfa_active", "false"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.mfa_return_enroll_settings", "false"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.enabled_database_customization", "true"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "auth0.0.brute_force_protection", "false"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "auth0.0.import_mode", "true"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "auth0.0.disable_signup", "true"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "auth0.0.requires_username", "true"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "auth0.0.custom_scripts.get_user",
						"myFunction"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "auth0.0.configuration.foo",
						"secretbar"),

					resource.TestCheckResourceAttr("auth0_connection.my_connection", "auth0.0.mfa_active", "false"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "auth0.0.mfa_active", "false"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"auth0.0.mfa_return_enroll_settings",
						"false"),
				),
			},
			// 			{
			// 				// todo: due to a bug in aws sdk it's not possible for now to unset vars.
			// 				// once the support is introduced by removing omitempty, verify the behaviour
			// 				// language=HCL
			// 				Config: random.Template(`
			// resource "auth0_connection" "my_connection" {
			// 	name = "Acceptance-Test-Connection-{{.random}}"
			// 	auth0 {}
			// }
			// 			`, rand),
			// 				Check: resource.ComposeAggregateTestCheckFunc(
			// 					random.TestCheckResourceAttr("auth0_connection.my_connection", "name", "Acceptance-Test-Connection-{{.random}}", rand),
			// 					random.TestCheckResourceAttr("auth0_connection.my_connection", "display_name",
			// 						"Display-{{.random}}", rand),
			// 					resource.TestCheckResourceAttr("auth0_connection.my_connection", "is_domain_connection", "true"),
			// 					resource.TestCheckResourceAttr("auth0_connection.my_connection", "realms.#", "2"),
			// 					resource.TestCheckResourceAttr("auth0_connection.my_connection", "realms.0", "foo"),
			// 					resource.TestCheckResourceAttr("auth0_connection.my_connection", "realms.1", "bar"),
			// 					resource.TestCheckResourceAttr("auth0_connection.my_connection", "auth0.0.mfa_active", "true"),
			// 					resource.TestCheckResourceAttr("auth0_connection.my_connection",
			// 						"auth0.0.mfa_return_enroll_settings",
			// 						"true"),
			// 					resource.TestCheckResourceAttr("auth0_connection.my_connection", "auth0.0.brute_force_protection",
			// 						"true"),
			// 					// todo: add is_domain_connection
			// 				),
			// 			},
			// ,
			// {
			// 	Config: random.Template(`
			// resource "auth0_connection" "my_connection" {
			// 	name = "Acceptance-Test-Connection-{{.random}}"
			// 	is_domain_connection = true
			// 	strategy = "auth0"
			// 	options {
			// 		password_policy = "fair"
			// 		password_history {
			// 			enable = true
			// 			size = 5
			// 		}
			// 		password_no_personal_info {
			// 			enable = true
			// 		}
			// 		password_dictionary {
			// 			enable = true
			// 			dictionary = [ "password", "admin", "1234" ]
			// 		}
			// 		password_complexity_options {
			// 			min_length = 6
			// 		}
			// 		validation {
			// 			username {
			// 				min = 10
			// 				max = 40
			// 			}
			// 		}
			// 		enabled_database_customization = false
			// 		brute_force_protection = true
			// 		import_mode = false
			// 		requires_username = true
			// 		disable_signup = false
			// 		custom_scripts = {
			// 			get_user = "myFunction"
			// 		}
			// 		configuration = {
			// 			foo = "bar"
			// 		}
			// 		mfa {
			// 			active                 = true
			// 			return_enroll_settings = true
			// 		}
			// 	}
			// }
			// `, rand),
			// 	Check: resource.ComposeAggregateTestCheckFunc(
			// 		random.TestCheckResourceAttr("auth0_connection.my_connection", "name", "Acceptance-Test-Connection-{{.random}}", rand),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "is_domain_connection", "true"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "strategy", "auth0"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.password_policy", "fair"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.password_no_personal_info.0.enable", "true"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.password_dictionary.0.enable", "true"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.password_complexity_options.0.min_length", "6"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.enabled_database_customization", "false"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.brute_force_protection", "true"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.import_mode", "false"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.disable_signup", "false"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.requires_username", "true"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.validation.0.username.0.min", "10"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.validation.0.username.0.max", "40"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.custom_scripts.get_user", "myFunction"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.mfa.0.active", "true"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.mfa.0.return_enroll_settings", "true"),
			// 		resource.TestCheckResourceAttrSet("auth0_connection.my_connection", "options.0.configuration.foo"),
			// 	),
			// },
			// {
			// 	Config: random.Template(`
			//
			// resource "auth0_connection" "my_connection" {
			// 	name = "Acceptance-Test-Connection-{{.random}}"
			// 	is_domain_connection = true
			// 	strategy = "auth0"
			// 	options {
			// 		password_policy = "fair"
			// 		password_history {
			// 			enable = true
			// 			size = 5
			// 		}
			// 		password_no_personal_info {
			// 			enable = true
			// 		}
			// 		enabled_database_customization = false
			// 		brute_force_protection = false
			// 		import_mode = false
			// 		disable_signup = false
			// 		requires_username = true
			// 		custom_scripts = {
			// 			get_user = "myFunction"
			// 		}
			// 		configuration = {
			// 			foo = "bar"
			// 		}
			// 		mfa {
			// 			active                 = true
			// 			return_enroll_settings = false
			// 		}
			// 	}
			// }
			// `, rand),
			// 	Check: resource.ComposeAggregateTestCheckFunc(
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.brute_force_protection", "false"),
			// 		resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.mfa.0.return_enroll_settings", "false"),
			// 	),
			// },
		},
	})
}

func TestAccConnection_NonPersistentAttrs(t *testing.T) {

	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
			resource "auth0_connection" "my_connection" {
				name = "Acceptance-Test-Connection-{{.random}}"
				strategy = "auth0"
				options {
					non_persistent_attrs = ["ethnicity"]
				}
			}
			`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.my_connection", "name", "Acceptance-Test-Connection-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "strategy", "auth0"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection",
						"options.0.non_persistent_attrs.0", "ethnicity"),
				),
			},
			{
				// language=HCL
				Config: random.Template(`
			resource "auth0_connection" "my_connection" {
				name = "Acceptance-Test-Connection-{{.random}}"
				options {
					non_persistent_attrs = ["bar"]
				}
			}
			`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.my_connection", "name", "Acceptance-Test-Connection-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "strategy", "auth0"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.non_persistent_attrs.0", "bar"),
				),
			},
		},
	})
}

func TestAccConnection_AD(t *testing.T) {
	rand := random.String(6)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=hcl
				Config: random.Template(`
resource "auth0_connection" "ad" {
	name = "Acceptance-Test-AD-{{.random}}"
	ad {
		tenant_domain = "example.com"
		domain_aliases = [
			"example.com",
			"api.example.com"
		]
		ips = [ "192.168.1.1", "192.168.1.2" ]
		set_user_root_attributes = "on_each_login"
		non_persistent_attrs = ["ethnicity","gender"]
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.ad", "name", "Acceptance-Test-AD-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.ad", "ad.0.domain_aliases.#", "2"),
					resource.TestCheckResourceAttr("auth0_connection.ad", "ad.0.tenant_domain", "example.com"),
					resource.TestCheckResourceAttr("auth0_connection.ad", "ad.0.use_kerberos", "false"),
					resource.TestCheckResourceAttr("auth0_connection.ad", "ad.0.ips.1", "192.168.1.2"),
					resource.TestCheckResourceAttr("auth0_connection.ad", "ad.0.ips.0", "192.168.1.1"),
					resource.TestCheckResourceAttr("auth0_connection.ad", "ad.0.domain_aliases.1", "example.com"),
					resource.TestCheckResourceAttr("auth0_connection.ad", "ad.0.domain_aliases.0",
						"api.example.com"),
					resource.TestCheckResourceAttr("auth0_connection.ad", "ad.0.set_user_root_attributes",
						"on_each_login"),
					resource.TestCheckResourceAttr("auth0_connection.ad", "ad.0.non_persistent_attrs.0", "ethnicity"),
					resource.TestCheckResourceAttr("auth0_connection.ad", "ad.0.non_persistent_attrs.1", "gender"),
				),
			},
		},
	})
}

func TestAccConnection_AzureAD(t *testing.T) {

	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=hcl
				Config: random.Template(`
resource "auth0_connection" "azure_ad" {
	name     = "Acceptance-Test-Azure-AD-{{.random}}"
	waad {
		client_id     = "123456"
		client_secret = "123456"
		tenant_domain = "example.onmicrosoft.com"
		domain        = "example.onmicrosoft.com"
		domain_aliases = [
			"example.com",
			"api.example.com"
		]
		use_wsfed            = false
		waad_protocol        = "openid-connect"
		waad_common_endpoint = false
		api_enable_users     = true
		set_user_root_attributes = "on_each_login"
		should_trust_email_verified_connection = "never_set_emails_as_verified"
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.azure_ad", "name", "Acceptance-Test-Azure-AD-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.azure_ad", "waad.0.client_id", "123456"),
					resource.TestCheckResourceAttr("auth0_connection.azure_ad", "waad.0.client_secret", "123456"),
					resource.TestCheckResourceAttr("auth0_connection.azure_ad", "waad.0.tenant_domain",
						"example.onmicrosoft.com"),
					resource.TestCheckResourceAttr("auth0_connection.azure_ad", "waad.0.domain",
						"example.onmicrosoft.com"),
					resource.TestCheckResourceAttr("auth0_connection.azure_ad", "waad.0.domain_aliases.#", "2"),
					resource.TestCheckResourceAttr("auth0_connection.azure_ad", "waad.0.domain_aliases.1",
						"example.com"),
					resource.TestCheckResourceAttr("auth0_connection.azure_ad", "waad.0.domain_aliases.0",
						"api.example.com"),
					resource.TestCheckResourceAttr("auth0_connection.azure_ad", "waad.0.use_wsfed",
						"false"),
					resource.TestCheckResourceAttr("auth0_connection.azure_ad", "waad.0.waad_protocol",
						"openid-connect"),
					resource.TestCheckResourceAttr("auth0_connection.azure_ad", "waad.0.waad_common_endpoint",
						"false"),
					resource.TestCheckResourceAttr("auth0_connection.azure_ad", "waad.0.api_enable_users",
						"true"),
					resource.TestCheckResourceAttr("auth0_connection.azure_ad", "waad.0.set_user_root_attributes",
						"on_each_login"),
					resource.TestCheckResourceAttr("auth0_connection.azure_ad",
						"waad.0.should_trust_email_verified_connection", "never_set_emails_as_verified"),
				),
			},
		},
	})
}

func TestAccConnection_OIDC(t *testing.T) {

	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=hcl
				Config: random.Template(`
resource "auth0_connection" "oidc" {
	name     = "Acceptance-Test-OIDC-{{.random}}"
	display_name     = "Acceptance-Test-OIDC-{{.random}}"
	oidc {
		client_id     = "123456"
		client_secret = "1234567"
		domain_aliases = [
			"example.com",
			"api.example.com"
		]
		type                   = "back_channel"
		issuer                 = "https://api.login.yahoo.com"
		jwks_uri               = "https://api.login.yahoo.com/openid/v1/certs"
		discovery_url          = "https://api.login.yahoo.com/.well-known/openid-configuration"
		token_endpoint         = "https://api.login.yahoo.com/oauth2/get_token"
		userinfo_endpoint      = "https://api.login.yahoo.com/openid/v1/userinfo"
		authorization_endpoint = "https://api.login.yahoo.com/oauth2/request_auth"
		scopes                 = [ "openid", "email", "profile","zzz" ]
		set_user_root_attributes = "on_each_login"
		non_persistent_attrs = ["gender","hair_color"]
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.oidc", "name", "Acceptance-Test-OIDC-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.client_id", "123456"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.client_secret", "1234567"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.domain_aliases.#", "2"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.domain_aliases.1", "example.com"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.domain_aliases.0",
						"api.example.com"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.type", "back_channel"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.issuer",
						"https://api.login.yahoo.com"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.jwks_uri",
						"https://api.login.yahoo.com/openid/v1/certs"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.discovery_url",
						"https://api.login.yahoo.com/.well-known/openid-configuration"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.token_endpoint",
						"https://api.login.yahoo.com/oauth2/get_token"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.userinfo_endpoint",
						"https://api.login.yahoo.com/openid/v1/userinfo"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.authorization_endpoint",
						"https://api.login.yahoo.com/oauth2/request_auth"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.scopes.#", "4"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.scopes.1", "openid"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.scopes.2", "profile"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.scopes.3", "zzz"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.scopes.0", "email"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.set_user_root_attributes",
						"on_each_login"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.non_persistent_attrs.0",
						"gender"),
					resource.TestCheckResourceAttr("auth0_connection.oidc", "oidc.0.non_persistent_attrs.1",
						"hair_color"),
				),
			},
		},
	})
}

func TestAccConnection_OAuth2(t *testing.T) {

	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "oauth2" {
	name     = "Acceptance-Test-OAuth2-{{.random}}"
	oauth2 {
		client_id     = "123456"
		client_secret = "123456"
		token_endpoint         = "https://api.login.yahoo.com/oauth2/get_token"
		authorization_endpoint = "https://api.login.yahoo.com/oauth2/request_auth"
		scopes = [ "openid", "email", "profile", "zzz" ]
		set_user_root_attributes = "on_each_login"
		scripts = {
			fetchUserProfile= "function( { return callback(null) }"
		}
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.oauth2", "name", "Acceptance-Test-OAuth2-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.client_id", "123456"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.client_secret", "123456"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.token_endpoint", "https://api.login.yahoo.com/oauth2/get_token"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.authorization_endpoint", "https://api.login.yahoo.com/oauth2/request_auth"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.scopes.#", "4"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.scopes.0", "email"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.scopes.1", "openid"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.scopes.2", "profile"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.scopes.3", "zzz"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.scripts.fetchUserProfile", "function( { return callback(null) }"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.set_user_root_attributes", "on_each_login"),
				),
			},
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "oauth2" {
	name     = "Acceptance-Test-OAuth2-{{.random}}"
	is_domain_connection = false
	oauth2 {
		client_id     = "1234567"
		client_secret = "1234567"
		token_endpoint         = "https://api.paypal.com/v1/oauth2/token"
		authorization_endpoint = "https://www.paypal.com/signin/authorize"
		scopes = [ "openid", "email" ]
		set_user_root_attributes = "on_first_login"
		scripts = {
			fetchUserProfile= "function( { return callback(null) }"
		}
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.client_id", "1234567"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.client_secret", "1234567"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.token_endpoint", "https://api.paypal.com/v1/oauth2/token"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.authorization_endpoint", "https://www.paypal.com/signin/authorize"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.scopes.#", "2"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.scopes.1", "openid"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.scopes.0", "email"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.scripts.fetchUserProfile", "function( { return callback(null) }"),
					resource.TestCheckResourceAttr("auth0_connection.oauth2", "oauth2.0.set_user_root_attributes", "on_first_login"),
				),
			},
		},
	})
}

func TestAccConnectionWithEnabledClients(t *testing.T) {

	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`

resource "auth0_client" "my_client_1" {
	name = "Application - Acceptance Test - 1 - {{.random}}"
	description = "Test Applications Long Description"
	app_type = "non_interactive"
}

resource "auth0_client" "my_client_2" {
	name = "Application - Acceptance Test - 2 - {{.random}}"
	description = "Test Applications Long Description"
	app_type = "non_interactive"
}

resource "auth0_client" "my_client_3" {
	name = "Application - Acceptance Test - 3 - {{.random}}"
	description = "Test Applications Long Description"
	app_type = "non_interactive"
}

resource "auth0_client" "my_client_4" {
	name = "Application - Acceptance Test - 4 - {{.random}}"
	description = "Test Applications Long Description"
	app_type = "non_interactive"
}

resource "auth0_connection" "my_connection" {
	name = "Acceptance-Test-Connection-{{.random}}"
	is_domain_connection = true
    options {}
	enabled_clients = [
		"${auth0_client.my_client_1.id}",
		"${auth0_client.my_client_2.id}",
		"${auth0_client.my_client_3.id}",
		"${auth0_client.my_client_4.id}",
	]
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.my_connection", "name", "Acceptance-Test-Connection-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "enabled_clients.#", "4"),
				),
			},
		},
	})
}

func TestAccConnection_Email(t *testing.T) {

	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=hcl
				Config: random.Template(`
resource "auth0_connection" "email" {
	name = "Acceptance-Test-Email-{{.random}}"
	is_domain_connection = false

	email {
		disable_signup = false
		name = "Email OTP"
		from = "Magic Password <password@example.com>"
		subject = "Sign in!"
		syntax = "liquid"
		template = "<html><body><h1>Here's your password!</h1></body></html>"
		brute_force_protection = true
		totp {
			time_step = 300
			length = 6
		}
	}
}

`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.email", "name", "Acceptance-Test-Email-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.email", "email.0.from",
						"Magic Password <password@example.com>"),
					resource.TestCheckResourceAttr("auth0_connection.email", "email.0.name", "Email OTP"),
					resource.TestCheckResourceAttr("auth0_connection.email", "email.0.subject", "Sign in!"),
					resource.TestCheckResourceAttr("auth0_connection.email", "email.0.syntax", "liquid"),
					resource.TestCheckResourceAttr("auth0_connection.email", "email.0.template", "<html><body><h1>Here's your password!</h1></body></html>"),
					resource.TestCheckResourceAttr("auth0_connection.email", "email.0.brute_force_protection",
						"true"),
					resource.TestCheckResourceAttr("auth0_connection.email", "email.0.totp.#", "1"),
					resource.TestCheckResourceAttr("auth0_connection.email", "email.0.totp.0.time_step", "300"),
					resource.TestCheckResourceAttr("auth0_connection.email", "email.0.totp.0.length", "6"),
				),
			},
		},
	})
}

func TestAccConnection_GoogleOAuth2(t *testing.T) {
	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "google_oauth2" {
	name = "Acceptance-Test-Google-OAuth2-{{.random}}"
	is_domain_connection = false
	google_oauth2 {
		client_id = "foo"
		client_secret = "bar"
		allowed_audiences = [ "example.com", "api.example.com" ]		
		set_user_root_attributes = "on_each_login"
		non_persistent_attrs = ["foo", "bar"]
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.google_oauth2", "name", "Acceptance-Test-Google-OAuth2-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.google_oauth2", "google_oauth2.0.client_id", "foo"),
					resource.TestCheckResourceAttr("auth0_connection.google_oauth2", "google_oauth2.0.client_secret", "bar"),
					resource.TestCheckResourceAttr("auth0_connection.google_oauth2", "google_oauth2.0.allowed_audiences.#", "2"),
					resource.TestCheckResourceAttr("auth0_connection.google_oauth2", "google_oauth2.0.allowed_audiences.1",
						"example.com"),
					resource.TestCheckResourceAttr("auth0_connection.google_oauth2", "google_oauth2.0.allowed_audiences.0",
						"api.example.com"),
					resource.TestCheckResourceAttr("auth0_connection.google_oauth2", "google_oauth2.0.set_user_root_attributes", "on_each_login"),
					resource.TestCheckResourceAttr("auth0_connection.google_oauth2",
						"google_oauth2.0.non_persistent_attrs.0", "bar"),
					resource.TestCheckResourceAttr("auth0_connection.google_oauth2",
						"google_oauth2.0.non_persistent_attrs.1", "foo"),
				),
			},
		},
	})
}

func TestAccConnection_Facebook(t *testing.T) {

	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "facebook" {
	name = "Acceptance-Test-Facebook-{{.random}}"
	is_domain_connection = false
	facebook {
		client_id = "client_id"
		client_secret = "client_secret"
		set_user_root_attributes = "on_each_login"
		non_persistent_attrs = ["foo", "bar"]
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.facebook", "name", "Acceptance-Test-Facebook-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.facebook", "facebook.0.client_id", "client_id"),
					resource.TestCheckResourceAttr("auth0_connection.facebook", "facebook.0.client_secret", "client_secret"),
					resource.TestCheckResourceAttr("auth0_connection.facebook", "facebook.0.set_user_root_attributes", "on_each_login"),
					resource.TestCheckResourceAttr("auth0_connection.facebook",
						"facebook.0.non_persistent_attrs.0", "bar"),
					resource.TestCheckResourceAttr("auth0_connection.facebook",
						"facebook.0.non_persistent_attrs.1", "foo"),
				),
			},
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "facebook" {
	name = "Acceptance-Test-Facebook-{{.random}}"
	is_domain_connection = false
	facebook {
		client_id = "client_id_update"
		client_secret = "client_secret_update"
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.facebook", "name", "Acceptance-Test-Facebook-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.facebook", "facebook.0.client_id", "client_id_update"),
					resource.TestCheckResourceAttr("auth0_connection.facebook", "facebook.0.client_secret", "client_secret_update"),
				),
			},
		},
	})
}

func TestAccConnection_Apple(t *testing.T) {
	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "apple" {
	name = "Acceptance-Test-Apple-{{.random}}"
	is_domain_connection = false
	apple {
		client_id = "client_id"
		client_secret = "-----BEGIN PRIVATE KEY-----\nMIHBAgEAMA0GCSqGSIb3DQEBAQUABIGsMIGpAgEAAiEA3+luhVHxSJ8cv3VNzQDP\nEL6BPs7FjBq4oro0MWM+QJMCAwEAAQIgWbq6/pRK4/ZXV+ZTSj7zuxsWZuK5i3ET\nfR2TCEkZR3kCEQD2ElqDr/pY5aHA++9HioY9AhEA6PIxC1c/K3gJqu+K+EsfDwIQ\nG5MS8Y7Wzv9skOOqfKnZQQIQdG24vaZZ2GwiyOD5YKiLWQIQYNtrb3j0BWsT4LI+\nN9+l1g==\n-----END PRIVATE KEY-----"
		team_id = "team_id"
		key_id = "key_id"
		set_user_root_attributes = "on_each_login"
		non_persistent_attrs = ["foo", "bar"]
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.apple", "name", "Acceptance-Test-Apple-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.apple", "apple.0.client_id", "client_id"),
					resource.TestCheckResourceAttr("auth0_connection.apple", "apple.0.client_secret", "-----BEGIN PRIVATE KEY-----\nMIHBAgEAMA0GCSqGSIb3DQEBAQUABIGsMIGpAgEAAiEA3+luhVHxSJ8cv3VNzQDP\nEL6BPs7FjBq4oro0MWM+QJMCAwEAAQIgWbq6/pRK4/ZXV+ZTSj7zuxsWZuK5i3ET\nfR2TCEkZR3kCEQD2ElqDr/pY5aHA++9HioY9AhEA6PIxC1c/K3gJqu+K+EsfDwIQ\nG5MS8Y7Wzv9skOOqfKnZQQIQdG24vaZZ2GwiyOD5YKiLWQIQYNtrb3j0BWsT4LI+\nN9+l1g==\n-----END PRIVATE KEY-----"),
					resource.TestCheckResourceAttr("auth0_connection.apple", "apple.0.team_id", "team_id"),
					resource.TestCheckResourceAttr("auth0_connection.apple", "apple.0.key_id", "key_id"),
					resource.TestCheckResourceAttr("auth0_connection.apple", "apple.0.set_user_root_attributes", "on_each_login"),
					resource.TestCheckResourceAttr("auth0_connection.apple",
						"apple.0.non_persistent_attrs.0", "bar"),
					resource.TestCheckResourceAttr("auth0_connection.apple",
						"apple.0.non_persistent_attrs.1", "foo"),
				),
			},
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "apple" {
	name = "Acceptance-Test-Apple-{{.random}}"
	is_domain_connection = false
	apple {
		client_id = "client_id"
		client_secret = "-----BEGIN PRIVATE KEY-----\nMIHBAgEAMA0GCSqGSIb3DQEBAQUABIGsMIGpAgEAAiEA3+luhVHxSJ8cv3VNzQDP\nEL6BPs7FjBq4oro0MWM+QJMCAwEAAQIgWbq6/pRK4/ZXV+ZTSj7zuxsWZuK5i3ET\nfR2TCEkZR3kCEQD2ElqDr/pY5aHA++9HioY9AhEA6PIxC1c/K3gJqu+K+EsfDwIQ\nG5MS8Y7Wzv9skOOqfKnZQQIQdG24vaZZ2GwiyOD5YKiLWQIQYNtrb3j0BWsT4LI+\nN9+l1g==\n-----END PRIVATE KEY-----"
		team_id = "team_id_update"
		key_id = "key_id_update"
		set_user_root_attributes = "on_first_login"
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_connection.apple", "apple.0.team_id", "team_id_update"),
					resource.TestCheckResourceAttr("auth0_connection.apple", "apple.0.key_id", "key_id_update"),
					resource.TestCheckResourceAttr("auth0_connection.apple", "apple.0.set_user_root_attributes", "on_first_login"),
				),
			},
		},
	})
}

func TestAccConnection_Linkedin(t *testing.T) {
	rand := random.String(6)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "linkedin" {
	name = "Acceptance-Test-Linkedin-{{.random}}"
	is_domain_connection = false
	linkedin {
		client_id = "client_id"
		client_secret = "client_secret"
		strategy_version = 2
		set_user_root_attributes = "on_each_login"
		non_persistent_attrs = ["foo", "bar"]
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.linkedin", "name", "Acceptance-Test-Linkedin-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.linkedin", "linkedin.0.client_id", "client_id"),
					resource.TestCheckResourceAttr("auth0_connection.linkedin", "linkedin.0.client_secret", "client_secret"),
					resource.TestCheckResourceAttr("auth0_connection.linkedin", "linkedin.0.strategy_version", "2"),
					resource.TestCheckResourceAttr("auth0_connection.linkedin", "linkedin.0.set_user_root_attributes", "on_each_login"),
					resource.TestCheckResourceAttr("auth0_connection.linkedin",
						"linkedin.0.non_persistent_attrs.0", "bar"),
					resource.TestCheckResourceAttr("auth0_connection.linkedin",
						"linkedin.0.non_persistent_attrs.1", "foo"),
				),
			},
			{
				// language=hcl
				Config: random.Template(`
resource "auth0_connection" "linkedin" {
	name = "Acceptance-Test-Linkedin-{{.random}}"
	is_domain_connection = false
	linkedin {
		client_id = "client_id_update"
		client_secret = "client_secret_update"
		strategy_version = 2
		set_user_root_attributes = "on_each_login"
		non_persistent_attrs = ["foo", "bar"]
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_connection.linkedin", "linkedin.0.client_id", "client_id_update"),
					resource.TestCheckResourceAttr("auth0_connection.linkedin", "linkedin.0.client_secret", "client_secret_update"),
				),
			},
		},
	})
}

func TestAccConnection_GitHub(t *testing.T) {
	rand := random.String(6)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=hcl
				Config: random.Template(`
resource "auth0_connection" "github" {
	name = "Acceptance-Test-GitHub-{{.random}}"
	github {
		client_id = "client-id"
		client_secret = "client-secret"
		set_user_root_attributes = "on_each_login"
		non_persistent_attrs = ["foo", "bar"]
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.github", "name", "Acceptance-Test-GitHub-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.github", "github.0.client_id", "client-id"),
					resource.TestCheckResourceAttr("auth0_connection.github", "github.0.client_secret", "client-secret"),
					resource.TestCheckResourceAttr("auth0_connection.github", "github.0.set_user_root_attributes", "on_each_login"),
					resource.TestCheckResourceAttr("auth0_connection.github",
						"github.0.non_persistent_attrs.0", "bar"),
					resource.TestCheckResourceAttr("auth0_connection.github",
						"github.0.non_persistent_attrs.1", "foo"),
				),
			},
		},
	})
}

func TestAccConnection_Windowslive(t *testing.T) {
	rand := random.String(6)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=hcl
				Config: random.Template(`
resource "auth0_connection" "windowslive" {
	name = "Acceptance-Test-Windowslive-{{.random}}"
	is_domain_connection = false
	windowslive {
		client_id = "client_id"
		client_secret = "client_secret"
		strategy_version = 2
		set_user_root_attributes = "on_each_login"
		non_persistent_attrs = ["foo", "bar"]
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.windowslive", "name", "Acceptance-Test-Windowslive-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.windowslive", "windowslive.0.client_id", "client_id"),
					resource.TestCheckResourceAttr("auth0_connection.windowslive", "windowslive.0.client_secret", "client_secret"),
					resource.TestCheckResourceAttr("auth0_connection.windowslive", "windowslive.0.strategy_version", "2"),
					resource.TestCheckResourceAttr("auth0_connection.windowslive", "windowslive.0.set_user_root_attributes", "on_each_login"),
					resource.TestCheckResourceAttr("auth0_connection.windowslive",
						"windowslive.0.non_persistent_attrs.0", "bar"),
					resource.TestCheckResourceAttr("auth0_connection.windowslive",
						"windowslive.0.non_persistent_attrs.1", "foo"),
				),
			},
			{
				// language=hcl
				Config: random.Template(`
resource "auth0_connection" "windowslive" {
	name = "Acceptance-Test-Windowslive-{{.random}}"
	is_domain_connection = false
	windowslive {
		client_id = "client_id_update"
		client_secret = "client_secret_update"
		strategy_version = 2
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.windowslive", "name", "Acceptance-Test-Windowslive-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.windowslive", "windowslive.0.client_id", "client_id_update"),
					resource.TestCheckResourceAttr("auth0_connection.windowslive", "windowslive.0.client_secret", "client_secret_update"),
					resource.TestCheckResourceAttr("auth0_connection.windowslive", "windowslive.0.strategy_version", "2"),
				),
			},
		},
	})
}

func TestAccConnection_Salesforce(t *testing.T) {
	rand := random.String(6)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "salesforce" {
	name = "Acceptance-Test-Salesforce-Connection-{{.random}}"
	is_domain_connection = false

	salesforce {		
		client_id = "client-id"
		client_secret = "client-secret"
		set_user_root_attributes = "on_each_login"
		non_persistent_attrs = ["foo", "bar"]
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.salesforce", "name", "Acceptance-Test-Salesforce-Connection-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.salesforce", "salesforce.0.client_id",
						"client-id"),
					resource.TestCheckResourceAttr("auth0_connection.salesforce", "salesforce.0.client_secret",
						"client-secret"),
					resource.TestCheckResourceAttr("auth0_connection.salesforce", "salesforce.0.set_user_root_attributes", "on_each_login"),
					resource.TestCheckResourceAttr("auth0_connection.salesforce",
						"salesforce.0.non_persistent_attrs.0", "bar"),
					resource.TestCheckResourceAttr("auth0_connection.salesforce",
						"salesforce.0.non_persistent_attrs.1", "foo"),
				),
			},
		},
	})
}

func TestAccConnection_Salesforce_Sandbox(t *testing.T) {
	rand := random.String(6)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "salesforce" {
	name = "Acceptance-Test-Salesforce-Connection-{{.random}}"
	is_domain_connection = false

	salesforce {		
		type = "sandbox"
		client_id = "client-id"
		client_secret = "client-secret"
		set_user_root_attributes = "on_each_login"
		non_persistent_attrs = ["foo", "bar"]
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.salesforce", "name", "Acceptance-Test-Salesforce-Connection-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.salesforce", "salesforce.0.client_id",
						"client-id"),
					resource.TestCheckResourceAttr("auth0_connection.salesforce", "salesforce.0.client_secret",
						"client-secret"),
					resource.TestCheckResourceAttr("auth0_connection.salesforce", "salesforce.0.set_user_root_attributes", "on_each_login"),
					resource.TestCheckResourceAttr("auth0_connection.salesforce",
						"salesforce.0.non_persistent_attrs.0", "bar"),
					resource.TestCheckResourceAttr("auth0_connection.salesforce",
						"salesforce.0.non_persistent_attrs.1", "foo"),
				),
			},
		},
	})
}

func TestAccConnection_Salesforce_Community(t *testing.T) {
	rand := random.String(6)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "salesforce" {
	name = "Acceptance-Test-Salesforce-Connection-{{.random}}"
	is_domain_connection = false

	salesforce {		
		type = "sandbox"
		client_id = "client-id"
		client_secret = "client-secret"
		set_user_root_attributes = "on_each_login"
		non_persistent_attrs = ["foo", "bar"]
		community_base_url = "http://google.com"
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.salesforce", "name", "Acceptance-Test-Salesforce-Connection-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.salesforce", "salesforce.0.client_id",
						"client-id"),
					resource.TestCheckResourceAttr("auth0_connection.salesforce", "salesforce.0.client_secret",
						"client-secret"),
					resource.TestCheckResourceAttr("auth0_connection.salesforce", "salesforce.0.set_user_root_attributes", "on_each_login"),
					resource.TestCheckResourceAttr("auth0_connection.salesforce", "salesforce.0.community_base_url", "http://google.com"),
					resource.TestCheckResourceAttr("auth0_connection.salesforce",
						"salesforce.0.non_persistent_attrs.0", "bar"),
					resource.TestCheckResourceAttr("auth0_connection.salesforce",
						"salesforce.0.non_persistent_attrs.1", "foo"),
				),
			},
		},
	})
}

func TestAccConnection_SMS(t *testing.T) {
	rand := random.String(6)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_connection" "sms" {
	name = "Acceptance-Test-SMS-{{.random}}"
	is_domain_connection = false

	sms {
		disable_signup = false
		name = "SMS OTP"
		twilio_sid = "ABC123"
		twilio_token = "DEF456"
		from = "+12345678"
		syntax = "md_with_macros"
		template = "@@password@@"
		messaging_service_sid = "GHI789"
		brute_force_protection = true

		totp {
			time_step = 300
			length = 6
		}
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.sms", "name", "Acceptance-Test-SMS-{{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_connection.sms", "sms.0.disable_signup", "false"),
					resource.TestCheckResourceAttr("auth0_connection.sms", "sms.0.name", "SMS OTP"),
					resource.TestCheckResourceAttr("auth0_connection.sms", "sms.0.twilio_sid", "ABC123"),
					resource.TestCheckResourceAttr("auth0_connection.sms", "sms.0.twilio_token", "DEF456"),
					resource.TestCheckResourceAttr("auth0_connection.sms", "sms.0.from", "+12345678"),
					resource.TestCheckResourceAttr("auth0_connection.sms", "sms.0.syntax", "md_with_macros"),
					resource.TestCheckResourceAttr("auth0_connection.sms", "sms.0.template", "@@password@@"),
					resource.TestCheckResourceAttr("auth0_connection.sms", "sms.0.messaging_service_sid", "GHI789"),
					resource.TestCheckResourceAttr("auth0_connection.sms", "sms.0.brute_force_protection",
						"true"),
					resource.TestCheckResourceAttr("auth0_connection.sms", "sms.0.totp.#", "1"),
					resource.TestCheckResourceAttr("auth0_connection.sms", "sms.0.totp.0.time_step", "300"),
					resource.TestCheckResourceAttr("auth0_connection.sms", "sms.0.totp.0.length", "6"),
				),
			},
		},
	})
}

func TestAccConnectionConfiguration(t *testing.T) {

	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`

resource "auth0_connection" "my_connection" {
	name = "Acceptance-Test-Connection-{{.random}}"
	is_domain_connection = true
	options {
		configuration = {
			foo = "xxx"
			bar = "zzz"
		}
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.configuration.%", "2"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.configuration.foo", "xxx"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.configuration.bar", "zzz"),
				),
			},
			{
				Config: random.Template(`

resource "auth0_connection" "my_connection" {
	name = "Acceptance-Test-Connection-{{.random}}"
	is_domain_connection = true
	options {
		configuration = {
			foo = "xxx"
			bar = "yyy"
			baz = "zzz"
		}
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.configuration.%", "3"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.configuration.foo", "xxx"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.configuration.bar", "yyy"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.configuration.baz", "zzz"),
				),
			},
		},
	})
}

func TestAccConnection_SAML(t *testing.T) {
	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`
resource "auth0_connection" "my_connection" {
	name = "Acceptance-Test-SAML-{{.random}}"
	display_name = "Acceptance-Test-SAML-{{.random}}"
	options {
		signing_cert = <<EOF
-----BEGIN CERTIFICATE-----
MIID6TCCA1ICAQEwDQYJKoZIhvcNAQEFBQAwgYsxCzAJBgNVBAYTAlVTMRMwEQYD
VQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRQwEgYDVQQK
EwtHb29nbGUgSW5jLjEMMAoGA1UECxMDRW5nMQwwCgYDVQQDEwNhZ2wxHTAbBgkq
hkiG9w0BCQEWDmFnbEBnb29nbGUuY29tMB4XDTA5MDkwOTIyMDU0M1oXDTEwMDkw
OTIyMDU0M1owajELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAf
BgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEjMCEGA1UEAxMaZXVyb3Bh
LnNmby5jb3JwLmdvb2dsZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQC6pgYt7/EibBDumASF+S0qvqdL/f+nouJw2T1Qc8GmXF/iiUcrsgzh/Fd8
pDhz/T96Qg9IyR4ztuc2MXrmPra+zAuSf5bevFReSqvpIt8Duv0HbDbcqs/XKPfB
uMDe+of7a9GCywvAZ4ZUJcp0thqD9fKTTjUWOBzHY1uNE4RitrhmJCrbBGXbJ249
bvgmb7jgdInH2PU7PT55hujvOoIsQW2osXBFRur4pF1wmVh4W4lTLD6pjfIMUcML
ICHEXEN73PDic8KS3EtNYCwoIld+tpIBjE1QOb1KOyuJBNW6Esw9ALZn7stWdYcE
qAwvv20egN2tEXqj7Q4/1ccyPZc3PQgC3FJ8Be2mtllM+80qf4dAaQ/fWvCtOrQ5
pnfe9juQvCo8Y0VGlFcrSys/MzSg9LJ/24jZVgzQved/Qupsp89wVidwIzjt+WdS
fyWfH0/v1aQLvu5cMYuW//C0W2nlYziL5blETntM8My2ybNARy3ICHxCBv2RNtPI
WQVm+E9/W5rwh2IJR4DHn2LHwUVmT/hHNTdBLl5Uhwr4Wc7JhE7AVqb14pVNz1lr
5jxsp//ncIwftb7mZQ3DF03Yna+jJhpzx8CQoeLT6aQCHyzmH68MrHHT4MALPyUs
Pomjn71GNTtDeWAXibjCgdL6iHACCF6Htbl0zGlG0OAK+bdn0QIDAQABMA0GCSqG
SIb3DQEBBQUAA4GBAOKnQDtqBV24vVqvesL5dnmyFpFPXBn3WdFfwD6DzEb21UVG
5krmJiu+ViipORJPGMkgoL6BjU21XI95VQbun5P8vvg8Z+FnFsvRFY3e1CCzAVQY
ZsUkLw2I7zI/dNlWdB8Xp7v+3w9sX5N3J/WuJ1KOO5m26kRlHQo7EzT3974g
-----END CERTIFICATE-----
EOF
		sign_in_endpoint = "https://saml.provider/sign_in"
		sign_out_endpoint = "https://saml.provider/sign_out"
		user_id_attribute = "https://saml.provider/imi/ns/identity-200810"
		tenant_domain = "example.com"
		domain_aliases = ["example.com", "example.coz"]
		protocol_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Post"
		request_template = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n@@AssertServiceURLAndDestination@@\n    ID=\"@@ID@@\"\n    IssueInstant=\"@@IssueInstant@@\"\n    ProtocolBinding=\"@@ProtocolBinding@@\" Version=\"2.0\">\n    <saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">@@Issuer@@</saml:Issuer>\n</samlp:AuthnRequest>"
		signature_algorithm = "rsa-sha256"
		digest_algorithm = "sha256"
		icon_url = "https://example.com/logo.svg"
		fields_map = {
			foo = "bar"
			baz = "baa"
		}
		idp_initiated {
			client_id = "client_id"
			client_protocol = "samlp"
			client_authorize_query = "type=code&timeout=30"
		}
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_connection.my_connection", "name", "Acceptance-Test-SAML-{{.random}}", rand),
					random.TestCheckResourceAttr("auth0_connection.my_connection", "display_name", "Acceptance-Test-SAML-{{.random}}", rand),
				),
			},
			{
				Config: random.Template(`
resource "auth0_connection" "my_connection" {
	name = "Acceptance-Test-SAML-{{.random}}"
	display_name = "Acceptance-Test-SAML-{{.random}}"
	options {
		signing_cert = <<EOF
-----BEGIN CERTIFICATE-----
MIID6TCCA1ICAQEwDQYJKoZIhvcNAQEFBQAwgYsxCzAJBgNVBAYTAlVTMRMwEQYD
VQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRQwEgYDVQQK
EwtHb29nbGUgSW5jLjEMMAoGA1UECxMDRW5nMQwwCgYDVQQDEwNhZ2wxHTAbBgkq
hkiG9w0BCQEWDmFnbEBnb29nbGUuY29tMB4XDTA5MDkwOTIyMDU0M1oXDTEwMDkw
OTIyMDU0M1owajELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAf
BgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEjMCEGA1UEAxMaZXVyb3Bh
LnNmby5jb3JwLmdvb2dsZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQC6pgYt7/EibBDumASF+S0qvqdL/f+nouJw2T1Qc8GmXF/iiUcrsgzh/Fd8
pDhz/T96Qg9IyR4ztuc2MXrmPra+zAuSf5bevFReSqvpIt8Duv0HbDbcqs/XKPfB
uMDe+of7a9GCywvAZ4ZUJcp0thqD9fKTTjUWOBzHY1uNE4RitrhmJCrbBGXbJ249
bvgmb7jgdInH2PU7PT55hujvOoIsQW2osXBFRur4pF1wmVh4W4lTLD6pjfIMUcML
ICHEXEN73PDic8KS3EtNYCwoIld+tpIBjE1QOb1KOyuJBNW6Esw9ALZn7stWdYcE
qAwvv20egN2tEXqj7Q4/1ccyPZc3PQgC3FJ8Be2mtllM+80qf4dAaQ/fWvCtOrQ5
pnfe9juQvCo8Y0VGlFcrSys/MzSg9LJ/24jZVgzQved/Qupsp89wVidwIzjt+WdS
fyWfH0/v1aQLvu5cMYuW//C0W2nlYziL5blETntM8My2ybNARy3ICHxCBv2RNtPI
WQVm+E9/W5rwh2IJR4DHn2LHwUVmT/hHNTdBLl5Uhwr4Wc7JhE7AVqb14pVNz1lr
5jxsp//ncIwftb7mZQ3DF03Yna+jJhpzx8CQoeLT6aQCHyzmH68MrHHT4MALPyUs
Pomjn71GNTtDeWAXibjCgdL6iHACCF6Htbl0zGlG0OAK+bdn0QIDAQABMA0GCSqG
SIb3DQEBBQUAA4GBAOKnQDtqBV24vVqvesL5dnmyFpFPXBn3WdFfwD6DzEb21UVG
5krmJiu+ViipORJPGMkgoL6BjU21XI95VQbun5P8vvg8Z+FnFsvRFY3e1CCzAVQY
ZsUkLw2I7zI/dNlWdB8Xp7v+3w9sX5N3J/WuJ1KOO5m26kRlHQo7EzT3974g
-----END CERTIFICATE-----
EOF
		sign_in_endpoint = "https://saml.provider/sign_in"
		sign_out_endpoint = ""
		tenant_domain = "example.com"
		domain_aliases = ["example.com", "example.coz"]
		protocol_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Post"
		signature_algorithm = "rsa-sha256"
		digest_algorithm = "sha256"
		fields_map = {
			foo = "bar"
			baz = "baa"
		}
		idp_initiated {
			client_id = "client_id"
			client_protocol = "samlp"
			client_authorize_query = "type=code&timeout=60"
		}
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.idp_initiated.0.client_authorize_query", "type=code&timeout=60"),
					resource.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.sign_out_endpoint", ""),
				),
			},
		},
	})
}

// disabled until we find a valid config
// func TestAccConnection_SAMLP_xml(t *testing.T) {
// 	rand := random.String(6)
//
// 	resource.Test(t, resource.TestCase{
// 		ProviderFactories: testAccProviderFactories,
// 		Steps: []resource.TestStep{
// 			{
// 				// language=HCL
// 				Config: random.Template(`
// resource "auth0_connection" "my_connection" {
// 	name = "Acceptance-Test-SAML-{{.random}}"
// 	strategy = "samlp"
// 	options {
// 		metadata_url = "https://auth0-provider-test.eu.auth0.com/samlp/metadata?connection=Username-Password-Authentication"
// 		//metadata_xml = "<xml>...</xml>"
// 	}
// }
// `, rand),
// 				Check: resource.ComposeAggregateTestCheckFunc(
// 					random.TestCheckResourceAttr("auth0_connection.my_connection", "name", "Acceptance-Test-SAML-{{.random}}", rand),
// 					resource.TestCheckResourceAttr("auth0_connection.my_connection", "strategy", "samlp"),
// 					random.TestCheckResourceAttr("auth0_connection.my_connection", "options.0.metadata_xml", "<xml>...</xml>", rand),
// 				),
// 			},
// 		},
// 	})
// }
