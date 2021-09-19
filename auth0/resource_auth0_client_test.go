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
	resource.AddTestSweepers("auth0_client", &resource.Sweeper{
		Name: "auth0_client",
		F: func(_ string) error {
			api := testAuth0ApiClient()
			var page int
			for {
				l, err := api.Client.List(management.Page(page))
				if err != nil {
					return err
				}
				for _, client := range l.Clients {
					log.Printf("[DEBUG] ➝ %s", client.GetName())
					if strings.Contains(client.GetName(), "Test") {
						if e := api.Client.Delete(client.GetClientID()); e != nil {
							_ = multierror.Append(err, e)
						}
						log.Printf("[DEBUG] ✗ %s", client.GetName())
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

func TestAccClient_Common(t *testing.T) {

	rand := random.String(6)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`

resource "auth0_client" "my_client" {
  name = "Acceptance Test - {{.random}}"
  description = "Test Application Long Description"
  app_type = "non_interactive"
  custom_login_page_on = true
  is_first_party = true
  is_token_endpoint_ip_header_trusted = true
  token_endpoint_auth_method = "client_secret_post"
  oidc_conformant = true
  callbacks = [ "https://example.com/callback" ]
  allowed_origins = [ "https://example.com" ]
  allowed_clients = [ "https://allowed.example.com" ]
  grant_types = [ "authorization_code", "http://auth0.com/oauth/grant-type/password-realm", "implicit", "password", "refresh_token" ]
  allowed_logout_urls = [ "https://example.com" ]
  web_origins = [ "https://example.com" ]
  jwt_configuration {
    lifetime_in_seconds = 300
    secret_encoded = true
    alg = "RS256"
    scopes = {
      foo = "bar"
    }
  }
  client_metadata = {
    foo = "zoo"
  }
   addons { 
     samlp {
       audience = "https://example.com/saml"
       recipient = "http://foo"
       mappings = {
         email = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
         name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
       }
       create_upn_claim = false
       passthrough_claims_with_no_mapping = false
       map_unknown_claims_as_is = false
       map_identities = false
       signature_algorithm = "rsa-sha1"
       digest_algorithm = "sha1"
       destination = "http://foo"
       lifetime_in_seconds = 180
       sign_response = false
       typed_attributes = false
       include_attribute_name_format = true
       name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
       name_identifier_probes = [
         "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
       ]
       logout {
         callback = "http://example.com/callback"
         slo_enabled = true
       }
	   signing_cert = "fakecertificate"
       binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
     }
   }
  refresh_token {
    leeway = 42
    token_lifetime = 424242
    rotation_type = "rotating"
    expiration_type = "expiring"
    infinite_token_lifetime = true
    infinite_idle_token_lifetime = false
    idle_token_lifetime = 3600
  }
  mobile {
    ios {
      team_id = "9JA89QQLNQ"
      app_bundle_identifier = "com.my.bundle.id"
    }
  }
  initiate_login_uri = "https://example.com/login"
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_client.my_client", "name", "Acceptance Test - {{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_client.my_client", "is_token_endpoint_ip_header_trusted", "true"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "token_endpoint_auth_method", "client_secret_post"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "refresh_token.#", "1"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "refresh_token.0.leeway", "42"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "refresh_token.0.token_lifetime", "424242"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "refresh_token.0.rotation_type", "rotating"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "refresh_token.0.expiration_type", "expiring"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "refresh_token.0.infinite_token_lifetime", "true"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "refresh_token.0.infinite_idle_token_lifetime", "false"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "refresh_token.0.idle_token_lifetime", "3600"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "allowed_clients.0", "https://allowed.example.com"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.#", "1"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.#", "1"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.audience", "https://example.com/saml"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.recipient", "http://foo"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.mappings.email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.mappings.name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.create_upn_claim", "false"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.passthrough_claims_with_no_mapping", "false"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.map_unknown_claims_as_is", "false"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.map_identities", "false"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.signature_algorithm", "rsa-sha1"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.digest_algorithm", "sha1"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.destination", "http://foo"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.lifetime_in_seconds", "180"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.sign_response", "false"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.typed_attributes", "false"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.include_attribute_name_format", "true"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.name_identifier_format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.name_identifier_probes.0", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.logout.0.callback", "http://example.com/callback"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.logout.0.slo_enabled", "true"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.signing_cert", "fakecertificate"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "addons.0.samlp.0.binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "client_metadata.foo", "zoo"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "initiate_login_uri", "https://example.com/login"),
				),
			},
		},
	})
}

func TestAccClientZeroValueCheck(t *testing.T) {

	rand := random.String(6)

	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`

resource "auth0_client" "my_client" {
  name = "Acceptance Test - Zero Value Check - {{.random}}"
  is_first_party = false
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_client.my_client", "name", "Acceptance Test - Zero Value Check - {{.random}}", rand),
					resource.TestCheckResourceAttr("auth0_client.my_client", "is_first_party", "false"),
				),
			},
			{
				Config: random.Template(`

resource "auth0_client" "my_client" {
  name = "Acceptance Test - Zero Value Check - {{.random}}"
  is_first_party = true
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_client.my_client", "is_first_party", "true"),
				),
			},
			{
				Config: random.Template(`

resource "auth0_client" "my_client" {
  name = "Acceptance Test - Zero Value Check - {{.random}}"
  is_first_party = false
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_client.my_client", "is_first_party", "false"),
				),
			},
		},
	})
}

func TestAccClientRotateSecret(t *testing.T) {

	rand := random.String(6)

	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`

resource "auth0_client" "my_client" {
  name = "Acceptance Test - Rotate Secret - {{.random}}"
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_client.my_client", "name", "Acceptance Test - Rotate Secret - {{.random}}", rand),
				),
			},
			{
				Config: random.Template(`

resource "auth0_client" "my_client" {
  name = "Acceptance Test - Rotate Secret - {{.random}}"
  client_secret_rotation_trigger = {
    triggered_at = "2018-01-02T23:12:01Z"
    triggered_by = "alex"
  }
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_client.my_client", "client_secret_rotation_trigger.triggered_at", "2018-01-02T23:12:01Z"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "client_secret_rotation_trigger.triggered_by", "alex"),
				),
			},
		},
	})
}

func TestAccClientInitiateLoginUri(t *testing.T) {

	rand := random.String(6)

	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`
resource "auth0_client" "my_client" {
  name = "Acceptance Test - Initiate Login URI - {{.random}}"
  initiate_login_uri = "http://example.com/login"
}
`, rand),
				ExpectError: regexp.MustCompile("to have a url with schema"),
			},
			{
				Config: random.Template(`

resource "auth0_client" "my_client" {
  name = "Acceptance Test - Initiate Login URI - {{.random}}"
  initiate_login_uri = "https://example.com/login#fragment"
}
`, rand),
				ExpectError: regexp.MustCompile("to have a url with an empty fragment"),
			},
		},
	})
}

func TestAccClientJwtScopes(t *testing.T) {

	rand := random.String(6)

	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`

resource "auth0_client" "my_client" {
  name = "Acceptance Test - JWT Scopes - {{.random}}"
  jwt_configuration {
    lifetime_in_seconds = 300
    secret_encoded = true
    alg = "RS256"
    scopes = {}
  }
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_client.my_client", "jwt_configuration.#", "1"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "jwt_configuration.0.secret_encoded", "true"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "jwt_configuration.0.lifetime_in_seconds", "300"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "jwt_configuration.0.scopes.%", "0"),
				),
			},
			{
				Config: random.Template(`

resource "auth0_client" "my_client" {
  name = "Acceptance Test - JWT Scopes - {{.random}}"
  jwt_configuration {
    lifetime_in_seconds = 300
    secret_encoded = true
    alg = "RS256"
    scopes = {
		foo = "bar"
	}
  }
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_client.my_client", "jwt_configuration.#", "1"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "jwt_configuration.0.alg", "RS256"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "jwt_configuration.0.lifetime_in_seconds", "300"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "jwt_configuration.0.scopes.%", "1"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "jwt_configuration.0.scopes.foo", "bar"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "jwt_configuration.0.secret_encoded", "true"),
				),
			},
		},
	})
}

func TestAccClientMobile(t *testing.T) {

	rand := random.String(6)

	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`

resource "auth0_client" "my_client" {
  name = "Acceptance Test - Mobile - {{.random}}"
  mobile {
    android {
      app_package_name = "com.example"
      sha256_cert_fingerprints = ["DE:AD:BE:EF"]
    }
  }
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_client.my_client", "mobile.0.android.#", "1"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "mobile.0.android.0.app_package_name", "com.example"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "mobile.0.android.0.sha256_cert_fingerprints.#", "1"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "mobile.0.android.0.sha256_cert_fingerprints.0", "DE:AD:BE:EF"),
				),
			},
			{
				Config: random.Template(`

resource "auth0_client" "my_client" {
  name = "Acceptance Test - Mobile - {{.random}}"
  mobile {
    android {
      app_package_name = "com.example"
      sha256_cert_fingerprints = []
    }
  }
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_client.my_client", "mobile.0.android.#", "1"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "mobile.0.android.0.app_package_name", "com.example"),
					resource.TestCheckResourceAttr("auth0_client.my_client", "mobile.0.android.0.sha256_cert_fingerprints.#", "0"),
				),
			},
		},
	})
}

func TestAccClientMobileValidationError(t *testing.T) {

	rand := random.String(6)

	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`

resource "auth0_client" "my_client" {
  name = "Acceptance Test - Mobile - {{.random}}"
  mobile {
    android {
      # nothing specified, should throw validation error
    }
  }
}
`, rand),
				ExpectError: regexp.MustCompile("Missing required argument"),
			},
		},
	})
}
