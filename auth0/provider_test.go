package auth0

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"gopkg.in/auth0.v5/management"
)

// Use other testAccProviderFactories functions, such as testAccProviderFactoriesAlternate,
// for tests requiring special provider configurations.
var testAccProviderFactories map[string]func() (*schema.Provider, error)

var testAccProviders map[string]*schema.Provider
var testAccProvider *schema.Provider

func init() {
	testAccProvider = Provider()
	testAccProviders = map[string]*schema.Provider{
		"auth0": testAccProvider,
	}
	testAccProviderFactories = map[string]func() (*schema.Provider, error){
		"auth0": func() (*schema.Provider, error) {
			return Provider(), nil
		},
	}
}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ *schema.Provider = Provider()
}

func testAccPreCheck(t *testing.T) {
	if err := os.Getenv("AUTH0_DOMAIN"); err == "" {
		t.Fatal("AUTH0_DOMAIN must be set for acceptance tests")
	}
	if err := os.Getenv("AUTH0_CLIENT_ID"); err == "" {
		t.Fatal("AUTH0_CLIENT_ID must be set for acceptance tests")
	}
	if err := os.Getenv("AUTH0_CLIENT_SECRET"); err == "" {
		t.Fatal("AUTH0_CLIENT_SECRET must be set for acceptance tests")
	}
}

func testAuth0ApiClient() *management.Management {
	api, err := management.New(os.Getenv("AUTH0_DOMAIN"),
		management.WithClientCredentials(os.Getenv("AUTH0_CLIENT_ID"), os.Getenv("AUTH0_CLIENT_SECRET")))
	if err != nil {
		panic("Cannot init sweeper client")
	}
	return api
}

func TestProvider_debugDefaults(t *testing.T) {
	for value, expected := range map[string]bool{
		"1":     true,
		"true":  true,
		"on":    true,
		"0":     false,
		"off":   false,
		"false": false,
		"foo":   false,
		"":      false,
	} {
		_ = os.Unsetenv("AUTH0_DEBUG")
		if value != "" {
			_ = os.Setenv("AUTH0_DEBUG", value)
		}

		p := Provider()
		debug, err := p.Schema["debug"].DefaultValue()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if debug.(bool) != expected {
			t.Fatalf("Expected debug to be %v, but got %v", expected, debug)
		}
	}
}
