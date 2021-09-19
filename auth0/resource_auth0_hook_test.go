package auth0

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/random"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccHook_Common(t *testing.T) {
	// todo: move to parallel once the config has been randomized
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `

resource "auth0_hook" "my_hook" {
  name = "pre-user-reg-hook"
  script = "function (user, context, callback) { callback(null, { user }); }"
  trigger_id = "pre-user-registration"
  enabled = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "name", "pre-user-reg-hook"),
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "script", "function (user, context, callback) { callback(null, { user }); }"),
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "trigger_id", "pre-user-registration"),
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "enabled", "true"),
				),
			},
		},
	})
}

func TestAccHook_Secrets(t *testing.T) {
	rand := acctest.RandStringFromCharSet(6, acctest.CharSetAlpha)
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_hook" "my_hook" {
	name = "acceptance-test-{{.random}}"
	script = "function (user, context, callback) { callback(null, { user }); }"
	trigger_id = "pre-user-registration"
	secrets = {
		foo = "secret1"
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "script", "function (user, context, callback) { callback(null, { user }); }"),
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "trigger_id", "pre-user-registration"),
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "secrets.foo", "secret1"),
				),
			},
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_hook" "my_hook" {
	name = "acceptance-test-{{.random}}"
	script = "function (user, context, callback) { callback(null, { user }); }"
	trigger_id = "pre-user-registration"
	secrets = {
		foo = "secret2"
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "script", "function (user, context, callback) { callback(null, { user }); }"),
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "trigger_id", "pre-user-registration"),
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "secrets.foo", "secret2"),
				),
			},
			{
				// language=HCL
				Config: random.Template(`
resource "auth0_hook" "my_hook" {
	name = "acceptance-test-{{.random}}"
	script = "function (user, context, callback) { callback(null, { user }); }"
	trigger_id = "pre-user-registration"
	secrets = {
		foo = "secret2"
		bar = "secretnew"
	}
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "script", "function (user, context, callback) { callback(null, { user }); }"),
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "trigger_id", "pre-user-registration"),
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "secrets.foo", "secret2"),
					resource.TestCheckResourceAttr("auth0_hook.my_hook", "secrets.bar", "secretnew"),
				),
			},
		},
	})
}

func TestHookNameRegexp(t *testing.T) {
	for name, valid := range map[string]bool{
		"my-hook-1":                 true,
		"hook 2 name with spaces":   true,
		" hook with a space prefix": false,
		"hook with a space suffix ": false,
		" ":                         false,
		"   ":                       false,
	} {
		fn := validateHookNameFunc()

		_, errs := fn(name, "name")
		if errs != nil && valid {
			t.Fatalf("Expected %q to be valid, but got validation errors %v", name, errs)
		}

		if errs == nil && !valid {
			t.Fatalf("Expected %q to be invalid, but got no validation errors.", name)
		}
	}
}
