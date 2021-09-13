package auth0

import (
	"log"
	"regexp"
	"testing"

	"github.com/hashicorp/go-multierror"
	"gopkg.in/auth0.v5/management"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/random"
)

func init() {
	resource.AddTestSweepers("auth0_user", &resource.Sweeper{
		Name: "auth0_user",
		F: func(_ string) error {
			api := testAuth0ApiClient()
			var page int
			for {
				l, err := api.User.Search(
					management.Page(page),
					management.Query(`email.domain:"acceptance.test.com"`))
				if err != nil {
					return err
				}
				for _, user := range l.Users {
					log.Printf("[DEBUG] ✗ %s", user.GetName())
					if e := api.User.Delete(user.GetID()); e != nil {
						_ = multierror.Append(err, e)
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

func TestAccUserMissingRequiredParams(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      "resource auth0_user user {}",
				ExpectError: regexp.MustCompile(`The argument "connection_name" is required`),
			},
		},
	})
}

func TestAccUser(t *testing.T) {

	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`

resource auth0_user user {
	connection_name = "Username-Password-Authentication"
	username = "{{.random}}"
	user_id = "{{.random}}"
	email = "{{.random}}@acceptance.test.com"
	password = "passpass$12$12"
	name = "Firstname Lastname"
	given_name = "Firstname"
	family_name = "Lastname"
	nickname = "{{.random}}"
	picture = "https://www.example.com/picture.jpg"
	user_metadata = <<EOF
{
  "foo": "bar",
  "bar": { "baz": "qux" }
}
EOF
	app_metadata = <<EOF
{
  "foo": "bar",
  "bar": { "baz": "qux" }
}
EOF
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_user.user", "user_id", "auth0|{{.random}}", rand),
					random.TestCheckResourceAttr("auth0_user.user", "email", "{{.random}}@acceptance.test.com", rand),
					resource.TestCheckResourceAttr("auth0_user.user", "name", "Firstname Lastname"),
					resource.TestCheckResourceAttr("auth0_user.user", "family_name", "Lastname"),
					resource.TestCheckResourceAttr("auth0_user.user", "given_name", "Firstname"),
					resource.TestCheckResourceAttr("auth0_user.user", "nickname", rand),
					resource.TestCheckResourceAttr("auth0_user.user", "connection_name", "Username-Password-Authentication"),
					resource.TestCheckResourceAttr("auth0_user.user", "roles.#", "0"),
					resource.TestCheckResourceAttr("auth0_user.user", "picture", "https://www.example.com/picture.jpg"),
				),
			},
			{
				Config: random.Template(`

resource auth0_user user {
	connection_name = "Username-Password-Authentication"
	username = "{{.random}}"
	user_id = "{{.random}}"
	email = "{{.random}}@acceptance.test.com"
	password = "passpass$12$12"
	name = "Firstname Lastname"
	given_name = "Firstname"
	family_name = "Lastname"
	nickname = "{{.random}}"
	picture = "https://www.example.com/picture.jpg"
	roles = [ auth0_role.owner.id, auth0_role.admin.id ]
	user_metadata = <<EOF
{
  "foo": "bar",
  "bar": { "baz": "qux" }
}
EOF
app_metadata = <<EOF
{
  "foo": "bar",
  "bar": { "baz": "qux" }
}
EOF
}

resource auth0_role owner {
	name = "owner"
	description = "Owner"
}

resource auth0_role admin {
	name = "admin"
	description = "Administrator"
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_user.user", "roles.#", "2"),
					resource.TestCheckResourceAttr("auth0_role.owner", "name", "owner"),
					resource.TestCheckResourceAttr("auth0_role.admin", "name", "admin"),
				),
			},
			{
				Config: random.Template(`

resource auth0_user user {
	connection_name = "Username-Password-Authentication"
	username = "{{.random}}"
	user_id = "{{.random}}"
	email = "{{.random}}@acceptance.test.com"
	password = "passpass$12$12"
	name = "Firstname Lastname"
	given_name = "Firstname"
	family_name = "Lastname"
	nickname = "{{.random}}"
	picture = "https://www.example.com/picture.jpg"
	roles = [ auth0_role.admin.id ]
	user_metadata = <<EOF
{
  	"foo": "bar",
  	"bar": { "baz": "qux" }
}
EOF
  app_metadata = <<EOF
{
  	"foo": "bar",
  	"bar": { "baz": "qux" }
}
EOF
}

resource auth0_role admin {
	name = "admin"
	description = "Administrator"
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_user.user", "roles.#", "1"),
				),
			},
		},
	})
}

func TestAccUserIssue218(t *testing.T) {

	rand := random.String(6)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`

resource auth0_user auth0_user_issue_218 {
  connection_name = "Username-Password-Authentication"
  user_id = "id_{{.random}}"
  username = "user_{{.random}}"
  email = "issue.218.{{.random}}@acceptance.test.com"
  email_verified = true
  password = "MyPass123$"
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_user.auth0_user_issue_218", "user_id", "auth0|id_{{.random}}", rand),
					random.TestCheckResourceAttr("auth0_user.auth0_user_issue_218", "username", "user_{{.random}}", rand),
					random.TestCheckResourceAttr("auth0_user.auth0_user_issue_218", "email", "issue.218.{{.random}}@acceptance.test.com", rand),
				),
			},
			{
				Config: random.Template(`

resource auth0_user auth0_user_issue_218 {
  connection_name = "Username-Password-Authentication"
  user_id = "id_{{.random}}"
  username = "user_{{.random}}"
  email = "issue.218.{{.random}}@acceptance.test.com"
  email_verified = true
  password = "MyPass123$"
}
`, rand),
			},
		},
	})
}

func TestAccUserChangeUsername(t *testing.T) {

	rand := random.String(4)

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`

resource auth0_user auth0_user_change_username {
  connection_name = "Username-Password-Authentication"
  username = "user_{{.random}}"
  email = "change.username.{{.random}}@acceptance.test.com"
  email_verified = true
  password = "MyPass123$"
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_user.auth0_user_change_username", "username", "user_{{.random}}", rand),
					random.TestCheckResourceAttr("auth0_user.auth0_user_change_username", "email", "change.username.{{.random}}@acceptance.test.com", rand),
					resource.TestCheckResourceAttr("auth0_user.auth0_user_change_username", "password", "MyPass123$"),
				),
			},
			{
				Config: random.Template(`

resource auth0_user auth0_user_change_username {
  connection_name = "Username-Password-Authentication"
  username = "user_x_{{.random}}"
  email = "change.username.{{.random}}@acceptance.test.com"
  email_verified = true
  password = "MyPass123$"
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_user.auth0_user_change_username", "username", "user_x_{{.random}}", rand),
					random.TestCheckResourceAttr("auth0_user.auth0_user_change_username", "email", "change.username.{{.random}}@acceptance.test.com", rand),
					resource.TestCheckResourceAttr("auth0_user.auth0_user_change_username", "password", "MyPass123$"),
				),
			},
			{
				Config: random.Template(`

resource auth0_user auth0_user_change_username {
  connection_name = "Username-Password-Authentication"
  username = "user_{{.random}}"
  email = "change.username.{{.random}}@acceptance.test.com"
  email_verified = true
  password = "MyPass123456$"
}
`, rand),
				ExpectError: regexp.MustCompile("Cannot update username and password simultaneously"),
			},
		},
	})
}
