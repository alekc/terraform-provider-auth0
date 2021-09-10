package auth0

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

func init() {
	resource.AddTestSweepers("auth0_email_template", &resource.Sweeper{
		Name: "auth0_email_template",
		F: func(_ string) (err error) {
			api := testAuth0ApiClient()
			err = api.EmailTemplate.Update("welcome_email", &management.EmailTemplate{
				Enabled: auth0.Bool(false),
			})
			return
		},
	})
}

func TestAccEmailTemplate(t *testing.T) {

	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
			
			resource "auth0_email" "my_email_provider" {
				name = "ses"
				enabled = true
				default_from_address = "accounts@example.com"
				credentials {
					access_key_id = "AKIAXXXXXXXXXXXXXXXX"
					secret_access_key = "7e8c2148xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
					region = "us-east-1"
				}
			}
			
			resource "auth0_email_template" "my_email_template" {
				template = "welcome_email"
				body = "<html><body><h1>Welcome!</h1></body></html>"
				from = "welcome@example.com"
				result_url = "https://example.com/welcome"
				subject = "Welcome"
				syntax = "liquid"
				url_lifetime_in_seconds = 3600
				enabled = true
			
				depends_on = ["auth0_email.my_email_provider"]
			}
			`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_email_template.my_email_template", "template", "welcome_email"),
					resource.TestCheckResourceAttr("auth0_email_template.my_email_template", "body", "<html><body><h1>Welcome!</h1></body></html>"),
					resource.TestCheckResourceAttr("auth0_email_template.my_email_template", "from", "welcome@example.com"),
					resource.TestCheckResourceAttr("auth0_email_template.my_email_template", "result_url", "https://example.com/welcome"),
					resource.TestCheckResourceAttr("auth0_email_template.my_email_template", "subject", "Welcome"),
					resource.TestCheckResourceAttr("auth0_email_template.my_email_template", "syntax", "liquid"),
					resource.TestCheckResourceAttr("auth0_email_template.my_email_template", "url_lifetime_in_seconds", "3600"),
					resource.TestCheckResourceAttr("auth0_email_template.my_email_template", "enabled", "true"),
				),
			},
		},
	})
}
