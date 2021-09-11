package auth0

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func init() {
	resource.AddTestSweepers("auth0_email", &resource.Sweeper{
		Name: "auth0_email",
		F: func(_ string) error {
			api := testAuth0ApiClient()
			return api.Email.Delete()
		},
	})
}

func TestAccEmail(t *testing.T) {
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
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "name", "ses"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "enabled", "true"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "default_from_address", "accounts@example.com"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "credentials.0.access_key_id", "AKIAXXXXXXXXXXXXXXXX"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "credentials.0.secret_access_key", "7e8c2148xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "credentials.0.region", "us-east-1"),
				),
			},
			{
				Config: `
				resource "auth0_email" "my_email_provider" {
					name = "ses"
					enabled = true
					default_from_address = "accounts@example.com"
					credentials {
						access_key_id = "AKIAXXXXXXXXXXXXXXXY"
						secret_access_key = "7e8c2148xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
						region = "us-east-1"
					}
				}
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "name", "ses"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "enabled", "true"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "default_from_address", "accounts@example.com"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "credentials.0.access_key_id", "AKIAXXXXXXXXXXXXXXXY"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "credentials.0.secret_access_key", "7e8c2148xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "credentials.0.region", "us-east-1"),
				),
			},
			{
				Config: `
				resource "auth0_email" "my_email_provider" {
					name = "mailgun"
					enabled = true
					default_from_address = "accounts@example.com"
					credentials {
						api_key = "MAILGUNXXXXXXXXXXXXXXX"
						domain = "example.com"
						region = "eu"
					}
				}
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "name", "mailgun"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "enabled", "true"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "default_from_address", "accounts@example.com"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "credentials.0.domain", "example.com"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "credentials.0.region", "eu"),
				),
			},
		},
	})
}
