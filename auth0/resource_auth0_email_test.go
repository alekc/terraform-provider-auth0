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

func TestAccEmail_Common(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				// language=HCL
				Config: `
			    resource "auth0_email" "my_email_provider" {
			        enabled = true
			        default_from_address = "accounts@example.com"
			        mandrill {
			          api_key = "xxxxx"
			        }
			    }
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "enabled", "true"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "default_from_address", "accounts@example.com"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "mandrill.0.api_key",
						"xxxxx"),
				),
			},
			{
				// language=HCL
				Config: `
			    resource "auth0_email" "my_email_provider" {
			        enabled = true
			        default_from_address = "accounts@example.com"
			        ses {
			        	access_key_id = "xxxxx"
						secret_access_key = "xxxxxxx"
						region = "eu-west-2"
			        }
			    }
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "enabled", "true"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "default_from_address", "accounts@example.com"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "ses.0.access_key_id",
						"xxxxx"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "ses.0.secret_access_key",
						"xxxxxxx"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "ses.0.region",
						"eu-west-2"),
				),
			},
			{
				// language=HCL
				Config: `
			    resource "auth0_email" "my_email_provider" {
			        enabled = true
			        default_from_address = "accounts@example.com"
			        sendgrid {
			        	api_key = "xxxxx"
			        }
			    }
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "sendgrid.0.api_key",
						"xxxxx"),
				),
			},
			{
				// language=HCL
				Config: `
			    resource "auth0_email" "my_email_provider" {
			        enabled = true
			        default_from_address = "accounts@example.com"
			        sparkpost {
			        	api_key = "xxxxx"
						region = "eu"
			        }
			    }
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "sparkpost.0.api_key",
						"xxxxx"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "sparkpost.0.region",
						"eu"),
				),
			},
			{
				// language=HCL
				Config: `
			    resource "auth0_email" "my_email_provider" {
			        enabled = true
			        default_from_address = "accounts@example.com"
			        sparkpost {
			        	api_key = "xxxxx"
			        }
			    }
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "sparkpost.0.api_key",
						"xxxxx"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "sparkpost.0.region", ""),
				),
			},
			{
				// language=HCL
				Config: `
			    resource "auth0_email" "my_email_provider" {
			        enabled = true
			        default_from_address = "accounts@example.com"
			        mailgun {
			        	api_key = "xxxxx"
						domain = "example.com"
						region = "eu"
			        }
			    }
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "mailgun.0.api_key",
						"xxxxx"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "mailgun.0.region",
						"eu"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "mailgun.0.domain",
						"example.com"),
				),
			},
			{
				// language=HCL
				Config: `
			    resource "auth0_email" "my_email_provider" {
			        enabled = true
			        default_from_address = "accounts@example.com"
			        mailgun {
			        	api_key = "xxxxx"
						domain = "example.com"
			        }
			    }
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "mailgun.0.api_key",
						"xxxxx"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "mailgun.0.region", ""),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "mailgun.0.domain", "example.com"),
				),
			},
			{
				// language=HCL
				Config: `
                resource "auth0_email" "my_email_provider" {
                    enabled = true
                    default_from_address = "accounts@example.com"
                    smtp {
                    	host = "example.com"
						port = "22"
						user = "mail_user"
						pass = "qwerty"
                    }
                }
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "smtp.0.host", "example.com"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "smtp.0.port", "22"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "smtp.0.user", "mail_user"),
					resource.TestCheckResourceAttr("auth0_email.my_email_provider", "smtp.0.pass", "qwerty"),
				),
			},
		},
	})
}
