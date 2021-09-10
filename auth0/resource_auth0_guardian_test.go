package auth0

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccGuardian(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "auth0_guardian" "foo" {
  policy = "all-applications"
  phone {
	provider = "twilio"
	message_types = ["sms"]
	options {
		enrollment_message = "enroll foo"
		verification_message = "verify foo"
		from = "from bar"
		messaging_service_sid = "foo"
		auth_token = "bar"
		sid = "foo"
	}
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_guardian.foo", "policy", "all-applications"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.message_types.0", "sms"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.provider", "twilio"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.enrollment_message", "enroll foo"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.verification_message", "verify foo"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.from", "from bar"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.messaging_service_sid", "foo"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.auth_token", "bar"),
				),
			},
			{
				Config: `

resource "auth0_guardian" "foo" {
  policy = "all-applications"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_guardian.foo", "policy", "all-applications"),
					resource.TestCheckNoResourceAttr("auth0_guardian.foo", "phone"),
				),
			},

			{
				Config: `

resource "auth0_guardian" "foo" {
  policy = "all-applications"
  phone {
	provider = "twilio"
	message_types = ["sms"]
	options {
		enrollment_message = "enroll foo"
		verification_message = "verify foo"
		from = "from bar"
		messaging_service_sid = "foo"
		auth_token = "bar"
		sid = "foo"
	}
}
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_guardian.foo", "policy", "all-applications"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.message_types.0", "sms"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.provider", "twilio"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.enrollment_message", "enroll foo"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.verification_message", "verify foo"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.from", "from bar"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.messaging_service_sid", "foo"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.auth_token", "bar"),
				),
			},

			{
				Config: `

resource "auth0_guardian" "foo" {
  policy = "all-applications"
  phone {
	provider = "phone-message-hook"
	message_types = ["sms"]
	options{
	}
	}
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_guardian.foo", "policy", "all-applications"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.message_types.0", "sms"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.provider", "phone-message-hook"),
				),
			},

			{
				Config: `
resource "auth0_guardian" "foo" {
  policy = "all-applications"
  phone {
    provider = "auth0"
    message_types = ["voice"]
    options {
      enrollment_message = "enroll foo"
      verification_message = "verify foo"
    }
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_guardian.foo", "policy", "all-applications"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.message_types.0", "voice"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.provider", "auth0"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.enrollment_message", "enroll foo"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.verification_message", "verify foo"),
				),
			},

			{
				Config: `

resource "auth0_guardian" "foo" {
  policy = "all-applications"
  phone {
	provider = "auth0"
	message_types = ["voice"]
	options {
		enrollment_message = "enroll foo"
		verification_message = "verify foo"
	}
}
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_guardian.foo", "policy", "all-applications"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.message_types.0", "voice"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.provider", "auth0"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.enrollment_message", "enroll foo"),
					resource.TestCheckResourceAttr("auth0_guardian.foo", "phone.0.options.0.verification_message", "verify foo"),
				),
			},

			{
				Config: `

resource "auth0_guardian" "foo" {
  policy = "all-applications"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_guardian.foo", "policy", "all-applications"),
					resource.TestCheckNoResourceAttr("auth0_guardian.foo", "phone"),
				),
			},
		},
	})
}
