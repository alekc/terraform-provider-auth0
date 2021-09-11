package auth0

import (
	"log"
	"strings"
	"testing"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/random"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func init() {
	resource.AddTestSweepers("auth0_custom_domain", &resource.Sweeper{
		Name: "auth0_custom_domain",
		F: func(_ string) error {
			api := testAuth0ApiClient()
			domains, err := api.CustomDomain.List()
			if err != nil {
				if err.Error() == "403 Forbidden: The account is not allowed to perform this operation, please contact our support team" {
					// we are not premium, so its safe to skip this one.
					return nil
				}
				return err
			}
			for _, domain := range domains {
				log.Printf("[DEBUG] ➝ %s", domain.GetDomain())
				if strings.Contains(domain.GetDomain(), "auth.uat.alexkappa.com") {
					if e := api.CustomDomain.Delete(domain.GetID()); e != nil {
						_ = multierror.Append(err, e)
					}
					log.Printf("[DEBUG] ✗ %s", domain.GetDomain())
				}
			}
			return nil
		},
	})
}

func TestAccCustomDomain(t *testing.T) {

	rand := random.String(6)

	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: random.Template(`

resource "auth0_custom_domain" "my_custom_domain" {
  domain = "{{.random}}.auth.uat.alexkappa.com"
  type = "auth0_managed_certs"
  verification_method = "txt"
}
`, rand),
				Check: resource.ComposeAggregateTestCheckFunc(
					random.TestCheckResourceAttr("auth0_custom_domain.my_custom_domain", "domain", "{{.random}}.auth.uat.alexkappa.com", rand),
					resource.TestCheckResourceAttr("auth0_custom_domain.my_custom_domain", "type", "auth0_managed_certs"),
					resource.TestCheckResourceAttr("auth0_custom_domain.my_custom_domain", "status", "pending_verification"),
				),
			},
		},
		ErrorCheck: func(err error) error {
			// if we are not a premium account, we cannot run this test, so let's just ignore it for time being
			if strings.Contains(err.Error(), "The account is not allowed to perform this operation") {
				return nil
			}
			return err
		},
	})
}
