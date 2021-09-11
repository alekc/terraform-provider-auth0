package auth0

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccBranding(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "auth0_branding" "my_brand" {
	logo_url = "https://mycompany.org/v1/logo.png"
	favicon_url = "https://mycompany.org/favicon.ico"
	colors {
		primary = "#0059d6"
		page_background = "#000000"
	}
	font {
		url = "https://mycompany.org/font/myfont.ttf"
	}
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_branding.my_brand", "logo_url", "https://mycompany.org/v1/logo.png"),
					resource.TestCheckResourceAttr("auth0_branding.my_brand", "favicon_url", "https://mycompany.org/favicon.ico"),
					resource.TestCheckResourceAttr("auth0_branding.my_brand", "colors.0.primary", "#0059d6"),
					resource.TestCheckResourceAttr("auth0_branding.my_brand", "colors.0.page_background", "#000000"),
					resource.TestCheckResourceAttr("auth0_branding.my_brand", "font.0.url", "https://mycompany.org/font/myfont.ttf"),
				),
			},
			{
				Config: `
resource "auth0_branding" "my_brand" {
	logo_url = "https://mycompany.org/v2/logo.png"
	favicon_url = "https://mycompany.org/favicon.ico"
	colors {
		primary = "#ffa629"
		page_background = "#ffffff"
	}
	font {
		url = "https://mycompany.org/font/myfont.ttf"
	}
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("auth0_branding.my_brand", "logo_url", "https://mycompany.org/v2/logo.png"),
					resource.TestCheckResourceAttr("auth0_branding.my_brand", "favicon_url", "https://mycompany.org/favicon.ico"),
					resource.TestCheckResourceAttr("auth0_branding.my_brand", "colors.0.primary", "#ffa629"),
					resource.TestCheckResourceAttr("auth0_branding.my_brand", "colors.0.page_background", "#ffffff"),
					resource.TestCheckResourceAttr("auth0_branding.my_brand", "font.0.url", "https://mycompany.org/font/myfont.ttf"),
				),
			},
		},
	})
}
