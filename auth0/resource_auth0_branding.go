package auth0

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"gopkg.in/auth0.v5/management"
)

func newBranding() *schema.Resource {
	return &schema.Resource{
		Description: `With Auth0, you can setting logo, color to maintain a consistent service brand. 
This resource allows you to manage a branding within your Auth0 tenant.`,
		CreateContext: createBranding,
		ReadContext:   readBranding,
		UpdateContext: updateBranding,
		DeleteContext: deleteBranding,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"colors": {
				Type:        schema.TypeList,
				Optional:    true,
				MaxItems:    1,
				Description: "Configuration settings for colors for branding",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"primary": {
							Type:        schema.TypeString,
							Optional:    true,
							Computed:    true,
							Description: "String, Hexadecimal. Background color of login pages.",
						},
						"page_background": {
							Type:        schema.TypeString,
							Optional:    true,
							Computed:    true,
							Description: "String, Hexadecimal. Primary button background color.",
						},
					},
				},
			},
			"favicon_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "URL for the favicon.",
			},
			"logo_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "URL of logo for branding.",
			},
			"font": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"url": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "URL for the custom font",
							Computed:    true,
						},
					},
				},
			},
			"universal_login": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"body": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "body of login pages",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func createBranding(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId(resource.UniqueId())
	return updateBranding(ctx, d, m)
}

func readBranding(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	b, err := api.Branding.Read(management.Context(ctx))

	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	_ = d.Set("favicon_url", b.FaviconURL)
	_ = d.Set("logo_url", b.LogoURL)
	_ = d.Set("colors", flattenBrandingColors(b.Colors))
	_ = d.Set("font", flattenBrandingFont(b.Font))

	t, err := api.Tenant.Read(management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}

	if t.Flags.EnableCustomDomainInEmails != nil && *t.Flags.EnableCustomDomainInEmails {
		if err := assignUniversalLogin(ctx, d, m); err != nil {
			d.SetId("")
			return diag.FromErr(err)
		}
	}

	return nil
}

func updateBranding(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	branding := buildBranding(d)
	universalLogin := buildBrandingUniversalLogin(d)
	api := m.(*management.Management)
	err := api.Branding.Update(branding, management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}

	if universalLogin.GetBody() != "" {
		err = api.Branding.SetUniversalLogin(universalLogin, management.Context(ctx))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	return readBranding(ctx, d, m)
}

func deleteBranding(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	t, err := api.Tenant.Read(management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}

	if t.Flags.EnableCustomDomainInEmails != nil && *t.Flags.EnableCustomDomainInEmails {
		err = api.Branding.DeleteUniversalLogin(management.Context(ctx))
		if err != nil {
			return flow.DefaultManagementError(err, d)
		}
	}
	return diag.FromErr(err)
}

func buildBranding(d *schema.ResourceData) *management.Branding {
	b := &management.Branding{
		FaviconURL: String(d, "favicon_url"),
		LogoURL:    String(d, "logo_url"),
	}

	List(d, "colors").Elem(func(d ResourceData) {
		b.Colors = &management.BrandingColors{
			PageBackground: String(d, "page_background"),
			Primary:        String(d, "primary"),
		}
	})

	List(d, "font").Elem(func(d ResourceData) {
		b.Font = &management.BrandingFont{
			URL: String(d, "url"),
		}
	})

	return b
}

func buildBrandingUniversalLogin(d *schema.ResourceData) *management.BrandingUniversalLogin {
	b := &management.BrandingUniversalLogin{}

	List(d, "universal_login").Elem(func(d ResourceData) {
		b.Body = String(d, "body")
	})

	return b
}

func assignUniversalLogin(ctx context.Context, d *schema.ResourceData, m interface{}) error {
	api := m.(*management.Management)
	ul, err := api.Branding.UniversalLogin(management.Context(ctx))
	if err != nil {
		if mErr, ok := err.(management.Error); ok {
			// if the custom domain is enabled, but custom universal login pages are not set
			// management api will return a 404 template not found. If that's the case we can safely ignore the error.
			// see https://github.com/alexkappa/terraform-provider-auth0/issues/380
			if mErr.Status() == http.StatusNotFound {
				return nil
			}
		}
		return err
	}

	_ = d.Set("universal_login", flattenBrandingUniversalLogin(ul))
	return nil
}

func flattenBrandingColors(brandingColors *management.BrandingColors) []interface{} {
	m := make(map[string]interface{})
	if brandingColors != nil {
		m["page_background"] = brandingColors.PageBackground
		m["primary"] = brandingColors.Primary
	}
	return []interface{}{m}
}

func flattenBrandingUniversalLogin(brandingUniversalLogin *management.BrandingUniversalLogin) []interface{} {
	m := make(map[string]interface{})
	if brandingUniversalLogin != nil {
		m["body"] = brandingUniversalLogin.Body
	}
	return []interface{}{m}
}

func flattenBrandingFont(brandingFont *management.BrandingFont) []interface{} {
	m := make(map[string]interface{})
	if brandingFont != nil {
		m["url"] = brandingFont.URL
	}
	return []interface{}{m}
}
