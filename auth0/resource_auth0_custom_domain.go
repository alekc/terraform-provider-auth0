package auth0

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

func newCustomDomain() *schema.Resource {
	return &schema.Resource{
		CreateContext: createCustomDomain,
		ReadContext:   readCustomDomain,
		DeleteContext: deleteCustomDomain,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Description: `With Auth0, you can use a custom domain to maintain a consistent user experience. 
This resource allows you to create and manage a custom domain within your Auth0 tenant.`,

		Schema: map[string]*schema.Schema{
			"domain": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the custom domain",
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "Provisioning type for the custom domain. Valid options are: auth0_managed_certs, " +
					"self_managed_certs",
				ValidateFunc: validation.StringInSlice([]string{
					"auth0_managed_certs",
					"self_managed_certs",
				}, true),
			},
			"primary": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates whether or not this is a primary domain",
			},
			"status": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "Configuration status for the custom domain. Options include `disabled`, `pending`, " +
					"`pending_verification`, and `ready`",
			},
			"verification_method": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"txt"}, true),
				Description:  "Domain verification method. Options include `txt`",
			},
			"verification": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Configuration settings for verification",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"methods": {
							Type:     schema.TypeList,
							Elem:     schema.TypeMap,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func createCustomDomain(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := buildCustomDomain(d)
	api := m.(*management.Management)
	if err := api.CustomDomain.Create(c, management.Context(ctx)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(auth0.StringValue(c.ID))
	return readCustomDomain(ctx, d, m)
}

func readCustomDomain(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	c, err := api.CustomDomain.Read(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	d.SetId(auth0.StringValue(c.ID))
	_ = d.Set("domain", c.Domain)
	_ = d.Set("type", c.Type)
	_ = d.Set("primary", c.Primary)
	_ = d.Set("status", c.Status)

	if c.Verification != nil {
		_ = d.Set("verification", []map[string]interface{}{
			{"methods": c.Verification.Methods},
		})
	}

	return nil
}

func deleteCustomDomain(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	err := api.CustomDomain.Delete(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	return nil
}

func buildCustomDomain(d *schema.ResourceData) *management.CustomDomain {
	return &management.CustomDomain{
		Domain:             String(d, "domain"),
		Type:               String(d, "type"),
		VerificationMethod: String(d, "verification_method"),
	}
}
