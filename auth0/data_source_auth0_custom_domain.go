package auth0

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceCustomDomain() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceCustomDomainRead,
		Description: `A custom domain configured for this tenant`,

		Schema: map[string]*schema.Schema{
			"custom_domain_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the custom domain",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the custom domain",
			},
			"domain": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the custom domain",
			},
			"type": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "Provisioning type for the custom domain. Valid options are: auth0_managed_certs, " +
					"self_managed_certs",
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
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Domain verification method. Options include `txt`",
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

func dataSourceCustomDomainRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId(d.Get("custom_domain_id").(string))
	return readCustomDomain(ctx, d, m)
}
