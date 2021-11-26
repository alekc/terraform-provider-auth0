package auth0

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceRole() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceRoleRead,
		Description: "TODO",
		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the role to retrieve",
			},
			"name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name for this role",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Role's description",
			},
			"permissions": {
				Type:        schema.TypeSet,
				Computed:    true,
				Description: "Configuration settings for permissions (scopes) attached to the role",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Name of the permission (scope)",
						},
						"description": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Description of this permission",
						},
						"resource_server_identifier": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Unique identifier for the resource server",
						},
						"resource_server_name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Resource server (API) name this permission is for",
						},
					},
				},
			},
		},
	}
}

func dataSourceRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId(d.Get("id").(string))
	return readRole(ctx, d, m)
}
