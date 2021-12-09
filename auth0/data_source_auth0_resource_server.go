package auth0

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceResourceServer() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceResourceServerRead,
		Description: "Retrieve an auth0 resource server",
		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the resource server",
			},
			"name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Friendly name for the resource server. Cannot include `<` or `>` characters",
			},
			"identifier": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "Unique identifier for the resource server. " +
					"Used as the audience parameter for authorization calls. Can not be changed once set",
			},
			"scopes": {
				Type:        schema.TypeSet,
				Computed:    true,
				Description: "List of permissions (scopes) used by this resource server",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"value": {
							Type:     schema.TypeString,
							Computed: true,
							Description: "Name of the permission (scope). " +
								"Examples include `read:appointments` or `delete:appointments`",
						},
						"description": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Description of the permission (scope)",
						},
					},
				},
			},
			"signing_alg": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Algorithm used to sign JWTs. Options include `HS256` and `RS256`",
			},
			"signing_secret": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Secret used to sign tokens when using symmetric algorithms (HS256)",
			},
			"allow_offline_access": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates whether or not refresh tokens can be issued for this resource server",
			},
			"token_lifetime": {
				Type:     schema.TypeInt,
				Computed: true,
				Description: "Number of seconds during which access tokens issued for this resource server from the" +
					" token endpoint remain valid",
			},
			"token_lifetime_for_web": {
				Type:     schema.TypeInt,
				Computed: true,
				Description: "Number of seconds during which access tokens issued for this resource server via" +
					" implicit or hybrid flows remain valid. Cannot be greater than the `token_lifetime` value",
			},
			"skip_consent_for_verifiable_first_party_clients": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates whether or not to skip user consent for applications flagged as first party",
			},
			"verification_location": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"options": {
				Type:        schema.TypeMap,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Computed:    true,
				Description: "Used to store additional metadata",
			},
			"enforce_policies": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates whether or not authorization polices are enforced",
			},
			"token_dialect": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "Dialect of access tokens that should be issued for this resource server. " +
					"Options include `access_token` or `access_token_authz` (includes permissions)",
			},
		},
	}
}

func dataSourceResourceServerRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId(d.Get("id").(string))
	return readResourceServer(ctx, d, m)
}
