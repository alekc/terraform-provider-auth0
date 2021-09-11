package auth0

import (
	"context"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

func newClientGrant() *schema.Resource {
	return &schema.Resource{
		CreateContext: createClientGrant,
		ReadContext:   readClientGrant,
		UpdateContext: updateClientGrant,
		DeleteContext: deleteClientGrant,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"client_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"audience": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"scope": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Required: true,
			},
		},
	}
}

func createClientGrant(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	clientGrant := buildClientGrant(d)
	api := m.(*management.Management)
	if err := api.ClientGrant.Create(clientGrant, management.Context(ctx)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(auth0.StringValue(clientGrant.ID))
	return readClientGrant(ctx, d, m)
}

func readClientGrant(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	g, err := api.ClientGrant.Read(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	d.SetId(auth0.StringValue(g.ID))
	_ = d.Set("client_id", g.ClientID)
	_ = d.Set("audience", g.Audience)
	_ = d.Set("scope", g.Scope)
	return nil
}

func updateClientGrant(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	clientGrant := buildClientGrant(d)
	clientGrant.Audience = nil
	clientGrant.ClientID = nil
	api := m.(*management.Management)
	err := api.ClientGrant.Update(d.Id(), clientGrant, management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	return readClientGrant(ctx, d, m)
}

func deleteClientGrant(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	err := api.ClientGrant.Delete(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	return diag.FromErr(err)
}

func buildClientGrant(d *schema.ResourceData) *management.ClientGrant {
	clientGrant := &management.ClientGrant{
		ClientID: String(d, "client_id"),
		Audience: String(d, "audience"),
	}
	if scope, ok := d.GetOk("scope"); ok {
		clientGrant.Scope = scope.([]interface{})
	} else {
		clientGrant.Scope = []interface{}{}
	}
	return clientGrant
}
