package auth0

import (
	"context"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

func newRuleConfig() *schema.Resource {
	return &schema.Resource{

		CreateContext: createRuleConfig,
		ReadContext:   readRuleConfig,
		UpdateContext: updateRuleConfig,
		DeleteContext: deleteRuleConfig,
		Description: "With Auth0, you can create custom Javascript snippets that run in a secure, " +
			"isolated sandbox as part of your authentication pipeline, " +
			"which are otherwise known as rules. This resource allows you to create and manage variables that are" +
			" available to all rules via Auth0's global configuration object. " +
			"Used in conjunction with configured rules",
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"key": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Key for a rules configuration variable",
			},
			"value": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Case-sensitive. Value for a rules configuration variable",
			},
		},
	}
}

func createRuleConfig(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	r := buildRuleConfig(d)
	key := auth0.StringValue(r.Key)
	r.Key = nil
	api := m.(*management.Management)
	if err := api.RuleConfig.Upsert(key, r, management.Context(ctx)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(auth0.StringValue(r.Key))
	return readRuleConfig(ctx, d, m)
}

func readRuleConfig(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	r, err := api.RuleConfig.Read(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	_ = d.Set("key", r.Key)
	return nil
}

func updateRuleConfig(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	r := buildRuleConfig(d)
	r.Key = nil
	api := m.(*management.Management)
	err := api.RuleConfig.Upsert(d.Id(), r, management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	return readRuleConfig(ctx, d, m)
}

func deleteRuleConfig(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	err := api.RuleConfig.Delete(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	return nil
}

func buildRuleConfig(d *schema.ResourceData) *management.RuleConfig {
	return &management.RuleConfig{
		Key:   String(d, "key"),
		Value: String(d, "value"),
	}
}
