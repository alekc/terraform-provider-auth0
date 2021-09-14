package auth0

import (
	"context"
	"regexp"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

var ruleNameRegexp = regexp.MustCompile("^[^\\s-][\\w -]+[^\\s-]$")

func newRule() *schema.Resource {
	return &schema.Resource{

		CreateContext: createRule,
		ReadContext:   readRule,
		UpdateContext: updateRule,
		DeleteContext: deleteRule,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Description: `
With Auth0, you can create custom Javascript snippets that run in a secure, 
isolated sandbox as part of your authentication pipeline, which are otherwise known as rules.

This resource allows you to create and manage rules.

You can create global variable for use with rules by using the auth0_rule_config resource.`,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the rule. May only contain alphanumeric characters, spaces, and hyphens. May neither start nor end with hyphens or spaces",
				ValidateFunc: validation.StringMatch(
					ruleNameRegexp,
					"Can only contain alphanumeric characters, spaces and '-'. "+
						"Can neither start nor end with '-' or spaces."),
			},
			"script": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Code to be executed when the rule runs",
			},
			"order": {
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
				Description: "Order in which the rule executes relative to other rules. " +
					"Lower-valued rules execute first",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Indicates whether the rule is enabled",
			},
		},
	}
}

func createRule(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := buildRule(d)
	api := m.(*management.Management)
	if err := api.Rule.Create(c, management.Context(ctx)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(auth0.StringValue(c.ID))
	return readRule(ctx, d, m)
}

func readRule(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	c, err := api.Rule.Read(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	_ = d.Set("name", c.Name)
	_ = d.Set("script", c.Script)
	_ = d.Set("order", c.Order)
	_ = d.Set("enabled", c.Enabled)
	return nil
}

func updateRule(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := buildRule(d)
	api := m.(*management.Management)
	err := api.Rule.Update(d.Id(), c, management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	return readRule(ctx, d, m)
}

func deleteRule(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	err := api.Rule.Delete(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	return diag.FromErr(err)
}

func buildRule(d *schema.ResourceData) *management.Rule {
	return &management.Rule{
		Name:    String(d, "name"),
		Script:  String(d, "script"),
		Order:   Int(d, "order"),
		Enabled: Bool(d, "enabled"),
	}
}
