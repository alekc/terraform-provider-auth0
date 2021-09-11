package auth0

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

func newHook() *schema.Resource {
	return &schema.Resource{
		CreateContext: createHook,
		ReadContext:   readHook,
		UpdateContext: updateHook,
		DeleteContext: deleteHook,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validateHookNameFunc(),
				Description:  "Name of this hook",
			},
			"dependencies": {
				Type:        schema.TypeMap,
				Elem:        schema.TypeString,
				Optional:    true,
				Description: "Dependencies of this hook used by webtask server",
			},
			"script": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Code to be executed when this hook runs",
			},
			"trigger_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice([]string{
					"credentials-exchange",
					"pre-user-registration",
					"post-user-registration",
					"post-change-password",
					"send-phone-message",
				}, false),
				Description: "Execution stage of this rule. Can be " +
					"credentials-exchange, pre-user-registration, " +
					"post-user-registration, post-change-password" +
					", or send-phone-message",
			},
			"secrets": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "The secrets associated with the hook",
				Elem:        schema.TypeString,
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Whether the hook is enabled, or disabled",
			},
		},
	}
}

func createHook(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := buildHook(d)
	api := m.(*management.Management)
	if err := api.Hook.Create(c, management.Context(ctx)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(auth0.StringValue(c.ID))
	d.Partial(true)
	if err := upsertHookSecrets(ctx, d, m); err != nil {
		return diag.FromErr(err)
	}
	d.Partial(false)
	return readHook(ctx, d, m)
}

func readHook(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	c, err := api.Hook.Read(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	_ = d.Set("name", c.Name)
	_ = d.Set("dependencies", c.Dependencies)
	_ = d.Set("script", c.Script)
	_ = d.Set("trigger_id", c.TriggerID)
	_ = d.Set("enabled", c.Enabled)
	return nil
}

func updateHook(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := buildHook(d)
	api := m.(*management.Management)
	err := api.Hook.Update(d.Id(), c, management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	if err = upsertHookSecrets(ctx, d, m); err != nil {
		return diag.FromErr(err)
	}
	return readHook(ctx, d, m)
}

func upsertHookSecrets(ctx context.Context, d *schema.ResourceData, m interface{}) error {
	if d.IsNewResource() || d.HasChange("secrets") {
		secrets := Map(d, "secrets")
		api := m.(*management.Management)
		hookSecrets := toHookSecrets(secrets)
		return api.Hook.ReplaceSecrets(d.Id(), hookSecrets, management.Context(ctx))
	}
	return nil
}

func toHookSecrets(val map[string]interface{}) management.HookSecrets {
	hookSecrets := management.HookSecrets{}
	for key, value := range val {
		if strVal, ok := value.(string); ok {
			hookSecrets[key] = strVal
		}
	}
	return hookSecrets
}

func deleteHook(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	err := api.Hook.Delete(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	return diag.FromErr(err)
}

func buildHook(d *schema.ResourceData) *management.Hook {
	h := &management.Hook{
		Name:      String(d, "name"),
		Script:    String(d, "script"),
		TriggerID: String(d, "trigger_id", IsNewResource()),
		Enabled:   Bool(d, "enabled"),
	}

	deps := Map(d, "dependencies")
	if deps != nil {
		h.Dependencies = &deps
	}

	return h
}

func validateHookNameFunc() schema.SchemaValidateFunc {
	return validation.StringMatch(
		regexp.MustCompile("^[^\\s-][\\w -]+[^\\s-]$"),
		"Can only contain alphanumeric characters, spaces and '-'. Can neither start nor end with '-' or spaces.")
}
