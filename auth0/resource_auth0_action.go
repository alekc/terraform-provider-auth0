package auth0

import (
	"context"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

func newAction() *schema.Resource {
	return &schema.Resource{
		CreateContext: createAction,
		ReadContext:   readAction,
		UpdateContext: updateAction,
		DeleteContext: deleteAction,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Description: `
Actions are secure, tenant-specific, versioned functions written in Node.
js that execute at certain points during the Auth0 runtime. 

Actions are used to customize and extend Auth0's capabilities with custom logic.`,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the action.",
				ValidateFunc: validation.StringMatch(
					ruleNameRegexp,
					"Can only contain alphanumeric characters, spaces and '-'. "+
						"Can neither start nor end with '-' or spaces."),
			},
			"trigger": {
				Type:     schema.TypeList,
				Required: true,
				Description: "The list of triggers that this action supports. At this time, " +
					"an action can only target a single trigger at a time",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Trigger id. Valid options are `post-login`, `credentials-exchange`, `pre-user-registration`, `post-user-registration`, `post-change-password`, `send-phone-message`",
							ValidateFunc: validation.StringInSlice([]string{"post-login", "credentials-exchange",
								"pre-user-registration", "post-user-registration", "post-change-password", "send-phone-message"},
								false),
						},
						"version": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Trigger version",
						},
					},
				},
			},
			"code": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The source code of the action",
			},
			// Not supported by sdk atm
			// "runtime": {
			// 	Type:        schema.TypeInt,
			// 	Optional:    true,
			// 	Description: "The Node runtime. Valid options are `node12` (not recommended) or `node16`",
			// 	Default:     "node16",
			// },
			"dependencies": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "The list of third party npm modules, and their versions, that this action depends on",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Dependency name",
						},
						"version": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Dependency version",
						},
					},
				},
			},
			"secrets": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "The list of secrets that are included in an action or a version of an action",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Trigger id. Valid options are `post-login`, `credentials-exchange`, `pre-user-registration`, `post-user-registration`, `post-change-password`, `send-phone-message`",
							ValidateFunc: validation.StringInSlice([]string{"post-login", "credentials-exchange",
								"pre-user-registration", "post-user-registration", "post-change-password", "send-phone-message"},
								false),
						},
						"code": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Trigger version",
						},
						"updated_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Trigger version",
						},
					},
				},
			},
		},
	}
}

func flattenActionTrigger(triggers []management.ActionTrigger) []map[string]interface{} {
	var result []map[string]interface{}
	for _, v := range triggers {
		result = append(result, map[string]interface{}{
			"id":      v.ID,
			"version": v.Version,
		})
	}
	return result
}
func flattenDependencies(triggers []management.ActionDependency) []map[string]interface{} {
	var result []map[string]interface{}
	for _, v := range triggers {
		result = append(result, map[string]interface{}{
			"name":    v.Name,
			"version": v.Version,
		})
	}
	return result
}
func flattenSecrets(triggers []management.ActionSecret) []map[string]interface{} {
	var result []map[string]interface{}
	for _, v := range triggers {
		result = append(result, map[string]interface{}{
			"name":       v.Name,
			"updated_at": v.UpdatedAt,
		})
	}
	return result
}

func createAction(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := buildAction(d)
	api := m.(*management.Management)
	if err := api.Action.Create(c, management.Context(ctx)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(auth0.StringValue(c.ID))
	return readAction(ctx, d, m)
}

func readAction(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	c, err := api.Action.Read(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	_ = d.Set("name", c.Name)
	_ = d.Set("trigger", flattenActionTrigger(c.SupportedTriggers))
	_ = d.Set("code", c.Name)
	_ = d.Set("dependencies", flattenDependencies(c.Dependencies))
	_ = d.Set("secrets", flattenSecrets(c.Secrets))
	_ = d.Set("name", c.Name)

	return nil
}

func updateAction(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := buildAction(d)
	api := m.(*management.Management)
	err := api.Action.Update(d.Id(), c, management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	return readAction(ctx, d, m)
}

func deleteAction(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	err := api.Action.Delete(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	return diag.FromErr(err)
}

func buildAction(d *schema.ResourceData) *management.Action {
	action := &management.Action{
		Name: String(d, "name"),
		Code: String(d, "code"),
	}
	List(d, "secrets").Elem(func(d ResourceData) {
		action.Secrets = append(action.Secrets, management.ActionSecret{
			Name:  String(d, "name"),
			Value: String(d, "value"),
		})
	})
	List(d, "trigger").Elem(func(d ResourceData) {
		action.SupportedTriggers = append(action.SupportedTriggers, management.ActionTrigger{
			ID:      String(d, "id"),
			Version: String(d, "version"),
		})
	})
	List(d, "dependencies").Elem(func(d ResourceData) {
		action.Dependencies = append(action.Dependencies, management.ActionDependency{
			Name:    String(d, "name"),
			Version: String(d, "version"),
		})
	})
	return action
}
