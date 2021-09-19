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

func newFlow() *schema.Resource {
	return &schema.Resource{
		CreateContext: createActionBinding,
		ReadContext:   readActionBinding,
		UpdateContext: updateActionBinding,
		DeleteContext: deleteActionBinding,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Description: `
Update the actions that are bound (i.e. attached) to a trigger. Once an action is created and deployed, it must be
attached (i.e. bound) to a trigger so that it will be executed as part of a flow.

The order in which the actions are provided will determine the order in which they are executed.
`,

		Schema: map[string]*schema.Schema{
			"trigger_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice([]string{
					"post-login",
					"credentials-exchange",
					"pre-user-registration",
					"post-user-registration",
					"post-change-password",
					"send-phone-message",
				}, false),
				Description: "Execution stage of this rule. Can be " +
					"post-login, credentials-exchange, pre-user-registration, " +
					"post-user-registration, post-change-password" +
					", or send-phone-message",
			},
			"action": {
				Type:     schema.TypeList,
				Optional: true,
				Description: "The list of triggers that this action supports. At this time, " +
					"an action can only target a single trigger at a time",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"display_name": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "How will the action be displayed on dashboard ui",
						},
						"name": {
							Type:        schema.TypeString,
							Optional:    true,
							Computed:    true,
							Description: "Action name. Either id or name must be specified (if both, id has priority)",
						},
						"id": {
							Type:        schema.TypeString,
							Optional:    true,
							Computed:    true,
							Description: "Action ID. Either id or name must be specified (if both, id has priority)",
						},
					},
				},
			},
		},
	}
}

func createActionBinding(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return execActionBindingUpdate(ctx, d, m, true)
}
func execActionBindingUpdate(ctx context.Context, d *schema.ResourceData, m interface{}, isCreation bool) diag.Diagnostics {
	actionBindings := buildActionBinding(d)
	api := m.(*management.Management)

	triggerID := d.Get("trigger_id").(string)
	if err := api.Action.UpdateBindings(
		triggerID,
		actionBindings,
		management.Context(ctx),
	); err != nil {
		return diag.FromErr(err)
	}

	if isCreation {
		d.SetId(triggerID)
	}

	return readActionBinding(ctx, d, m)
}

func readActionBinding(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	c, err := api.Action.ListBindings(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	_ = d.Set("trigger_id", d.Id())
	bindings := make([]map[string]interface{}, 0, len(c.Bindings))
	for _, v := range c.Bindings {
		bindings = append(bindings, map[string]interface{}{
			"display_name": auth0.StringValue(v.DisplayName),
			"name":         auth0.StringValue(v.Action.Name),
			"id":           auth0.StringValue(v.Action.ID),
		})
	}
	_ = d.Set("action", bindings)
	return nil
}

func updateActionBinding(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return execActionBindingUpdate(ctx, d, m, false)
}

func deleteActionBinding(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	err := api.Action.UpdateBindings(d.Id(), []*management.ActionBinding{}, management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	return diag.FromErr(err)
}

func buildActionBinding(d *schema.ResourceData) []*management.ActionBinding {
	result := make([]*management.ActionBinding, 0)
	List(d, "action").Elem(func(d ResourceData) {
		temp := management.ActionBinding{
			DisplayName: String(d, "display_name"),
		}
		if val, ok := d.GetOk("id"); ok {
			temp.Ref = &management.ActionBindingReference{
				Type:  auth0.String(management.ActionBindingReferenceById),
				Value: auth0.String(val.(string)),
			}
		} else if val, ok := d.GetOk("name"); ok {
			temp.Ref = &management.ActionBindingReference{
				Type:  auth0.String(management.ActionBindingReferenceByName),
				Value: auth0.String(val.(string)),
			}
		}
		result = append(result, &temp)
	})

	return result
}
