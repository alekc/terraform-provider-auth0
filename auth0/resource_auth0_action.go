package auth0

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
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
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(10 * time.Minute),
			Update: schema.DefaultTimeout(10 * time.Minute),
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
							Default:     "v2",
						},
					},
				},
			},
			"code": {
				Type:        schema.TypeString,
				Required:    true, // if set to optional, secrets won't work
				Description: "The source code of the action",
			},
			"deploy": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If set to true, it will deploy the action on every change",
			},
			// not supported by sdk atm
			// "runtime": {
			// 	Type:        schema.TypeString,
			// 	Computed:    true,
			// 	Description: "The Node runtime. Valid options are `node12` (not recommended) or `node16`",
			// 	Default:     "node16",
			// },
			"status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The build status of this action",
			},
			"all_changes_deployed": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if all of an Action's contents have been deployed",
			},
			"dependency": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "The list of third party npm modules, and their versions, that this action depends on",
				Set: func(i interface{}) int {
					return schema.HashString(i.(map[string]interface{})["name"])
				},
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
			"secret": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "The list of secrets that are included in an action or a version of an action",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Secret name",
						},
						"value": {
							Type:        schema.TypeString,
							Optional:    true,
							Sensitive:   true,
							Description: "Secret Value",
						},
						"updated_at": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Secret's last update date",
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
func flattenDependencies(deps []management.ActionDependency) []map[string]interface{} {
	var result []map[string]interface{}
	for _, v := range deps {
		result = append(result, map[string]interface{}{
			"name":    v.Name,
			"version": v.Version,
		})
	}
	return result
}
func flattenSecrets(d *schema.ResourceData, triggers []management.ActionSecret, update bool) []map[string]interface{} {
	var result []map[string]interface{}
	for k, v := range triggers {
		data := map[string]interface{}{
			"name":       v.GetName(),
			"updated_at": v.GetUpdatedAt().String(),
			"value":      "",
		}
		oldValue, found := d.GetOk(fmt.Sprintf("secret.%d", k))
		if !found {
			// nothing else we can do here, just return
			result = append(result, data)
			continue
		}
		updatedAt := oldValue.(map[string]interface{})["updated_at"].(string)
		// Auth0 doesn't send back secret value. So we can assume (
		// and assign state value) to the secret only in following cases:
		// 1) updateAt is empty, so it's a new entity
		// 2) updated_at field hasn't changed
		// 3) it's an update
		if updatedAt == "" ||
			v.UpdatedAt.String() == updatedAt ||
			update {
			data["value"] = d.Get(fmt.Sprintf("secret.%d.value", k))
		}
		result = append(result, data)
	}
	return result
}

func actionStateConf(d *schema.ResourceData, api *management.Management) *resource.StateChangeConf {
	return &resource.StateChangeConf{
		Pending:    []string{"pending", "building", "packaged"},
		Target:     []string{"built"},
		Refresh:    resourceActionStateRefreshFunc(d.Id(), api),
		Timeout:    d.Timeout(schema.TimeoutCreate),
		MinTimeout: 10 * time.Second,
	}
}

func createAction(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := buildAction(d)
	api := m.(*management.Management)
	if err := api.Action.Create(c, management.Context(ctx)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(auth0.StringValue(c.ID))

	log.Printf("[INFO] Waiting for the action (%s) to be built", d.Id())
	_, err := actionStateConf(d, api).WaitForStateContext(ctx)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := deployAction(ctx, api, *c.ID, d.Get("deploy").(bool)); err != nil {
		return err
	}
	return readAction(ctx, d, m)
}

func resourceActionStateRefreshFunc(id string, api *management.Management) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		v, err := api.Action.Read(id)
		switch {
		case err != nil:
			log.Printf("Error on retrieving action when waiting: %s", err)
			return nil, "", err
		case v == nil:
			return nil, "", nil
		}
		return v, v.GetStatus(), nil
	}
}

func deployAction(ctx context.Context, api *management.Management, ID string, deploy bool) diag.Diagnostics {
	if !deploy {
		return nil
	}
	err := resource.RetryContext(ctx, time.Second*30, func() *resource.RetryError {
		log.Printf("[DEBUG] Deploying action %s", ID)
		if _, apiErr := api.Action.Deploy(ID); apiErr != nil {
			log.Printf("[DEBUG] Got an error deploying action %s: %#v", ID, apiErr)
			return resource.RetryableError(apiErr)
		}
		log.Printf("[TRACE] Deployed action %s", ID)
		return nil
	})
	return diag.FromErr(err)
}

func readAction(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return execRead(ctx, d, m, false)
}
func execRead(ctx context.Context, d *schema.ResourceData, m interface{}, fromUpdate bool) diag.Diagnostics {
	api := m.(*management.Management)
	action, err := api.Action.Read(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	_ = d.Set("name", action.Name)
	_ = d.Set("trigger", flattenActionTrigger(action.SupportedTriggers))
	_ = d.Set("code", action.Code)
	_ = d.Set("dependency", flattenDependencies(action.Dependencies))
	_ = d.Set("secret", flattenSecrets(d, action.Secrets, fromUpdate))
	_ = d.Set("status", action.Status)
	_ = d.Set("all_changes_deployed", action.AllChangesDeployed)
	_ = d.Set("deploy", d.Get("deploy"))

	return nil
}
func updateAction(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := buildAction(d)
	api := m.(*management.Management)
	err := api.Action.Update(d.Id(), c, management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[INFO] Waiting for the action (%s) to be built", d.Id())
	_, err = actionStateConf(d, api).WaitForStateContext(ctx)
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[INFO] Deploying action (%s)", d.Id())
	if err := deployAction(ctx, api, *c.ID, d.Get("deploy").(bool)); err != nil {
		return err
	}

	return execRead(ctx, d, m, true)
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
	List(d, "secret").Elem(func(d ResourceData) {
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
	Set(d, "dependency").Elem(func(d ResourceData) {
		action.Dependencies = append(action.Dependencies, management.ActionDependency{
			Name:    String(d, "name"),
			Version: String(d, "version"),
		})
	})
	return action
}
