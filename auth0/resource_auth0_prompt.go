package auth0

import (
	"context"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

func newPrompt() *schema.Resource {
	return &schema.Resource{
		CreateContext: createPrompt,
		ReadContext:   readPrompt,
		UpdateContext: updatePrompt,
		DeleteContext: deletePrompt,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"universal_login_experience": {
				Type:     schema.TypeString,
				Optional: true,
				ValidateFunc: validation.StringInSlice([]string{
					"new", "classic",
				}, false),
			},
			"identifier_first": {
				Type:     schema.TypeBool,
				Optional: true,
			},
		},
	}
}

func createPrompt(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId(resource.UniqueId())
	return updatePrompt(ctx, d, m)
}

func readPrompt(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	p, err := api.Prompt.Read(management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	_ = d.Set("universal_login_experience", p.UniversalLoginExperience)
	_ = d.Set("identifier_first", p.IdentifierFirst)
	return nil
}

func updatePrompt(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	p := buildPrompt(d)
	api := m.(*management.Management)
	err := api.Prompt.Update(p)
	if err != nil {
		return diag.FromErr(err)
	}
	return readPrompt(ctx, d, m)
}

func deletePrompt(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	d.SetId("") // todo verify the auth0 resource
	return nil
}

func buildPrompt(d *schema.ResourceData) *management.Prompt {
	return &management.Prompt{
		UniversalLoginExperience: auth0.StringValue(String(d, "universal_login_experience")),
		IdentifierFirst:          Bool(d, "identifier_first"),
	}
}
