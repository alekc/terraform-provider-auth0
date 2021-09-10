package auth0

import (
	"context"
	"log"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

func newEmailTemplate() *schema.Resource {
	return &schema.Resource{
		CreateContext: createEmailTemplate,
		ReadContext:   readEmailTemplate,
		UpdateContext: updateEmailTemplate,
		DeleteContext: deleteEmailTemplate,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"template": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.StringInSlice([]string{
					"verify_email",
					"verify_email_by_code",
					"reset_email",
					"welcome_email",
					"blocked_account",
					"stolen_credentials",
					"enrollment_email",
					"change_password",
					"password_reset",
					"mfa_oob_code",
				}, true),
			},
			"body": {
				Type:     schema.TypeString,
				Required: true,
			},
			"from": {
				Type:     schema.TypeString,
				Required: true,
			},
			"result_url": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"subject": {
				Type:     schema.TypeString,
				Required: true,
			},
			"syntax": {
				Type:     schema.TypeString,
				Required: true,
			},
			"url_lifetime_in_seconds": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"enabled": {
				Type:     schema.TypeBool,
				Required: true,
			},
		},
	}
}

func createEmailTemplate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	e := buildEmailTemplate(d)
	api := m.(*management.Management)

	// The email template resource doesn't allow deleting templates, so in order
	// to avoid conflicts, we first attempt to read the template. If it exists
	// we'll try to update it, if not we'll try to create it.
	if _, err := api.EmailTemplate.Read(auth0.StringValue(e.Template), management.Context(ctx)); err == nil {

		// We succeeded in reading the template, this means it was created
		// previously.
		if err := api.EmailTemplate.Update(auth0.StringValue(e.Template), e, management.Context(ctx)); err != nil {
			return diag.FromErr(err)
		}
		d.SetId(auth0.StringValue(e.Template))
		return nil
	}

	// If we reached this point the template doesn't exist. Therefore it is safe
	// to create it.
	if err := api.EmailTemplate.Create(e, management.Context(ctx)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(auth0.StringValue(e.Template))

	return nil
}

func readEmailTemplate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	e, err := api.EmailTemplate.Read(d.Id(), management.Context(ctx))
	if err != nil {
		if mErr, ok := err.(management.Error); ok {
			if mErr.Status() == http.StatusNotFound {
				d.SetId("")
				return nil
			}
		}
		return diag.FromErr(err)
	}
	d.SetId(auth0.StringValue(e.Template))
	_ = d.Set("template", e.Template)
	_ = d.Set("body", e.Body)
	_ = d.Set("from", e.From)
	_ = d.Set("result_url", e.ResultURL)
	_ = d.Set("subject", e.Subject)
	_ = d.Set("syntax", e.Syntax)
	_ = d.Set("url_lifetime_in_seconds", e.URLLifetimeInSecoonds)
	_ = d.Set("enabled", e.Enabled)
	return nil
}

func updateEmailTemplate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	e := buildEmailTemplate(d)
	api := m.(*management.Management)
	err := api.EmailTemplate.Update(d.Id(), e, management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	return readEmailTemplate(ctx, d, m)
}

func deleteEmailTemplate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	t := &management.EmailTemplate{
		Template: auth0.String(d.Id()),
		Enabled:  auth0.Bool(false),
	}
	err := api.EmailTemplate.Update(d.Id(), t, management.Context(ctx))
	if err != nil {
		if mErr, ok := err.(management.Error); ok {
			if mErr.Status() == http.StatusNotFound {
				d.SetId("")
				return nil
			}
		}
	}
	return diag.FromErr(err)
}

func buildEmailTemplate(d *schema.ResourceData) *management.EmailTemplate {
	t := &management.EmailTemplate{
		Template:              String(d, "template"),
		Body:                  String(d, "body"),
		From:                  String(d, "from"),
		ResultURL:             String(d, "result_url"),
		Subject:               String(d, "subject"),
		Syntax:                String(d, "syntax"),
		URLLifetimeInSecoonds: Int(d, "url_lifetime_in_seconds"),
		Enabled:               Bool(d, "enabled"),
	}
	log.Printf("[DEBUG] Template: %s", t)
	return t
}
