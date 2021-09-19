package auth0

import (
	"context"
	"log"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
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
		Description: `With Auth0, you can have standard welcome, password reset, 
and account verification email-based workflows built right into Auth0. 

This resource allows you to configure email templates to customize the look, feel, 
and sender identities of emails sent by Auth0. Used in conjunction with configured email providers.`,
		Schema: map[string]*schema.Schema{
			"template": {
				Type:     schema.TypeString,
				Required: true,
				Description: "Template name. Options include `verify_email`, `verify_email_by_code`, `reset_email`, " +
					"`welcome_email`, `blocked_account`, `stolen_credentials`, `enrollment_email`, `mfa_oob_code`, " +
					"`change_password`, `user_invitation` (legacy), and `password_reset` (legacy)",
				ValidateFunc: validation.StringInSlice([]string{
					"verify_email",
					"verify_email_by_code",
					"reset_email",
					"welcome_email",
					"enrollment_email",
					"blocked_account",
					"stolen_credentials",
					"mfa_oob_code",
					"user_invitation",
					"change_password",
					"password_reset",
				}, false),
			},
			"body": {
				Type:     schema.TypeString,
				Required: true,
				Description: "Body of the email template. You can include [common variables](https://auth0." +
					"com/docs/email/templates#common-variables)",
			},
			"from": {
				Type:     schema.TypeString,
				Required: true,
				Description: "Email address to use as the sender. You can include [common variables](https://auth0." +
					"com/docs/email/templates#common-variables)",
			},
			"result_url": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "URL to redirect the user to after a successful action. [Learn more](https://auth0." +
					"com/docs/email/templates#configuring-the-redirect-to-url)",
			},
			"subject": {
				Type:     schema.TypeString,
				Required: true,
				Description: "Subject line of the email. You can include [common variables](https://auth0." +
					"com/docs/email/templates#common-variables)",
			},
			"syntax": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Syntax of the template body. You can use either text or HTML + Liquid syntax",
			},
			"url_lifetime_in_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Number of seconds during which the link within the email will be valid",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Required:    true,
				Description: "Indicates whether or not the template is enabled",
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
		return flow.DefaultManagementError(err, d)
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
		return flow.DefaultManagementError(err, d)
	}
	return nil
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
