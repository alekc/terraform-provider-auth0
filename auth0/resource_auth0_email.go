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

func newEmail() *schema.Resource {
	emailProvider := []string{"mandrill", "sendgrid", "sparkpost", "mailgun", "ses", "smtp"}
	return &schema.Resource{

		CreateContext: createEmail,
		ReadContext:   readEmail,
		UpdateContext: updateEmail,
		DeleteContext: deleteEmail,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Description: `
With Auth0, you can have standard welcome, password reset, 
and account verification email-based workflows built right into Auth0. 
This resource allows you to configure email providers so you can route all emails that are part of Auth0's
authentication workflows through the supported high-volume email service of your choice.`,

		Schema: map[string]*schema.Schema{
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether the provider is enabled (`true`) or disabled (`false`)",
			},
			"default_from_address": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Email address to use as `from` when no other address specified",
			},
			"mandrill": {
				Type:         schema.TypeList,
				Optional:     true,
				Description:  "Configuration for the mandrill email integration",
				MaxItems:     1,
				ExactlyOneOf: emailProvider,
				ForceNew:     true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"api_key": {
							Type:        schema.TypeString,
							Required:    true,
							Sensitive:   true,
							ForceNew:    true,
							Description: "API Key",
						},
					},
				},
			},
			"sendgrid": {
				Type:         schema.TypeList,
				Optional:     true,
				Description:  "Configuration for the sendgrid email integration",
				MaxItems:     1,
				ExactlyOneOf: emailProvider,
				ForceNew:     true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"api_key": {
							Type:        schema.TypeString,
							Required:    true,
							Sensitive:   true,
							ForceNew:    true,
							Description: "API Key",
						},
					},
				},
			},
			"sparkpost": {
				Type:         schema.TypeList,
				Optional:     true,
				Description:  "Configuration for the sparkpost email integration",
				MaxItems:     1,
				ExactlyOneOf: emailProvider,
				ForceNew:     true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"api_key": {
							Type:        schema.TypeString,
							Required:    true,
							Sensitive:   true,
							ForceNew:    true,
							Description: "API Key",
						},
						"region": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true, // auth0 requires patch null which is not possible to do with the current
							// sdk
							ValidateDiagFunc: validation.ToDiagFunc(
								validation.StringInSlice([]string{"eu"}, false),
							),
							Description: "Sparkpost region. If set must be `eu`",
						},
					},
				},
			},
			"mailgun": {
				Type:         schema.TypeList,
				Optional:     true,
				Description:  "Configuration for the mailgun email integration",
				MaxItems:     1,
				ExactlyOneOf: emailProvider,
				ForceNew:     true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"api_key": {
							Type:        schema.TypeString,
							Required:    true,
							Sensitive:   true,
							ForceNew:    true,
							Description: "API Key",
						},
						"region": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
							ValidateDiagFunc: validation.ToDiagFunc(
								validation.StringInSlice([]string{"eu"}, false),
							),
							Description: "Mailgun region. If set must be `eu`",
						},
						"domain": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Your Domain registered with Mailgun",
						},
					},
				},
			},
			"ses": {
				Type:         schema.TypeList,
				Optional:     true,
				Description:  "Configuration for the Aws ses email integration",
				MaxItems:     1,
				ForceNew:     true,
				ExactlyOneOf: emailProvider,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"access_key_id": {
							Type:        schema.TypeString,
							Required:    true,
							Sensitive:   true,
							ForceNew:    true,
							Description: "Access key ID",
						},
						"secret_access_key": {
							Type:        schema.TypeString,
							Required:    true,
							Sensitive:   true,
							ForceNew:    true,
							Description: "Secret Access key. It's not advisable to store it in clear",
						},
						"region": {
							Required:    true,
							Type:        schema.TypeString,
							Description: "Ses region",
						},
					},
				},
			},
			"smtp": {
				Type:         schema.TypeList,
				Optional:     true,
				Description:  "Configuration for the generic SMTP email integration",
				MaxItems:     1,
				ExactlyOneOf: emailProvider,
				ForceNew:     true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"host": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "SMTP Host",
						},
						"port": {
							Type:     schema.TypeInt,
							Required: true,
						},
						"user": {
							Type:     schema.TypeString,
							Required: true,
						},
						"pass": {
							Type:      schema.TypeString,
							Required:  true,
							Sensitive: true,
							ForceNew:  true,
						},
					},
				},
			},
		},
	}
}

func createEmail(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	e := buildEmail(d)
	api := m.(*management.Management)
	if err := api.Email.Create(e, management.Context(ctx)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(auth0.StringValue(e.Name))
	return readEmail(ctx, d, m)
}

func readEmail(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	e, err := api.Email.Read(management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	d.SetId(auth0.StringValue(e.Name))
	_ = d.Set("enabled", e.Enabled)
	_ = d.Set("default_from_address", e.DefaultFromAddress)

	switch *e.Name {
	case "mandrill":
		_ = d.Set("mandrill", flattenMap(map[string]interface{}{
			"api_key": d.Get("mandrill.0.api_key"),
		}, true))
	case "sendgrid":
		_ = d.Set("sendgrid", flattenMap(map[string]interface{}{
			"api_key": d.Get("sendgrid.0.api_key"),
		}, true))
	case "ses":
		_ = d.Set("ses", flattenMap(map[string]interface{}{
			"access_key_id":     d.Get("ses.0.access_key_id"),
			"secret_access_key": d.Get("ses.0.secret_access_key"),
			"region":            e.Credentials.Region,
		}, true))
	case "sparkpost":
		dataMap := map[string]interface{}{
			"api_key": d.Get("sparkpost.0.api_key"),
		}
		if e.Credentials.Region != nil {
			dataMap["region"] = e.Credentials.Region
		}
		_ = d.Set("sparkpost", flattenMap(dataMap, true))
	case "mailgun":
		dataMap := map[string]interface{}{
			"api_key": d.Get("mailgun.0.api_key"),
			"domain":  d.Get("mailgun.0.domain"),
		}
		if e.Credentials.Region != nil {
			dataMap["region"] = e.Credentials.Region
		}
		_ = d.Set("mailgun", flattenMap(dataMap, true))
	case "smtp":
		dataMap := map[string]interface{}{
			"pass": d.Get("smtp.0.pass"),
			"host": e.Credentials.GetSMTPHost(),
			"port": e.Credentials.GetSMTPPort(),
			"user": e.Credentials.GetSMTPUser(),
		}
		_ = d.Set("smtp", flattenMap(dataMap, true))
	}

	return nil
}

func updateEmail(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	e := buildEmail(d)
	api := m.(*management.Management)
	err := api.Email.Update(e, management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	return readEmail(ctx, d, m)
}

func deleteEmail(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	err := api.Email.Delete(management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	return nil
}

func buildEmail(d *schema.ResourceData) *management.Email {
	e := &management.Email{
		Enabled:            Bool(d, "enabled"),
		DefaultFromAddress: String(d, "default_from_address"),
	}

	List(d, "mandrill").Elem(func(d ResourceData) {
		e.Name = auth0.String("mandrill")
		e.Credentials = &management.EmailCredentials{
			APIKey: String(d, "api_key"),
		}
	})

	List(d, "sendgrid").Elem(func(d ResourceData) {
		e.Name = auth0.String("sendgrid")
		e.Credentials = &management.EmailCredentials{
			APIKey: String(d, "api_key"),
		}
	})
	List(d, "sparkpost").Elem(func(d ResourceData) {
		e.Name = auth0.String("sparkpost")
		e.Credentials = &management.EmailCredentials{
			APIKey: String(d, "api_key"),
		}
		if region, ok := d.GetOk("region"); ok {
			e.Credentials.Region = auth0.String(region.(string))
		}
	})
	List(d, "mailgun").Elem(func(d ResourceData) {
		e.Name = auth0.String("mailgun")
		e.Credentials = &management.EmailCredentials{
			APIKey: String(d, "api_key"),
			Domain: String(d, "domain"),
		}
		if region, ok := d.GetOk("region"); ok {
			e.Credentials.Region = auth0.String(region.(string))
		}
	})

	List(d, "ses").Elem(func(d ResourceData) {
		e.Name = auth0.String("ses")
		e.Credentials = &management.EmailCredentials{
			AccessKeyID:     String(d, "access_key_id"),
			SecretAccessKey: String(d, "secret_access_key"),
			Region:          String(d, "region"),
		}
	})
	List(d, "smtp").Elem(func(d ResourceData) {
		e.Name = auth0.String("smtp")
		e.Credentials = &management.EmailCredentials{
			SMTPHost: String(d, "host"),
			SMTPPort: Int(d, "port"),
			SMTPUser: String(d, "user"),
			SMTPPass: String(d, "pass"),
		}
	})

	return e
}
