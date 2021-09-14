package auth0

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"gopkg.in/auth0.v5/management"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
	v "github.com/alekc/terraform-provider-auth0/auth0/internal/validation"
)

func newTenant() *schema.Resource {
	return &schema.Resource{

		CreateContext: createTenant,
		ReadContext:   readTenant,
		UpdateContext: updateTenant,
		DeleteContext: deleteTenant,
		Description: `
With this resource, you can manage Auth0 tenants, including setting logos and support contact information, setting error pages, and configuring default tenant behaviors.

~> Auth0 does not currently support creating tenants through the Management API. Therefore this resource can only manage an existing tenant created through the Auth0 dashboard.

Auth0 does not currently support adding/removing extensions on tenants through their API. The Auth0 dashboard must be used to add/remove extensions.
`,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"change_password": {
				Type:        schema.TypeList,
				Optional:    true,
				MaxItems:    1,
				Computed:    true,
				Description: "Configuration settings for change password page",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Required:    true,
							Description: "Indicates whether or not to use the custom change password page",
						},
						"html": {
							Type:     schema.TypeString,
							Required: true,
							Description: "HTML format with supported Liquid syntax. " +
								"Customized content of the change password page",
						},
					},
				},
			},
			"guardian_mfa_page": {
				Type:        schema.TypeList,
				Optional:    true,
				MaxItems:    1,
				Computed:    true,
				Description: "Configuration settings for the Guardian MFA page",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Required:    true,
							Description: "Indicates whether or not to use the custom change password page",
						},
						"html": {
							Type:     schema.TypeString,
							Required: true,
							Description: "HTML format with supported Liquid syntax. " +
								"Customized content of the change password page",
						},
					},
				},
			},
			"default_audience": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"default_directory": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "Name of the connection to be used for Password Grant exchanges. " +
					"Options include `auth0-adldap`, `ad`, `auth0`, `email`, `sms`, `waad`, and `adfs`",
			},
			"error_page": {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				MaxItems:    1,
				Description: "Configuration settings for error pages",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"html": {
							Type:     schema.TypeString,
							Required: true,
							Description: "HTML format with supported Liquid syntax. " +
								"Customized content of the error page",
						},
						"show_log_link": {
							Type:     schema.TypeBool,
							Required: true,
							Description: "Indicates whether or not to show the link to logs as part of the default" +
								" error page",
						},
						"url": {
							Type:     schema.TypeString,
							Required: true,
							Description: "URL to redirect to when an error occurs rather than showing the default" +
								" error page",
						},
					},
				},
			},
			"friendly_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Friendly name for the tenant",
			},
			"picture_url": {
				Type: schema.TypeString,
				Description: "String URL of logo to be shown for the tenant. Recommended size is 150px x 150px. " +
					"If no URL is provided, the Auth0 logo will be used",
				Optional: true,
				Computed: true,
			},
			"support_email": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Support email address for authenticating users",
			},
			"support_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Support URL for authenticating users",
			},
			"allowed_logout_urls": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Computed:    true,
				Description: "URLs that Auth0 may redirect to after logout",
			},
			"session_lifetime": {
				Type:         schema.TypeFloat,
				Optional:     true,
				Computed:     true,
				ValidateFunc: validation.FloatAtLeast(0.01),
				Description:  "Number of hours during which a session will stay valid",
			},
			"sandbox_version": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "Selected sandbox version for the extensibility environment, " +
					"which allows you to use custom scripts to extend parts of Auth0's functionality",
			},
			"idle_session_lifetime": {
				Type:         schema.TypeFloat,
				Optional:     true,
				Computed:     true,
				ValidateFunc: validation.FloatAtLeast(0.01),
				Description:  "Number of hours during which a session can be inactive before the user must log in again",
			},
			"enabled_locales": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
				Computed: true,
				Description: "Supported locales for the user interface. " +
					"The first locale in the list will be used to set the default locale",
			},
			"flags": {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				MaxItems:    1,
				Description: "Configuration settings for tenant flags",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"change_pwd_flow_v1": {
							Type:     schema.TypeBool,
							Optional: true,
							Computed: true,
							Description: "Indicates whether or not to use the older v1 change password flow. " +
								"Not recommended except for backward compatibility",
						},
						"enable_client_connections": {
							Type:     schema.TypeBool,
							Optional: true,
							Computed: true,
							Description: "Indicates whether or not all current connections should be enabled when a" +
								" new client is created",
						},
						"enable_apis_section": {
							Type:        schema.TypeBool,
							Optional:    true,
							Computed:    true,
							Description: "Indicates whether or not the APIs section is enabled for the tenant",
						},
						"enable_pipeline2": {
							Type:        schema.TypeBool,
							Optional:    true,
							Computed:    true,
							Description: "Indicates whether or not advanced API Authorization scenarios are enabled",
						},
						"enable_dynamic_client_registration": {
							Type:        schema.TypeBool,
							Optional:    true,
							Computed:    true,
							Description: "Indicates whether or not the tenant allows dynamic client registration",
						},
						"enable_custom_domain_in_emails": {
							Type:        schema.TypeBool,
							Optional:    true,
							Computed:    true,
							Description: "Indicates whether or not the tenant allows custom domains in emails",
						},
						"universal_login": {
							Type:        schema.TypeBool,
							Optional:    true,
							Computed:    true,
							Description: "Indicates whether or not the tenant uses universal login",
						},
						"enable_legacy_logs_search_v2": {
							Type:        schema.TypeBool,
							Optional:    true,
							Computed:    true,
							Description: "Indicates whether or not to use the older v2 legacy logs search",
						},
						"disable_clickjack_protection_headers": {
							Type:     schema.TypeBool,
							Optional: true,
							Computed: true,
							Description: "Indicated whether or not classic Universal Login prompts include additional" +
								" security headers to prevent clickjacking",
						},
						"enable_public_signup_user_exists_error": {
							Type:     schema.TypeBool,
							Optional: true,
							Computed: true,
							Description: "Indicates whether or not the public sign up process shows a user_exists" +
								" error if the user already exists",
						},
						"use_scope_descriptions_for_consent": {
							Type:     schema.TypeBool,
							Optional: true,
							Computed: true,
						},
					},
				},
			},
			"universal_login": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"colors": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"primary": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"page_background": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
								},
							},
						},
					},
				},
			},
			"default_redirection_uri": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ValidateFunc: validation.All(
					v.IsURLWithNoFragment,
					validation.IsURLWithScheme([]string{"https"}),
				),
			},
		},
	}
}

func createTenant(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId(resource.UniqueId())
	return updateTenant(ctx, d, m)
}

func readTenant(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	t, err := api.Tenant.Read(management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	_ = d.Set("change_password", flattenTenantChangePassword(t.ChangePassword))
	_ = d.Set("guardian_mfa_page", flattenTenantGuardianMFAPage(t.GuardianMFAPage))

	_ = d.Set("default_audience", t.DefaultAudience)
	_ = d.Set("default_directory", t.DefaultDirectory)

	_ = d.Set("friendly_name", t.FriendlyName)
	_ = d.Set("picture_url", t.PictureURL)
	_ = d.Set("support_email", t.SupportEmail)
	_ = d.Set("support_url", t.SupportURL)
	_ = d.Set("allowed_logout_urls", t.AllowedLogoutURLs)
	_ = d.Set("session_lifetime", t.SessionLifetime)
	_ = d.Set("idle_session_lifetime", t.IdleSessionLifetime)
	_ = d.Set("sandbox_version", t.SandboxVersion)
	_ = d.Set("enabled_locales", t.EnabledLocales)

	_ = d.Set("error_page", flattenTenantErrorPage(t.ErrorPage))
	_ = d.Set("flags", flattenTenantFlags(t.Flags))
	_ = d.Set("universal_login", flattenTenantUniversalLogin(t.UniversalLogin))

	return nil
}

func updateTenant(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	t := buildTenant(d)
	api := m.(*management.Management)
	err := api.Tenant.Update(t, management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	return readTenant(ctx, d, m)
}

func deleteTenant(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}

func buildTenant(d *schema.ResourceData) *management.Tenant {
	t := &management.Tenant{
		DefaultAudience:     String(d, "default_audience"),
		DefaultDirectory:    String(d, "default_directory"),
		FriendlyName:        String(d, "friendly_name"),
		PictureURL:          String(d, "picture_url"),
		SupportEmail:        String(d, "support_email"),
		SupportURL:          String(d, "support_url"),
		AllowedLogoutURLs:   Slice(d, "allowed_logout_urls"),
		SessionLifetime:     Float64(d, "session_lifetime"),
		SandboxVersion:      String(d, "sandbox_version"),
		IdleSessionLifetime: Float64(d, "idle_session_lifetime", IsNewResource(), HasChange()),
		EnabledLocales:      List(d, "enabled_locales").List(),
		ChangePassword:      expandTenantChangePassword(d),
		GuardianMFAPage:     expandTenantGuardianMFAPage(d),
		ErrorPage:           expandTenantErrorPage(d),
		Flags:               expandTenantFlags(d),
		UniversalLogin:      expandTenantUniversalLogin(d),
	}

	return t
}
