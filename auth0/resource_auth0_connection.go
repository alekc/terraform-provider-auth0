package auth0

import (
	"context"
	"log"
	"strconv"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
	v "github.com/alekc/terraform-provider-auth0/auth0/internal/validation"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

func newConnection() *schema.Resource {
	return &schema.Resource{
		CreateContext: createConnection,
		ReadContext:   readConnection,
		UpdateContext: updateConnection,
		DeleteContext: deleteConnection,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Description: `
With Auth0, you can define sources of users, otherwise known as connections, 
which may include identity providers (such as Google or LinkedIn), databases, 
or passwordless authentication methods. This resource allows you to configure and manage connections to be used with
your clients and users.
`,
		Schema:        connectionSchema,
		SchemaVersion: 2,
		StateUpgraders: []schema.StateUpgrader{
			{
				Type:    connectionSchemaV0().CoreConfigSchema().ImpliedType(),
				Upgrade: connectionSchemaUpgradeV0,
				Version: 0,
			},
			{
				Type:    connectionSchemaV1().CoreConfigSchema().ImpliedType(),
				Upgrade: connectionSchemaUpgradeV1,
				Version: 1,
			},
		},
	}
}

var connectionSchema = map[string]*schema.Schema{
	"name": {
		Type:        schema.TypeString,
		Required:    true,
		ForceNew:    true,
		Description: "Name of the connection",
	},
	"display_name": {
		Type:        schema.TypeString,
		Optional:    true,
		Description: "Name used in login screen",
	},
	"is_domain_connection": {
		Type:        schema.TypeBool,
		Optional:    true,
		Computed:    true,
		Description: "Indicates whether or not the connection is domain level",
	},
	"strategy": {
		Type:         schema.TypeString,
		Required:     true,
		ValidateFunc: v.IsAuth0Strategy,
		ForceNew:     true,
		Description: "Type of the connection, which indicates the identity provider. Options include `ad`, `adfs`, " +
			"`amazon`, `apple`, `dropbox`, `bitbucket`, `aol`,`auth0-adldap`, `auth0-oidc`, `auth0`, `baidu`, " +
			"`bitly`,`box`, `custom`, `daccount`, `dwolla`, `email`,`evernote-sandbox`, `evernote`, `exact`, " +
			"`facebook`,`fitbit`, `flickr`, `github`, `google-apps`,`google-oauth2`, `guardian`, `instagram`, `ip`, " +
			"`linkedin`,`miicard`, `oauth1`, `oauth2`, `office365`, `oidc`, `paypal`,`paypal-sandbox`, " +
			"`pingfederate`, `planningcenter`,`renren`, `salesforce-community`, `salesforce-sandbox`,`salesforce`, " +
			"`samlp`, `sharepoint`, `shopify`, `sms`,`soundcloud`, `thecity-sandbox`, `thecity`,`thirtysevensignals`," +
			" `twitter`, `untappd`, `vkontakte`,`waad`, `weibo`, `windowslive`, `wordpress`, `yahoo`,`yammer`, " +
			"`yandex`, `line`",
	},
	"options": {
		Type:     schema.TypeList,
		Required: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"validation": {
					Type:        schema.TypeList,
					MaxItems:    1,
					Description: "Validation of the minimum and maximum values allowed for a user to have as username",
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"username": {
								Optional:    true,
								Type:        schema.TypeList,
								MaxItems:    1,
								Description: "Specifies the min and max values of username length",
								Elem: &schema.Resource{
									Schema: map[string]*schema.Schema{
										"min": {
											Type:         schema.TypeInt,
											Optional:     true,
											ValidateFunc: validation.IntAtLeast(1),
										},
										"max": {
											Type:         schema.TypeInt,
											Optional:     true,
											ValidateFunc: validation.IntAtLeast(1),
										},
									},
								},
							},
						},
					},
					Optional: true,
				},
				"password_policy": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						"none", "low", "fair", "good", "excellent",
					}, false),
					Description: "Indicates level of password strength to enforce during authentication. A strong password policy will make it difficult, if not improbable, for someone to guess a password through either manual or automated means. Options include `none`, `low`, `fair`, `good`, `excellent`",
				},
				"password_history": {
					Type:     schema.TypeList,
					Optional: true,
					Computed: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"enable": {
								Type:     schema.TypeBool,
								Optional: true,
							},
							"size": {
								Type:     schema.TypeInt,
								Optional: true,
							},
						},
					},
					Description: "Configuration settings for the password history that is maintained for each user to prevent the reuse of passwords",
				},
				"password_no_personal_info": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"enable": {
								Type:     schema.TypeBool,
								Optional: true,
							},
						},
					},
					Description: "Configuration settings for the password personal info check, which does not allow passwords that contain any part of the user's personal data, including user's name, username, nickname, user_metadata.name, user_metadata.first, user_metadata.last, user's email, or firstpart of the user's email",
				},
				"password_dictionary": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"enable": {
								Type:     schema.TypeBool,
								Optional: true,
							},
							"dictionary": {
								Type:     schema.TypeSet,
								Elem:     &schema.Schema{Type: schema.TypeString},
								Optional: true,
							},
						},
					},
					Description: "Configuration settings for the password dictionary check, which does not allow passwords that are part of the password dictionary",
				},
				"password_complexity_options": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"min_length": {
								Type:         schema.TypeInt,
								Optional:     true,
								ValidateFunc: validation.IntAtLeast(1),
							},
						},
					},
					Description: "Configuration settings for password complexity",
				},
				"enabled_database_customization": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "",
				},
				"brute_force_protection": {
					Type:        schema.TypeBool,
					Optional:    true,
					Computed:    true,
					Description: "Indicates whether or not to enable brute force protection, which will limit the number of signups and failed logins from a suspicious IP address",
				},
				"import_mode": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "Indicates whether or not you have a legacy user store and want to gradually migrate those users to the Auth0 user store",
				},
				"disable_signup": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "Indicates whether or not to allow user sign-ups to your application",
				},
				"requires_username": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "Indicates whether or not the user is required to provide a username in addition to an email address",
				},
				"custom_scripts": {
					Type:     schema.TypeMap,
					Elem:     &schema.Schema{Type: schema.TypeString},
					Optional: true,
					Description: "Custom database action scripts. For more information, " +
						"read [Custom Database Action Script Templates](https://auth0." +
						"com/docs/connections/database/custom-db/templates)",
				},
				"scripts": {
					Type:        schema.TypeMap,
					Elem:        &schema.Schema{Type: schema.TypeString},
					Optional:    true,
					Description: "",
				},
				"configuration": {
					Type:        schema.TypeMap,
					Elem:        &schema.Schema{Type: schema.TypeString},
					Sensitive:   true,
					Optional:    true,
					Description: "A case-sensitive map of key value pairs used as configuration variables for the `custom_script`",
				},
				"client_id": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "Client ID",
				},
				"client_secret": {
					Type:        schema.TypeString,
					Optional:    true,
					Sensitive:   true,
					Description: "App secret",
				},
				"allowed_audiences": {
					Type:        schema.TypeSet,
					Elem:        &schema.Schema{Type: schema.TypeString},
					Optional:    true,
					Description: "",
				},
				"api_enable_users": {
					Type:     schema.TypeBool,
					Optional: true,
				},
				"app_id": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"app_domain": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
					Deprecated:  "use domain instead",
				},
				"domain": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"domain_aliases": {
					Type:        schema.TypeSet,
					Elem:        &schema.Schema{Type: schema.TypeString},
					Optional:    true,
					Description: "",
				},
				"max_groups_to_retrieve": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"tenant_domain": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"use_wsfed": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "",
				},
				"waad_protocol": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"waad_common_endpoint": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "",
				},
				"icon_url": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"identity_api": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"ips": {
					Type: schema.TypeSet,
					Elem: &schema.Schema{
						Type:         schema.TypeString,
						ValidateFunc: validation.IsIPAddress,
					},
					Optional:    true,
					Description: "",
				},
				"use_cert_auth": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "",
				},
				"use_kerberos": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "",
				},
				"disable_cache": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "",
				},
				"name": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"twilio_sid": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"twilio_token": {
					Type:        schema.TypeString,
					Optional:    true,
					Sensitive:   true,
					DefaultFunc: schema.EnvDefaultFunc("TWILIO_TOKEN", nil),
					Description: "",
				},
				"from": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"syntax": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"subject": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"template": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"totp": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"time_step": {
								Type:     schema.TypeInt,
								Optional: true,
							},
							"length": {
								Type:     schema.TypeInt,
								Optional: true,
							},
						},
					},
					Description: "",
				},
				"messaging_service_sid": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"mfa": {
					Type:     schema.TypeList,
					MaxItems: 1,
					Optional: true,
					Computed: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"active": {
								Type:     schema.TypeBool,
								Optional: true,
							},
							"return_enroll_settings": {
								Type:     schema.TypeBool,
								Optional: true,
							},
						},
					},
				},

				"set_user_root_attributes": {
					Type:     schema.TypeString,
					Optional: true,
					Computed: true,
					ValidateFunc: validation.StringInSlice([]string{
						"on_each_login", "on_first_login",
					}, false),
					Description: "Determines whether the 'name', 'given_name', 'family_name', 'nickname', and 'picture' attributes can be independently updated when using an external IdP. Possible values are 'on_each_login' (default value, it configures the connection to automatically update the root attributes from the external IdP with each user login. When this setting is used, root attributes cannot be independently updated), 'on_first_login' (configures the connection to only set the root attributes on first login, allowing them to be independently updated thereafter)",
				},
				"non_persistent_attrs": {
					Type:        schema.TypeSet,
					Elem:        &schema.Schema{Type: schema.TypeString},
					Optional:    true,
					Computed:    true,
					Description: "If there are user fields that should not be stored in Auth0 databases due to privacy reasons, you can add them to the DenyList here",
				},
				"should_trust_email_verified_connection": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"never_set_emails_as_verified", "always_set_emails_as_verified",
					}, false),
					Description: "Choose how Auth0 sets the email_verified field in the user profile.",
				},

				// apple options
				"team_id": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "Apple Team ID",
				},
				"key_id": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "Apple Key ID",
				},

				// adfs options
				"adfs_server": {
					Type:     schema.TypeString,
					Optional: true,
				},

				// salesforce options
				"community_base_url": {
					Type:     schema.TypeString,
					Optional: true,
				},

				"strategy_version": {
					Type:     schema.TypeInt,
					Optional: true,
					Computed: true,
				},

				"scopes": {
					Type:     schema.TypeSet,
					Optional: true,
					Elem:     &schema.Schema{Type: schema.TypeString},
				},

				// OIDC options
				"type": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"issuer": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"jwks_uri": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"discovery_url": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"token_endpoint": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"userinfo_endpoint": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"authorization_endpoint": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				// SAML options
				"debug": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "When enabled, additional debug information will be generated.",
				},
				"signing_cert": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "X.509 signing certificate (encoded in PEM or CER) you retrieved from the IdP, Base64-encoded",
				},
				"metadata_xml": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "XML content of the document for saml",
				},
				"metadata_url": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "Url of the document for saml connection expressed in xml",
				},
				"protocol_binding": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "The SAML Response Binding: how the SAML token is received by Auth0 from IdP",
					ValidateFunc: validation.StringInSlice([]string{
						"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
						"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					}, true),
				},
				"request_template": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "Template that formats the SAML request.",
				},
				"user_id_attribute": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "Attribute in the SAML token that will be mapped to the user_id property in Auth0.",
				},
				"idp_initiated": {
					Type:     schema.TypeList,
					MaxItems: 1,
					Required: false,
					Optional: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"client_id": {
								Type:     schema.TypeString,
								Optional: true,
							},
							"client_protocol": {
								Type:     schema.TypeString,
								Optional: true,
							},
							"client_authorize_query": {
								Type:     schema.TypeString,
								Optional: true,
							},
						},
					},
				},
				"sign_in_endpoint": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "SAML single login URL for the connection.",
				},
				"sign_out_endpoint": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "SAML single logout URL for the connection.",
				},
				"fields_map": {
					Type:        schema.TypeMap,
					Elem:        &schema.Schema{Type: schema.TypeString},
					Optional:    true,
					Description: "If you're configuring a SAML enterprise connection for a non-standard PingFederate Server, you must update the attribute mappings.",
				},
				"sign_saml_request": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "When enabled, the SAML authentication request will be signed.",
				},
				"signature_algorithm": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "Sign Request Algorithm",
				},
				"digest_algorithm": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "Sign Request Algorithm Digest",
				},
			},
		},
		Description: "Configuration settings for connection options",
	},
	"enabled_clients": {
		Type:        schema.TypeSet,
		Elem:        &schema.Schema{Type: schema.TypeString},
		Optional:    true,
		Computed:    true,
		Description: "IDs of the clients for which the connection is enabled",
	},
	"realms": {
		Type:        schema.TypeList,
		Elem:        &schema.Schema{Type: schema.TypeString},
		Optional:    true,
		Computed:    true,
		Description: "Defines the realms for which the connection will be used (i.e., email domains). If not specified, the connection name is added as the realm",
	},
}

func connectionSchemaV0() *schema.Resource {
	s := connectionSchema
	s["strategy_version"] = &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Computed: true,
	}
	return &schema.Resource{Schema: s}
}

func connectionSchemaV1() *schema.Resource {
	s := connectionSchema
	s["validation"] = &schema.Schema{
		Type:     schema.TypeMap,
		Elem:     &schema.Schema{Type: schema.TypeString},
		Optional: true,
	}
	return &schema.Resource{Schema: s}
}

func connectionSchemaUpgradeV0(ctx context.Context, state map[string]interface{}, meta interface{}) (map[string]interface{}, error) {
	o, ok := state["options"]
	if !ok {
		return state, nil
	}

	l, ok := o.([]interface{})
	if ok && len(l) > 0 {

		m := l[0].(map[string]interface{})

		v, ok := m["strategy_version"]
		if !ok {
			return state, nil
		}

		s, ok := v.(string)
		if !ok {
			return state, nil
		}

		i, err := strconv.Atoi(s)
		if err == nil {
			m["strategy_version"] = i
		} else {
			m["strategy_version"] = 0
		}

		state["options"] = []interface{}{m}

		log.Printf("[DEBUG] Schema upgrade: options.strategy_version has been migrated to %d", i)
	}

	return state, nil
}

func connectionSchemaUpgradeV1(ctx context.Context, state map[string]interface{}, meta interface{}) (map[string]interface{}, error) {

	o, ok := state["options"]
	if !ok {
		return state, nil
	}

	l, ok := o.([]interface{})
	if ok && len(l) > 0 {

		m := l[0].(map[string]interface{})

		v, ok := m["validation"]
		if !ok {
			return state, nil
		}

		validator := v.(interface{})

		m["validation"] = []map[string][]interface{}{
			{
				"username": []interface{}{validator},
			},
		}

		state["options"] = []interface{}{m}

		log.Print("[DEBUG] Schema upgrade: options.validation has been migrated to options.validation.user")
	}

	return state, nil
}

func createConnection(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := expandConnection(d)
	api := m.(*management.Management)
	if err := api.Connection.Create(c, management.Context(ctx)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(auth0.StringValue(c.ID))
	return readConnection(ctx, d, m)
}

func readConnection(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	c, err := api.Connection.Read(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	d.SetId(auth0.StringValue(c.ID))
	_ = d.Set("name", c.Name)
	_ = d.Set("display_name", c.DisplayName)
	_ = d.Set("is_domain_connection", c.IsDomainConnection)
	_ = d.Set("strategy", c.Strategy)
	_ = d.Set("options", flattenConnectionOptions(d, c.Options))
	_ = d.Set("enabled_clients", c.EnabledClients)
	_ = d.Set("realms", c.Realms)
	return nil
}

func updateConnection(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := expandConnection(d)
	api := m.(*management.Management)
	err := api.Connection.Update(d.Id(), c, management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	return readConnection(ctx, d, m)
}

func deleteConnection(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	err := api.Connection.Delete(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	return nil
}
