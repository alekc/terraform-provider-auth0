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
	}
}

var connectionSchemaClientID = &schema.Schema{
	Type:        schema.TypeString,
	Optional:    true,
	Description: "Client ID",
}
var connectionSchemaClientSecret = &schema.Schema{
	Type:        schema.TypeString,
	Optional:    true,
	Sensitive:   true,
	Description: "App secret",
}
var connectionSchemaScopes = &schema.Schema{
	Type:     schema.TypeSet,
	Optional: true,
	Elem:     &schema.Schema{Type: schema.TypeString},
}
var connectionSchemaStrategyVersion = &schema.Schema{
	Type:     schema.TypeInt,
	Optional: true,
	Computed: true,
}
var connectionSchemaSetUserRootAttributes = &schema.Schema{
	Type:     schema.TypeString,
	Optional: true,
	Computed: true,
	ValidateFunc: validation.StringInSlice([]string{
		"on_each_login", "on_first_login",
	}, false),
	Description: "Determines whether the 'name', 'given_name', 'family_name', 'nickname', and 'picture' attributes can be " +
		"independently updated when using an external IdP. Possible values are 'on_each_login' (default value, it configures " +
		"the connection to automatically update the root attributes from the external IdP with each user login. When this " +
		"setting is used, root attributes cannot be independently updated), 'on_first_login' (configures the connection to" +
		" only set the root attributes on first login, allowing them to be independently updated thereafter)",
}
var connectionSchemaNonPersistentAttributes = &schema.Schema{
	Type:     schema.TypeSet,
	Elem:     &schema.Schema{Type: schema.TypeString},
	Optional: true,
	Computed: true,
	Description: "If there are user fields that should not be stored in Auth0 databases due to privacy reasons, you can add" +
		" them to the DenyList here",
}
var connectionSchemaDisableSignup = &schema.Schema{
	Type:        schema.TypeBool,
	Optional:    true,
	Default:     false,
	Description: "Indicates whether or not to allow user sign-ups to your application",
}
var connectionSchemaBruteForceProtection = &schema.Schema{
	Type:        schema.TypeBool,
	Optional:    true,
	Default:     true,
	Description: "Indicates whether or not to enable brute force protection, which will limit the number of signups and failed logins from a suspicious IP address",
}
var connectionSchemaAuthorizationEndpoint = &schema.Schema{
	Type:        schema.TypeString,
	Optional:    true,
	Description: "",
}
var connectionSchemaTokenEndpoint = &schema.Schema{
	Type:        schema.TypeString,
	Optional:    true,
	Description: "",
}
var connectionSchemaDomainAliases = &schema.Schema{
	Type:        schema.TypeSet,
	Elem:        &schema.Schema{Type: schema.TypeString},
	Optional:    true,
	Description: "",
}
var connectionSchemaTenantDomain = &schema.Schema{
	Type:        schema.TypeString,
	Optional:    true,
	Description: "",
}
var connectionSchemaIconURL = &schema.Schema{
	Type:        schema.TypeString,
	Optional:    true,
	Description: "",
}
var connectionSchemaTotp = &schema.Schema{
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
}
var connectionOptionBlocks = []string{
	management.ConnectionStrategyAuth0,
	"google_oauth2",
	management.ConnectionStrategyOAuth2,
	management.ConnectionStrategyFacebook,
	management.ConnectionStrategyApple,
	management.ConnectionStrategyLinkedin,
	management.ConnectionStrategyGitHub,
	management.ConnectionStrategyWindowsLive,
	management.ConnectionStrategySalesforce,
	management.ConnectionStrategySMS,
	management.ConnectionStrategyOIDC,
	management.ConnectionStrategyAD,
	management.ConnectionStrategyAzureAD,
	management.ConnectionStrategyEmail,
	management.ConnectionStrategySAML,
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
	"enabled_clients": {
		Type:        schema.TypeSet,
		Elem:        &schema.Schema{Type: schema.TypeString},
		Optional:    true,
		Description: "IDs of the clients for which the connection is enabled",
	},
	"realms": {
		Type:        schema.TypeList,
		Elem:        &schema.Schema{Type: schema.TypeString},
		Optional:    true,
		Description: "Defines the realms for which the connection will be used (i.e., email domains). If not specified, the connection name is added as the realm",
	},
	management.ConnectionStrategyAuth0: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Auth0 hosted database connection",
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
					Default:  "good",
					ValidateFunc: validation.StringInSlice([]string{
						"none", "low", "fair", "good", "excellent",
					}, false),
					Description: "Indicates level of password strength to enforce during authentication. A strong password policy will make it difficult, if not improbable, for someone to guess a password through either manual or automated means. Options include `none`, `low`, `fair`, `good`, `excellent`",
				},
				"non_persistent_attrs": connectionSchemaNonPersistentAttributes,
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
				"mfa_active": {
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     true,
					Description: "",
				},
				"mfa_return_enroll_settings": {
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     true,
					Description: "",
				},
				"enabled_database_customization": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "",
				},
				"brute_force_protection": connectionSchemaBruteForceProtection,
				"import_mode": {
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     false,
					Description: "Indicates whether or not you have a legacy user store and want to gradually migrate those users to the Auth0 user store",
				},
				"disable_signup": connectionSchemaDisableSignup,
				"requires_username": {
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     false,
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
				"configuration": {
					Type: schema.TypeMap,
					Elem: &schema.Schema{Type: schema.TypeString},
					// Sensitive: true,
					Optional: true,
					Description: "A case-sensitive map of key value pairs used as configuration variables for the" +
						" `custom_script`. NOTE: this field will not detect any drifting originating from auth0",
				},
			},
		},
	},
	"google_oauth2": {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Google/Gmail social connection ",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"client_id":     connectionSchemaClientID,
				"client_secret": connectionSchemaClientSecret,
				"allowed_audiences": {
					Type:        schema.TypeSet,
					Elem:        &schema.Schema{Type: schema.TypeString},
					Optional:    true,
					Description: "Allowed audience",
				},
				"set_user_root_attributes": connectionSchemaSetUserRootAttributes,
				"non_persistent_attrs":     connectionSchemaNonPersistentAttributes,
			},
		},
	},
	management.ConnectionStrategyOAuth2: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Oauth2 connection ",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"client_id":                connectionSchemaClientID,
				"client_secret":            connectionSchemaClientSecret,
				"authorization_endpoint":   connectionSchemaAuthorizationEndpoint,
				"token_endpoint":           connectionSchemaTokenEndpoint,
				"set_user_root_attributes": connectionSchemaSetUserRootAttributes,
				"non_persistent_attrs":     connectionSchemaNonPersistentAttributes,
				"scripts": {
					Type:        schema.TypeMap,
					Elem:        &schema.Schema{Type: schema.TypeString},
					Optional:    true,
					Description: "",
				},
				"scopes": connectionSchemaScopes,
			},
		},
	},
	management.ConnectionStrategyFacebook: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Facebook connection ",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"client_id":                connectionSchemaClientID,
				"client_secret":            connectionSchemaClientSecret,
				"set_user_root_attributes": connectionSchemaSetUserRootAttributes,
				"non_persistent_attrs":     connectionSchemaNonPersistentAttributes,
			},
		},
	},
	management.ConnectionStrategyApple: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Apple connection ",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"client_id":     connectionSchemaClientID,
				"client_secret": connectionSchemaClientSecret,
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
				"set_user_root_attributes": connectionSchemaSetUserRootAttributes,
				"non_persistent_attrs":     connectionSchemaNonPersistentAttributes,
			},
		},
	},
	management.ConnectionStrategyLinkedin: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Linkedin connection",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"client_id":                connectionSchemaClientID,
				"client_secret":            connectionSchemaClientSecret,
				"strategy_version":         connectionSchemaStrategyVersion,
				"set_user_root_attributes": connectionSchemaSetUserRootAttributes,
				"non_persistent_attrs":     connectionSchemaNonPersistentAttributes,
			},
		},
	},
	management.ConnectionStrategyGitHub: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Github connection",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"client_id":                connectionSchemaClientID,
				"client_secret":            connectionSchemaClientSecret,
				"set_user_root_attributes": connectionSchemaSetUserRootAttributes,
				"non_persistent_attrs":     connectionSchemaNonPersistentAttributes,
			},
		},
	},
	management.ConnectionStrategyWindowsLive: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Windows Live connection",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"client_id":                connectionSchemaClientID,
				"client_secret":            connectionSchemaClientSecret,
				"strategy_version":         connectionSchemaStrategyVersion,
				"set_user_root_attributes": connectionSchemaSetUserRootAttributes,
				"non_persistent_attrs":     connectionSchemaNonPersistentAttributes,
			},
		},
	},
	management.ConnectionStrategySalesforce: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Salesforce connection",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"type": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"community", "sandbox",
					}, false),
					Description: "If set, indicates what type of salesforce connection. " +
						"Possible values are `community`,`sandbox`",
					ForceNew: true,
				},
				"client_id":     connectionSchemaClientID,
				"client_secret": connectionSchemaClientSecret,
				"community_base_url": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "Used only if type is `community`",
				},
				"set_user_root_attributes": connectionSchemaSetUserRootAttributes,
				"non_persistent_attrs":     connectionSchemaNonPersistentAttributes,
				"scopes":                   connectionSchemaScopes,
			},
		},
	},
	management.ConnectionStrategySMS: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Twillo SMS connection",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:        schema.TypeString,
					Optional:    true,
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
				"template": {
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
				"messaging_service_sid": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"disable_signup":         connectionSchemaDisableSignup,
				"brute_force_protection": connectionSchemaBruteForceProtection,
				"totp":                   connectionSchemaTotp,
			},
		},
	},
	management.ConnectionStrategyOIDC: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "OIDC connection",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"client_id":      connectionSchemaClientID,
				"client_secret":  connectionSchemaClientSecret,
				"tenant_domain":  connectionSchemaTenantDomain,
				"domain_aliases": connectionSchemaDomainAliases,
				"icon_url":       connectionSchemaIconURL,
				"discovery_url": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"authorization_endpoint": connectionSchemaAuthorizationEndpoint,
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
				"type": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"userinfo_endpoint": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"token_endpoint":           connectionSchemaTokenEndpoint,
				"set_user_root_attributes": connectionSchemaSetUserRootAttributes,
				"non_persistent_attrs":     connectionSchemaNonPersistentAttributes,
				"scopes":                   connectionSchemaScopes,
			},
		},
	},
	management.ConnectionStrategyAD: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Active Directory connection",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"domain_aliases": connectionSchemaDomainAliases,
				"tenant_domain":  connectionSchemaTenantDomain,
				"icon_url":       connectionSchemaIconURL,
				"ips": {
					Type: schema.TypeSet,
					Elem: &schema.Schema{
						Type:         schema.TypeString,
						ValidateFunc: validation.IsIPAddress,
					},
					Optional: true,
					Description: "When users log in through these IP addresses, " +
						"use Windows Integrated Auth (Kerberos). Otherwise not, ask for Active Directory/LDAP username and password.",
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
				"brute_force_protection":   connectionSchemaBruteForceProtection,
				"set_user_root_attributes": connectionSchemaSetUserRootAttributes,
				"non_persistent_attrs":     connectionSchemaNonPersistentAttributes,
			},
		},
	},
	management.ConnectionStrategyAzureAD: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Microsoft Azure enterprise connection",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"client_id":     connectionSchemaClientID,
				"client_secret": connectionSchemaClientSecret,
				"app_id": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"domain": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"domain_aliases": connectionSchemaDomainAliases,
				"tenant_domain":  connectionSchemaTenantDomain,
				"max_groups_to_retrieve": {
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
					Description: "If enabled, will use a common Endpoint",
				},
				"api_enable_users": {
					Type:     schema.TypeBool,
					Optional: true,
				},
				"icon_url": connectionSchemaIconURL,
				"identity_api": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"should_trust_email_verified_connection": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"never_set_emails_as_verified", "always_set_emails_as_verified",
					}, false),
					Description: "Choose how Auth0 sets the email_verified field in the user profile.",
				},
				"set_user_root_attributes": connectionSchemaSetUserRootAttributes,
				"non_persistent_attrs":     connectionSchemaNonPersistentAttributes,
				"scopes":                   connectionSchemaScopes,
			},
		},
	},
	management.ConnectionStrategyEmail: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Passwordless Email connection",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"disable_signup": connectionSchemaDisableSignup,
				"syntax": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "",
				},
				"from": {
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
				"brute_force_protection":   connectionSchemaBruteForceProtection,
				"totp":                     connectionSchemaTotp,
				"set_user_root_attributes": connectionSchemaSetUserRootAttributes,
				"non_persistent_attrs":     connectionSchemaNonPersistentAttributes,
			},
		},
	},
	management.ConnectionStrategySAML: {
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Windows Live connection",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
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
				"protocol_binding": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "The SAML Response Binding: how the SAML token is received by Auth0 from IdP",
					ValidateFunc: validation.StringInSlice([]string{
						"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
						"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					}, true),
				},
				"tenant_domain":  connectionSchemaTenantDomain,
				"domain_aliases": connectionSchemaDomainAliases,
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
				"icon_url": connectionSchemaIconURL,
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
				"set_user_root_attributes": connectionSchemaSetUserRootAttributes,
				"non_persistent_attrs":     connectionSchemaNonPersistentAttributes,
			},
		},
	},
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

// By default,(?) Auth0 appends to the realm the name of the connection itself which breaks the terraform state
// triggering permanent diff
func readRealms(d *schema.ResourceData, realms []interface{}, name string) []interface{} {
	// if we have a name stored inside the previous realm already (for some reason), return data as it is
	for _, v := range List(d, "realms").List() {
		if v.(string) == name {
			return realms
		}
	}

	// if the last element of the realms is the name, then it had been appended by the auth0.
	// Return the slice without it
	realmLength := len(realms)
	if realmLength > 0 && realms[realmLength-1].(string) == name {
		return realms[0 : realmLength-1]
	}
	return realms
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
	_ = d.Set("enabled_clients", c.EnabledClients)
	_ = d.Set("realms", readRealms(d, c.Realms, *c.Name))

	switch o := c.Options.(type) {
	case *management.ConnectionOptions:
		_ = d.Set(management.ConnectionStrategyAuth0, flattenMap(flattenConnectionOptionsAuth0(d, o), false))
	case *management.ConnectionOptionsGoogleOAuth2:
		_ = d.Set("google_oauth2", flattenMap(flattenConnectionOptionsGoogleOAuth2(o), false))
	case *management.ConnectionOptionsOAuth2:
		_ = d.Set(management.ConnectionStrategyOAuth2, flattenMap(flattenConnectionOptionsOAuth2(o), false))
	case *management.ConnectionOptionsFacebook:
		_ = d.Set(management.ConnectionStrategyFacebook, flattenMap(flattenConnectionOptionsFacebook(o), true))
	case *management.ConnectionOptionsApple:
		_ = d.Set(management.ConnectionStrategyApple, flattenMap(flattenConnectionOptionsApple(o), true))
	case *management.ConnectionOptionsLinkedin:
		_ = d.Set(management.ConnectionStrategyLinkedin, flattenMap(flattenConnectionOptionsLinkedin(o), true))
	case *management.ConnectionOptionsGitHub:
		_ = d.Set(management.ConnectionStrategyGitHub, flattenMap(flattenConnectionOptionsGitHub(o), true))
	case *management.ConnectionOptionsWindowsLive:
		_ = d.Set(management.ConnectionStrategyWindowsLive, flattenMap(flattenConnectionOptionsWindowsLive(o), true))
	case *management.ConnectionOptionsSalesforce:
		_ = d.Set(management.ConnectionStrategySalesforce, flattenMap(flattenConnectionOptionsSalesforce(o), true))
	case *management.ConnectionOptionsEmail:
		_ = d.Set(management.ConnectionStrategyEmail, flattenMap(flattenConnectionOptionsEmail(o), true))
	case *management.ConnectionOptionsSMS:
		_ = d.Set(management.ConnectionStrategySMS, flattenMap(flattenConnectionOptionsSMS(o), true))
	case *management.ConnectionOptionsOIDC:
		_ = d.Set(management.ConnectionStrategyOIDC, flattenMap(flattenConnectionOptionsOIDC(o), true))
	case *management.ConnectionOptionsAD:
		_ = d.Set(management.ConnectionStrategyAD, flattenMap(flattenConnectionOptionsAD(o), true))
	case *management.ConnectionOptionsAzureAD:
		_ = d.Set(management.ConnectionStrategyAzureAD, flattenMap(flattenConnectionOptionsAzureAD(o), true))
	case *management.ConnectionOptionsSAML:
		_ = d.Set(management.ConnectionStrategySAML, flattenMap(flattenConnectionOptionsSAML(o), true))
	}

	return nil
}

func updateConnection(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := expandConnection(d)
	// unset the strategy field, otherwise Auth0 will freak out (you cannot change it)
	c.Strategy = nil
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
