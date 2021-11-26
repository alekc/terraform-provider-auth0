package auth0

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceConnection() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceConnectionRead,
		Description: `Retrieve an auth0 connection`,
		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the connection",
			},
			"name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the connection",
			},
			"display_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name used in login screen",
			},
			"is_domain_connection": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates whether or not the connection is domain level",
			},
			"strategy": {
				Type:     schema.TypeString,
				Computed: true,
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
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Configuration settings for connection options",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"validation": {
							Type:        schema.TypeList,
							Description: "Validation of the minimum and maximum values allowed for a user to have as username",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"username": {
										Computed:    true,
										Type:        schema.TypeList,
										Description: "Specifies the min and max values of username length",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"min": {
													Type:     schema.TypeInt,
													Computed: true,
												},
												"max": {
													Type:     schema.TypeInt,
													Computed: true,
												},
											},
										},
									},
								},
							},
							Computed: true,
						},
						"password_policy": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Indicates level of password strength to enforce during authentication. A strong password policy will make it difficult, if not improbable, for someone to guess a password through either manual or automated means. Options include `none`, `low`, `fair`, `good`, `excellent`",
						},
						"password_history": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enable": {
										Type:     schema.TypeBool,
										Computed: true,
									},
									"size": {
										Type:     schema.TypeInt,
										Computed: true,
									},
								},
							},
							Description: "Configuration settings for the password history that is maintained for each user to prevent the reuse of passwords",
						},
						"password_no_personal_info": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enable": {
										Type:     schema.TypeBool,
										Computed: true,
									},
								},
							},
							Description: "Configuration settings for the password personal info check, which does not allow passwords that contain any part of the user's personal data, including user's name, username, nickname, user_metadata.name, user_metadata.first, user_metadata.last, user's email, or firstpart of the user's email",
						},
						"password_dictionary": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enable": {
										Type:     schema.TypeBool,
										Computed: true,
									},
									"dictionary": {
										Type:     schema.TypeSet,
										Elem:     &schema.Schema{Type: schema.TypeString},
										Computed: true,
									},
								},
							},
							Description: "Configuration settings for the password dictionary check, which does not allow passwords that are part of the password dictionary",
						},
						"password_complexity_options": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"min_length": {
										Type:     schema.TypeInt,
										Computed: true,
									},
								},
							},
							Description: "Configuration settings for password complexity",
						},
						"enabled_database_customization": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "",
						},
						"brute_force_protection": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Indicates whether or not to enable brute force protection, which will limit the number of signups and failed logins from a suspicious IP address",
						},
						"import_mode": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Indicates whether or not you have a legacy user store and want to gradually migrate those users to the Auth0 user store",
						},
						"disable_signup": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Indicates whether or not to allow user sign-ups to your application",
						},
						"requires_username": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Indicates whether or not the user is required to provide a username in addition to an email address",
						},
						"custom_scripts": {
							Type:     schema.TypeMap,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Computed: true,
							Description: "Custom database action scripts. For more information, " +
								"read [Custom Database Action Script Templates](https://auth0." +
								"com/docs/connections/database/custom-db/templates)",
						},
						"scripts": {
							Type:        schema.TypeMap,
							Elem:        &schema.Schema{Type: schema.TypeString},
							Computed:    true,
							Description: "",
						},
						"configuration": {
							Type:      schema.TypeMap,
							Elem:      &schema.Schema{Type: schema.TypeString},
							Sensitive: true,
							Computed:  true,
							Description: "Note: Currently empty because the values fetched from Auth0 are encrypted. " +
								"A case-sensitive map of key value pairs used as configuration variables for the `custom_script`",
						},
						"client_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Client ID",
						},
						"client_secret": {
							Type:        schema.TypeString,
							Computed:    true,
							Sensitive:   true,
							Description: "App secret",
						},
						"allowed_audiences": {
							Type:        schema.TypeSet,
							Elem:        &schema.Schema{Type: schema.TypeString},
							Computed:    true,
							Description: "",
						},
						"api_enable_users": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"app_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"app_domain": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
							Deprecated:  "use domain instead",
						},
						"domain": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"domain_aliases": {
							Type:        schema.TypeSet,
							Elem:        &schema.Schema{Type: schema.TypeString},
							Computed:    true,
							Description: "",
						},
						"max_groups_to_retrieve": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"tenant_domain": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"use_wsfed": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "",
						},
						"waad_protocol": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"waad_common_endpoint": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "",
						},
						"icon_url": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"identity_api": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"ips": {
							Type: schema.TypeSet,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Computed:    true,
							Description: "",
						},
						"use_cert_auth": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "",
						},
						"use_kerberos": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "",
						},
						"disable_cache": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "",
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"twilio_sid": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"twilio_token": {
							Type:        schema.TypeString,
							Computed:    true,
							Sensitive:   true,
							Description: "",
						},
						"from": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"syntax": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"subject": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"template": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"totp": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"time_step": {
										Type:     schema.TypeInt,
										Computed: true,
									},
									"length": {
										Type:     schema.TypeInt,
										Computed: true,
									},
								},
							},
							Description: "",
						},
						"messaging_service_sid": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"mfa": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"active": {
										Type:     schema.TypeBool,
										Computed: true,
									},
									"return_enroll_settings": {
										Type:     schema.TypeBool,
										Computed: true,
									},
								},
							},
						},

						"set_user_root_attributes": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Determines whether the 'name', 'given_name', 'family_name', 'nickname', and 'picture' attributes can be independently updated when using an external IdP. Possible values are 'on_each_login' (default value, it configures the connection to automatically update the root attributes from the external IdP with each user login. When this setting is used, root attributes cannot be independently updated), 'on_first_login' (configures the connection to only set the root attributes on first login, allowing them to be independently updated thereafter)",
						},
						"non_persistent_attrs": {
							Type:        schema.TypeSet,
							Elem:        &schema.Schema{Type: schema.TypeString},
							Computed:    true,
							Description: "If there are user fields that should not be stored in Auth0 databases due to privacy reasons, you can add them to the DenyList here",
						},
						"should_trust_email_verified_connection": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Choose how Auth0 sets the email_verified field in the user profile.",
						},

						// apple options
						"team_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Apple Team ID",
						},
						"key_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Apple Key ID",
						},

						// adfs options
						"adfs_server": {
							Type:     schema.TypeString,
							Computed: true,
						},

						// salesforce options
						"community_base_url": {
							Type:     schema.TypeString,
							Computed: true,
						},

						"strategy_version": {
							Type:     schema.TypeInt,
							Computed: true,
						},

						"scopes": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},

						// OIDC options
						"type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"issuer": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"jwks_uri": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"discovery_url": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"token_endpoint": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"userinfo_endpoint": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						"authorization_endpoint": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "",
						},
						// SAML options
						"debug": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "When enabled, additional debug information will be generated.",
						},
						"signing_cert": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "X.509 signing certificate (encoded in PEM or CER) you retrieved from the IdP, Base64-encoded",
						},
						"metadata_xml": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "XML content of the document for saml",
						},
						"metadata_url": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Url of the document for saml connection expressed in xml",
						},
						"protocol_binding": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The SAML Response Binding: how the SAML token is received by Auth0 from IdP",
						},
						"request_template": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Template that formats the SAML request.",
						},
						"user_id_attribute": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Attribute in the SAML token that will be mapped to the user_id property in Auth0.",
						},
						"idp_initiated": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"client_id": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"client_protocol": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"client_authorize_query": {
										Type:     schema.TypeString,
										Computed: true,
									},
								},
							},
						},
						"sign_in_endpoint": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "SAML single login URL for the connection.",
						},
						"sign_out_endpoint": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "SAML single logout URL for the connection.",
						},
						"fields_map": {
							Type:        schema.TypeMap,
							Elem:        &schema.Schema{Type: schema.TypeString},
							Computed:    true,
							Description: "If you're configuring a SAML enterprise connection for a non-standard PingFederate Server, you must update the attribute mappings.",
						},
						"sign_saml_request": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "When enabled, the SAML authentication request will be signed.",
						},
						"signature_algorithm": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Sign Request Algorithm",
						},
						"digest_algorithm": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Sign Request Algorithm Digest",
						},
					},
				},
			},
			"enabled_clients": {
				Type:        schema.TypeSet,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Computed:    true,
				Description: "IDs of the clients for which the connection is enabled",
			},
			"realms": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Computed:    true,
				Description: "Defines the realms for which the connection will be used (i.e., email domains). If not specified, the connection name is added as the realm",
			},
		},
	}
}

func dataSourceConnectionRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId(d.Get("id").(string))
	return readConnection(ctx, d, m)
}
