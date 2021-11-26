package auth0

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceAuth0Client() *schema.Resource {
	return &schema.Resource{

		ReadContext: dataSourceClientRead,
		Description: `Retrieve an auth0 client`,

		Schema: map[string]*schema.Schema{
			"client_id": {
				Type:     schema.TypeString,
				Required: true,
			},
			"name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the client",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Description of the purpose of the client (Max length = 140 characters)",
			},
			"client_secret": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Secret for the client; keep this private",
			},
			"app_type": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "Type of application the client represents. Options include `native`, `spa`, " +
					"`regular_web`, `non_interactive`, `rms`, `box`, `cloudbees`, `concur`, `dropbox`, `mscrm`, " +
					"`echosign`, `egnyte`, `newrelic`, `office365`, `salesforce`, `sentry`, `sharepoint`, `slack`, `springcm`, `zendesk`, `zoom`",
			},
			"logo_uri": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "URL of the logo for the client. Recommended size is 150px x 150px. If none is set, " +
					"the default badge for the application type will be shown",
			},
			"is_first_party": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates whether or not this client is a first-party client",
			},
			"is_token_endpoint_ip_header_trusted": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates whether or not the token endpoint IP header is trusted",
			},
			"oidc_conformant": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates whether or not this client will conform to strict OIDC specifications",
			},
			"callbacks": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
				Description: "URLs that Auth0 may call back to after a user authenticates for the client. " +
					"Make sure to specify the protocol (https://) otherwise the callback may fail in some cases. " +
					"With the exception of custom URI schemes for native clients, all callbacks should use protocol https://",
			},
			"allowed_logout_urls": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Computed:    true,
				Description: "URLs that Auth0 may redirect to after logout",
			},
			"grant_types": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Computed:    true,
				Description: "Types of grants that this client is authorized to use",
			},
			"organization_usage": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "Dictates whether your application can support users logging into an organization. " +
					"Options include: `deny`, `allow`, `require`",
			},
			"organization_require_behavior": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "Specifies what type of prompt to use when your application requires that users select" +
					" their organization. Only applicable when ORG_USAGE is require. Options include: `no_prompt`, " +
					"`pre_login_prompt`",
			},
			"allowed_origins": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
				Description: "URLs that represent valid origins for cross-origin resource sharing. By default, " +
					"all your callback URLs will be allowed",
			},
			"allowed_clients": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
			},
			"web_origins": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Computed:    true,
				Description: "URLs that represent valid web origins for use with web message response mode",
			},
			"jwt_configuration": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Configuration settings for the JWTs issued for this client",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"lifetime_in_seconds": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "Number of seconds during which the JWT will be valid",
						},
						"secret_encoded": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Indicates whether or not the client secret is base64 encoded",
						},
						"scopes": {
							Type:        schema.TypeMap,
							Computed:    true,
							Description: "Permissions (scopes) included in JWTs",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"alg": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Algorithm used to sign JWTs",
						},
					},
				},
			},
			"encryption_key": {
				Type:        schema.TypeMap,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Encryption used for WsFed responses with this client",
			},
			"sso": {
				Type:     schema.TypeBool,
				Computed: true,
				Description: "Applies only to SSO clients and determines whether Auth0 will handle Single Sign On (" +
					"true) or whether the Identity Provider will (false)",
			},
			"sso_disabled": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates whether or not SSO is disabled",
			},
			"cross_origin_auth": {
				Type:     schema.TypeBool,
				Computed: true,
				Description: "Indicates whether or not the client can be used to make cross-origin authentication" +
					" requests",
			},
			"cross_origin_loc": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "URL for the location on your site where the cross-origin verification takes place for" +
					" the cross-origin auth flow. Used when performing auth in your own domain instead of through the Auth0-hosted login page",
			},
			"custom_login_page_on": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates whether or not a custom login page is to be used",
			},
			"custom_login_page": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Content of the custom login page",
			},
			"form_template": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Form template for WS-Federation protocol",
			},
			"addons": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Configuration settings for add-ons for this client",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"aws": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"azure_blob": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"azure_sb": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"rms": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"mscrm": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"slack": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"sentry": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"box": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"cloudbees": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"concur": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"dropbox": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"echosign": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"egnyte": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"firebase": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"newrelic": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"office365": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"salesforce": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"salesforce_api": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"salesforce_sandbox_api": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"samlp": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "Configuration settings for a SAML add-on",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"audience": {
										Type:     schema.TypeString,
										Computed: true,
										Description: "Audience of the SAML Assertion. " +
											"Default will be the Issuer on SAMLRequest",
									},
									"recipient": {
										Type:     schema.TypeString,
										Computed: true,
										Description: "Recipient of the SAML Assertion (SubjectConfirmationData). " +
											"Default is AssertionConsumerUrl on SAMLRequest or Callback URL if no SAMLRequest was sent",
									},
									"mappings": {
										Type:     schema.TypeMap,
										Computed: true,
										Elem:     schema.TypeString,
										Description: "Mappings between the Auth0 user profile property name (" +
											"`name`) and the output attributes on the SAML attribute in the assertion (`value`)",
									},
									"create_upn_claim": {
										Type:        schema.TypeBool,
										Computed:    true,
										Description: "Indicates whether or not a UPN claim should be created",
									},
									"passthrough_claims_with_no_mapping": {
										Type:     schema.TypeBool,
										Computed: true,
										Description: "Indicates whether or not to passthrough claims that are not" +
											" mapped to the common profile in the output assertion",
									},
									"map_unknown_claims_as_is": {
										Type:     schema.TypeBool,
										Computed: true,
										Description: "Indicates whether or not to add a prefix of `http://schema." +
											"auth0.com` to any claims that are not mapped to the common profile when passed through in the output assertion",
									},
									"map_identities": {
										Type:     schema.TypeBool,
										Computed: true,
										Description: "Indicates whether or not to add additional identity information" +
											" in the token, such as the provider used and the `access_token`, if available",
									},
									"signature_algorithm": {
										Type:     schema.TypeString,
										Computed: true,
										Description: "Algorithm used to sign the SAML Assertion or response. " +
											"Options include `rsa-sha1` (default) and `rsa-sha256`",
									},
									"digest_algorithm": {
										Type:     schema.TypeString,
										Computed: true,
										Description: "Algorithm used to calculate the digest of the SAML Assertion or" +
											" response. Options include `sha1` (default) and `sha256`",
									},
									"destination": {
										Type:     schema.TypeString,
										Computed: true,
										Description: "Destination of the SAML Response. If not specified, " +
											"it will be `AssertionConsumerUrl` of SAMLRequest or `CallbackURL` if" +
											" there was no SAMLRequest",
									},
									"lifetime_in_seconds": {
										Type:        schema.TypeInt,
										Computed:    true,
										Description: "Number of seconds during which the token is valid",
									},
									"sign_response": {
										Type:     schema.TypeBool,
										Computed: true,
										Description: "Indicates whether or not the SAML Response should be signed instead" +
											" of the SAML Assertion",
									},
									"name_identifier_format": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Format of the name identifier",
									},
									"name_identifier_probes": {
										Type:     schema.TypeList,
										Elem:     &schema.Schema{Type: schema.TypeString},
										Computed: true,
										Description: "Attributes that can be used for Subject/NameID. " +
											"Auth0 will try each of the attributes of this array in order and use the" +
											" first value it finds",
									},
									"authn_context_class_ref": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Class reference of the authentication context",
									},
									"typed_attributes": {
										Type:     schema.TypeBool,
										Computed: true,
									},
									"include_attribute_name_format": {
										Type:     schema.TypeBool,
										Computed: true,
										Description: "Indicates whether or not we should infer the NameFormat based" +
											" on the attribute name. If set to false, the attribute NameFormat is not set in the assertion",
									},
									"logout": {
										Type:        schema.TypeList,
										Computed:    true,
										Description: "Configuration settings for logout",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"callback": {
													Type:     schema.TypeString,
													Computed: true,
													Description: "Service provider's Single Logout Service URL, " +
														"to which Auth0 will send logout requests and responses",
												},
												"slo_enabled": {
													Type:     schema.TypeBool,
													Computed: true,
													Description: "Indicates whether or not Auth0 should notify" +
														" service providers of session termination",
												},
											},
										},
									},
									"binding": {
										Type:        schema.TypeString,
										Computed:    true,
										Description: "Protocol binding used for SAML logout responses",
									},
									"signing_cert": {
										Type:     schema.TypeString,
										Computed: true,
										Description: "Optionally indicates the public key certificate used to validate " +
											"SAML requests. If set, SAML requests will be required to be signed." +
											" A sample value would be `-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----`",
									},
								},
							},
						},
						"layer": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"sap_api": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"sharepoint": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"springcm": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"wams": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"wsfed": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"zendesk": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"zoom": {
							Type:     schema.TypeMap,
							Computed: true,
						},
					},
				},
			},
			"token_endpoint_auth_method": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "Defines the requested authentication method for the token endpoint. " +
					"Options include `none` (public client without a client secret), " +
					"`client_secret_post` (client uses HTTP POST parameters), `client_secret_basic` (client uses HTTP Basic)",
			},
			"client_metadata": {
				Type:     schema.TypeMap,
				Computed: true,
				Elem:     schema.TypeString,
				Description: "Metadata associated with the client, in the form of an object with string values (" +
					"max 255 chars). Maximum of 10 metadata properties allowed. Field names (" +
					"max 255 chars) are alphanumeric and may only include the following special characters: :," +
					"-+=_*?\"/\\()<>@ [Tab] [Space]",
			},
			"mobile": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Additional configuration for native mobile apps.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"android": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "Android native app configuration",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"app_package_name": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"sha256_cert_fingerprints": {
										Type:     schema.TypeList,
										Computed: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
								},
							},
						},
						"ios": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "iOS native app configuration",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"team_id": {
										Type:     schema.TypeString,
										Computed: true,
									},
									"app_bundle_identifier": {
										Type:     schema.TypeString,
										Computed: true,
									},
								},
							},
						},
					},
				},
			},
			"initiate_login_uri": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Initiate login uri, must be https",
			},
			"refresh_token": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Configuration settings for the refresh tokens issued for this client",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"rotation_type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Refresh token rotation types, one of: `rotating`, `non-rotating`",
						},
						"expiration_type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Refresh token expiration types, one of: `expiring`, `non-expiring`",
						},
						"leeway": {
							Type:     schema.TypeInt,
							Computed: true,
							Description: "Period in seconds where the previous refresh token can be exchanged without" +
								" triggering breach detection",
						},
						"token_lifetime": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "Period (in seconds) for which refresh tokens will remain valid",
						},
						"infinite_token_lifetime": {
							Type:     schema.TypeBool,
							Computed: true,
							Description: "Prevents tokens from having a set lifetime when true (" +
								"takes precedence over token_lifetime values)",
						},
						"infinite_idle_token_lifetime": {
							Type:     schema.TypeBool,
							Computed: true,
							Description: "Prevents tokens from expiring without use when `true` (" +
								"takes precedence over `idle_token_lifetime` values)",
						},
						"idle_token_lifetime": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "Period (in seconds) for which refresh tokens will remain valid without use",
						},
					},
				},
			},
		},
	}
}

func dataSourceClientRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId(d.Get("client_id").(string))
	return readClient(ctx, d, m)
}
