package auth0

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
	v "github.com/alekc/terraform-provider-auth0/auth0/internal/validation"
)

func newClient() *schema.Resource {
	return &schema.Resource{

		CreateContext: createClient,
		ReadContext:   readClient,
		UpdateContext: updateClient,
		DeleteContext: deleteClient,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"description": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringLenBetween(0, 140),
			},
			"client_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"client_secret": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"client_secret_rotation_trigger": {
				Type:     schema.TypeMap,
				Optional: true,
			},
			"app_type": {
				Type:     schema.TypeString,
				Optional: true,
				ValidateFunc: validation.StringInSlice([]string{
					"native", "spa", "regular_web", "non_interactive", "rms",
					"box", "cloudbees", "concur", "dropbox", "mscrm", "echosign",
					"egnyte", "newrelic", "office365", "salesforce", "sentry",
					"sharepoint", "slack", "springcm", "zendesk", "zoom",
				}, false),
			},
			"logo_uri": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"is_first_party": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"is_token_endpoint_ip_header_trusted": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"oidc_conformant": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"callbacks": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
			},
			"allowed_logout_urls": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
			},
			"grant_types": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
				Optional: true,
			},
			"allowed_origins": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
			},
			"web_origins": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
			},
			"jwt_configuration": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				MinItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"lifetime_in_seconds": {
							Type:     schema.TypeInt,
							Optional: true,
							Computed: true,
						},
						"secret_encoded": {
							Type:     schema.TypeBool,
							Optional: true,
							Computed: true,
							ForceNew: true,
						},
						"scopes": {
							Type:     schema.TypeMap,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"alg": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"encryption_key": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"sso": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"sso_disabled": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"cross_origin_auth": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"cross_origin_loc": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"custom_login_page_on": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"custom_login_page": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"form_template": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"addons": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"aws": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"azure_blob": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"azure_sb": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"rms": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"mscrm": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"slack": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"sentry": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"box": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"cloudbees": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"concur": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"dropbox": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"echosign": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"egnyte": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"firebase": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"newrelic": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"office365": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"salesforce": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"salesforce_api": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"salesforce_sandbox_api": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"samlp": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"audience": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"recipient": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"mappings": {
										Type:     schema.TypeMap,
										Optional: true,
										Elem:     schema.TypeString,
									},
									"create_upn_claim": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  true,
									},
									"passthrough_claims_with_no_mapping": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  true,
									},
									"map_unknown_claims_as_is": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  false,
									},
									"map_identities": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  true,
									},
									"signature_algorithm": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "rsa-sha1",
									},
									"digest_algorithm": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "sha1",
									},
									"destination": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"lifetime_in_seconds": {
										Type:     schema.TypeInt,
										Optional: true,
										Default:  3600,
									},
									"sign_response": {
										Type:     schema.TypeBool,
										Optional: true,
									},
									"name_identifier_format": {
										Type:     schema.TypeString,
										Optional: true,
										Default:  "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
									},
									"name_identifier_probes": {
										Type:     schema.TypeList,
										Elem:     &schema.Schema{Type: schema.TypeString},
										Optional: true,
									},
									"authn_context_class_ref": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"typed_attributes": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  true,
									},
									"include_attribute_name_format": {
										Type:     schema.TypeBool,
										Optional: true,
										Default:  true,
									},
									"logout": {
										Type:     schema.TypeList,
										Optional: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"callback": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"slo_enabled": {
													Type:     schema.TypeBool,
													Optional: true,
												},
											},
										},
									},
									"binding": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
						"layer": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"sap_api": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"sharepoint": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"springcm": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"wams": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"wsfed": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"zendesk": {
							Type:     schema.TypeMap,
							Optional: true,
						},
						"zoom": {
							Type:     schema.TypeMap,
							Optional: true,
						},
					},
				},
				Default: nil,
			},
			"token_endpoint_auth_method": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ValidateFunc: validation.StringInSlice([]string{
					"none",
					"client_secret_post",
					"client_secret_basic",
				}, false),
			},
			"client_metadata": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem:     schema.TypeString,
			},
			"mobile": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"android": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"app_package_name": {
										Type:     schema.TypeString,
										Optional: true,
										AtLeastOneOf: []string{
											"mobile.0.android.0.app_package_name",
											"mobile.0.android.0.sha256_cert_fingerprints",
										},
									},
									"sha256_cert_fingerprints": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
										AtLeastOneOf: []string{
											"mobile.0.android.0.app_package_name",
											"mobile.0.android.0.sha256_cert_fingerprints",
										},
									},
								},
							},
						},
						"ios": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"team_id": {
										Type:     schema.TypeString,
										Optional: true,
										AtLeastOneOf: []string{
											"mobile.0.ios.0.team_id",
											"mobile.0.ios.0.app_bundle_identifier",
										},
									},
									"app_bundle_identifier": {
										Type:     schema.TypeString,
										Optional: true,
										AtLeastOneOf: []string{
											"mobile.0.ios.0.team_id",
											"mobile.0.ios.0.app_bundle_identifier",
										},
									},
								},
							},
						},
					},
				},
			},
			"initiate_login_uri": {
				Type:     schema.TypeString,
				Optional: true,
				ValidateFunc: validation.All(
					validation.IsURLWithScheme([]string{"https"}),
					v.IsURLWithNoFragment,
				),
			},
			"refresh_token": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				MinItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"rotation_type": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								"rotating",
								"non-rotating",
							}, false),
						},
						"expiration_type": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								"expiring",
								"non-expiring",
							}, false),
						},
						"leeway": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"token_lifetime": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"infinite_token_lifetime": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"infinite_idle_token_lifetime": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"idle_token_lifetime": {
							Type:     schema.TypeInt,
							Optional: true,
						},
					},
				},
			},
		},
	}
}

func createClient(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := expandClient(d)
	api := m.(*management.Management)
	if err := api.Client.Create(c, management.Context(ctx)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(auth0.StringValue(c.ClientID))
	return readClient(ctx, d, m)
}

func readClient(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	c, err := api.Client.Read(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	_ = d.Set("client_id", c.ClientID)
	_ = d.Set("client_secret", c.ClientSecret)
	_ = d.Set("name", c.Name)
	_ = d.Set("description", c.Description)
	_ = d.Set("app_type", c.AppType)
	_ = d.Set("logo_uri", c.LogoURI)
	_ = d.Set("is_first_party", c.IsFirstParty)
	_ = d.Set("is_token_endpoint_ip_header_trusted", c.IsTokenEndpointIPHeaderTrusted)
	_ = d.Set("oidc_conformant", c.OIDCConformant)
	_ = d.Set("callbacks", c.Callbacks)
	_ = d.Set("allowed_logout_urls", c.AllowedLogoutURLs)
	_ = d.Set("allowed_origins", c.AllowedOrigins)
	_ = d.Set("grant_types", c.GrantTypes)
	_ = d.Set("web_origins", c.WebOrigins)
	_ = d.Set("sso", c.SSO)
	_ = d.Set("sso_disabled", c.SSODisabled)
	_ = d.Set("cross_origin_auth", c.CrossOriginAuth)
	_ = d.Set("cross_origin_loc", c.CrossOriginLocation)
	_ = d.Set("custom_login_page_on", c.CustomLoginPageOn)
	_ = d.Set("custom_login_page", c.CustomLoginPage)
	_ = d.Set("form_template", c.FormTemplate)
	_ = d.Set("token_endpoint_auth_method", c.TokenEndpointAuthMethod)
	_ = d.Set("jwt_configuration", flattenClientJwtConfiguration(c.JWTConfiguration))
	_ = d.Set("refresh_token", flattenClientRefreshTokenConfiguration(c.RefreshToken))
	_ = d.Set("encryption_key", c.EncryptionKey)
	_ = d.Set("addons", flattenMap(c.Addons))
	_ = d.Set("client_metadata", c.ClientMetadata)
	_ = d.Set("mobile", flattenMap(c.Mobile))
	_ = d.Set("initiate_login_uri", c.InitiateLoginURI)

	return nil
}

func updateClient(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := expandClient(d)
	api := m.(*management.Management)
	if clientHasChange(c) {
		err := api.Client.Update(d.Id(), c, management.Context(ctx))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	d.Partial(true)
	err := rotateClientSecret(ctx, d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	d.Partial(false)
	return readClient(ctx, d, m)
}

func deleteClient(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	err := api.Client.Delete(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	return diag.FromErr(err)
}

func expandClient(d *schema.ResourceData) *management.Client {

	c := &management.Client{
		Name:                           String(d, "name"),
		Description:                    String(d, "description"),
		AppType:                        String(d, "app_type"),
		LogoURI:                        String(d, "logo_uri"),
		IsFirstParty:                   Bool(d, "is_first_party"),
		IsTokenEndpointIPHeaderTrusted: Bool(d, "is_token_endpoint_ip_header_trusted"),
		OIDCConformant:                 Bool(d, "oidc_conformant"),
		Callbacks:                      Slice(d, "callbacks"),
		AllowedLogoutURLs:              Slice(d, "allowed_logout_urls"),
		AllowedOrigins:                 Slice(d, "allowed_origins"),
		GrantTypes:                     Slice(d, "grant_types"),
		WebOrigins:                     Slice(d, "web_origins"),
		SSO:                            Bool(d, "sso"),
		SSODisabled:                    Bool(d, "sso_disabled"),
		CrossOriginAuth:                Bool(d, "cross_origin_auth"),
		CrossOriginLocation:            String(d, "cross_origin_loc"),
		CustomLoginPageOn:              Bool(d, "custom_login_page_on"),
		CustomLoginPage:                String(d, "custom_login_page"),
		FormTemplate:                   String(d, "form_template"),
		TokenEndpointAuthMethod:        String(d, "token_endpoint_auth_method"),
		InitiateLoginURI:               String(d, "initiate_login_uri"),
	}

	List(d, "refresh_token", IsNewResource(), HasChange()).Elem(func(d ResourceData) {
		c.RefreshToken = &management.ClientRefreshToken{
			RotationType:              String(d, "rotation_type"),
			ExpirationType:            String(d, "expiration_type"),
			Leeway:                    Int(d, "leeway"),
			TokenLifetime:             Int(d, "token_lifetime"),
			InfiniteTokenLifetime:     Bool(d, "infinite_token_lifetime"),
			InfiniteIdleTokenLifetime: Bool(d, "infinite_idle_token_lifetime"),
			IdleTokenLifetime:         Int(d, "idle_token_lifetime"),
		}
	})

	List(d, "jwt_configuration").Elem(func(d ResourceData) {
		c.JWTConfiguration = &management.ClientJWTConfiguration{
			LifetimeInSeconds: Int(d, "lifetime_in_seconds"),
			SecretEncoded:     Bool(d, "secret_encoded", IsNewResource()),
			Algorithm:         String(d, "alg"),
			Scopes:            Map(d, "scopes"),
		}
	})

	if m := Map(d, "encryption_key"); m != nil {
		c.EncryptionKey = map[string]string{}
		for k, val := range m {
			c.EncryptionKey[k] = val.(string)
		}
	}

	List(d, "addons").Elem(func(d ResourceData) {

		c.Addons = make(map[string]interface{})

		// disabled due to https://community.auth0.com/t/new-customer-trying-to-authenticate-with-firebase-api-using-auth0/7534/18
		// if there will be anyone complaining (from old customers),
		// I will have a look at the underlying data to create proper structure. However, I think such event is unlikely

		// for _, name := range []string{
		// 	"aws", "azure_blob", "azure_sb", "rms", "mscrm", "slack", "sentry",
		// 	"box", "cloudbees", "concur", "dropbox", "echosign", "egnyte",
		// 	"firebase", "newrelic", "office365", "salesforce", "salesforce_api",
		// 	"salesforce_sandbox_api", "layer", "sap_api", "sharepoint",
		// 	"springcm", "wams", "wsfed", "zendesk", "zoom",
		// } {
		// 	_, ok := d.GetOk(name)
		// 	if ok {
		// 		c.Addons[name] = buildClientAddon(Map(d, name))
		// 	}
		// }
		if _, ok := d.GetOk("wsfed"); ok {
			c.Addons["wsfed"] = buildClientAddon(Map(d, "name"))
		}

		List(d, "samlp").Elem(func(d ResourceData) {

			m := make(MapData)

			_ = m.Set("audience", String(d, "audience"))
			_ = m.Set("authnContextClassRef", String(d, "authn_context_class_ref"))
			_ = m.Set("binding", String(d, "binding"))
			_ = m.Set("createUpnClaim", Bool(d, "create_upn_claim"))
			_ = m.Set("destination", String(d, "destination"))
			_ = m.Set("digestAlgorithm", String(d, "digest_algorithm"))
			_ = m.Set("includeAttributeNameFormat", Bool(d, "include_attribute_name_format"))
			_ = m.Set("lifetimeInSeconds", Int(d, "lifetime_in_seconds"))
			_ = m.Set("logout", List(d, "logout").List())
			_ = m.Set("mapIdentities", Bool(d, "map_identities"))
			_ = m.Set("mappings", Map(d, "mappings"))
			_ = m.Set("mapUnknownClaimsAsIs", Bool(d, "map_unknown_claims_as_is"))
			_ = m.Set("nameIdentifierFormat", String(d, "name_identifier_format"))
			_ = m.Set("nameIdentifierProbes", Slice(d, "name_identifier_probes"))
			_ = m.Set("passthroughClaimsWithNoMapping", Bool(d, "passthrough_claims_with_no_mapping"))
			_ = m.Set("recipient", String(d, "recipient"))
			_ = m.Set("signatureAlgorithm", String(d, "signature_algorithm"))
			_ = m.Set("signResponse", Bool(d, "sign_response"))
			_ = m.Set("typedAttributes", Bool(d, "typed_attributes"))

			c.Addons["samlp"] = []interface{}{m}
		})
	})

	if val, ok := d.GetOk("client_metadata"); ok {
		c.ClientMetadata = make(map[string]string)
		for key, value := range val.(map[string]interface{}) {
			c.ClientMetadata[key] = value.(string)
		}
	}

	List(d, "mobile").Elem(func(d ResourceData) {

		c.Mobile = make(map[string]interface{})

		List(d, "android").Elem(func(d ResourceData) {
			m := make(MapData)
			_ = m.Set("app_package_name", String(d, "app_package_name"))
			_ = m.Set("sha256_cert_fingerprints", Slice(d, "sha256_cert_fingerprints"))

			c.Mobile["android"] = m
		})

		List(d, "ios").Elem(func(d ResourceData) {
			m := make(MapData)
			_ = m.Set("team_id", String(d, "team_id"))
			_ = m.Set("app_bundle_identifier", String(d, "app_bundle_identifier"))

			c.Mobile["ios"] = m
		})
	})

	return c
}

func buildClientAddon(d map[string]interface{}) map[string]interface{} {

	addon := make(map[string]interface{})

	for key, value := range d {

		switch v := value.(type) {

		case string:
			if i, err := strconv.ParseInt(v, 10, 64); err == nil {
				addon[key] = i
			} else if f, err := strconv.ParseFloat(v, 64); err == nil {
				addon[key] = f
			} else if b, err := strconv.ParseBool(v); err == nil {
				addon[key] = b
			} else {
				addon[key] = v
			}

		case map[string]interface{}:
			addon[key] = buildClientAddon(v)

		case []interface{}:
			addon[key] = v

		default:
			addon[key] = v
		}
	}
	return addon
}

func rotateClientSecret(ctx context.Context, d *schema.ResourceData, m interface{}) error {
	if d.HasChange("client_secret_rotation_trigger") {
		api := m.(*management.Management)
		c, err := api.Client.RotateSecret(d.Id(), management.Context(ctx))
		if err != nil {
			return err
		}
		_ = d.Set("client_secret", c.ClientSecret)
	}
	// d.SetPartial("client_secret_rotation_trigger")
	return nil
}

func clientHasChange(c *management.Client) bool {
	return c.String() != "{}"
}

func flattenClientJwtConfiguration(jwt *management.ClientJWTConfiguration) []interface{} {
	m := make(map[string]interface{})
	if jwt != nil {
		m["lifetime_in_seconds"] = jwt.LifetimeInSeconds
		m["secret_encoded"] = jwt.SecretEncoded
		m["scopes"] = jwt.Scopes
		m["alg"] = jwt.Algorithm
	}
	return []interface{}{m}
}

func flattenClientRefreshTokenConfiguration(refresh_token *management.ClientRefreshToken) []interface{} {
	m := make(map[string]interface{})
	if refresh_token != nil {
		m["rotation_type"] = refresh_token.RotationType
		m["expiration_type"] = refresh_token.ExpirationType
		m["leeway"] = refresh_token.Leeway
		m["token_lifetime"] = refresh_token.TokenLifetime
		m["infinite_token_lifetime"] = refresh_token.InfiniteTokenLifetime
		m["infinite_idle_token_lifetime"] = refresh_token.InfiniteIdleTokenLifetime
		m["idle_token_lifetime"] = refresh_token.IdleTokenLifetime
	}
	return []interface{}{m}
}
