package auth0

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"gopkg.in/auth0.v5/management"
)

func newGuardian() *schema.Resource {
	return &schema.Resource{
		CreateContext: createGuardian,
		ReadContext:   readGuardian,
		UpdateContext: updateGuardian,
		DeleteContext: deleteGuardian,
		Description: `Multi-factor Authentication works by requiring additional factors during the login process to
prevent unauthorized access. 

With this resource you can configure some of the options available for MFA.`,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"policy": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.StringInSlice([]string{
					"all-applications",
					"confidence-score",
					"never",
				}, false),
			},
			"phone": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				MinItems: 0,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"provider": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice([]string{
								"auth0",
								"twilio",
								"phone-message-hook",
							}, false),
						},
						"message_types": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"options": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							MinItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enrollment_message": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"verification_message": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"from": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"messaging_service_sid": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"auth_token": {
										Type:      schema.TypeString,
										Sensitive: true,
										Optional:  true,
									},
									"sid": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
func createGuardian(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId(resource.UniqueId())
	return updateGuardian(ctx, d, m)
}

func deleteGuardian(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	err := api.Guardian.MultiFactor.Phone.Enable(false, management.Context(ctx))
	if err != nil {
		return nil
	}
	d.SetId("")
	return nil
}
func updateGuardian(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)

	var err error
	if d.HasChange("policy") {
		p := d.Get("policy").(string)
		if p == "never" {
			// Passing empty array to set it to the "never" policy.
			err = api.Guardian.MultiFactor.UpdatePolicy(&management.MultiFactorPolicies{}, management.Context(ctx))
		} else {
			err = api.Guardian.MultiFactor.UpdatePolicy(&management.MultiFactorPolicies{p}, management.Context(ctx))
		}
		if err != nil {
			return diag.FromErr(err)
		}
	}
	// TODO: Extend for other MFA types
	if ok := factorShouldBeUpdated(d, "phone"); ok {
		if err = api.Guardian.MultiFactor.Phone.Enable(true, management.Context(ctx)); err != nil {
			return diag.FromErr(err)
		}
		err = configurePhone(d, api)
	} else {
		err = api.Guardian.MultiFactor.Phone.Enable(false, management.Context(ctx))
	}
	if err != nil {
		return diag.FromErr(err)
	}

	return readGuardian(ctx, d, m)
}

func configurePhone(d *schema.ResourceData, api *management.Management) (err error) {

	md := make(MapData)
	List(d, "phone").Elem(func(d ResourceData) {
		md.Set("provider", String(d, "provider", HasChange()))
		md.Set("message_types", Slice(d, "message_types", HasChange()))
		md.Set("options", List(d, "options"))
		switch *String(d, "provider") {
		case "twilio":
			err = updateTwilioOptions(md["options"].(Iterator), api)
		case "auth0":
			err = updateAuth0Options(md["options"].(Iterator), api)
		}
	})

	if s, ok := md.GetOk("provider"); ok {
		if err := api.Guardian.MultiFactor.Phone.UpdateProvider(&management.MultiFactorProvider{Provider: s.(*string)}); err != nil {
			return err
		}
	}

	mtypes := typeAssertToStringArray(Slice(md, "message_types"))
	if mtypes != nil {
		if err := api.Guardian.MultiFactor.Phone.UpdateMessageTypes(&management.PhoneMessageTypes{MessageTypes: mtypes}); err != nil {
			return err
		}
	}

	return err
}

func updateAuth0Options(opts Iterator, api *management.Management) (err error) {
	opts.Elem(func(d ResourceData) {
		err = api.Guardian.MultiFactor.SMS.UpdateTemplate(&management.MultiFactorSMSTemplate{
			EnrollmentMessage:   String(d, "enrollment_message"),
			VerificationMessage: String(d, "verification_message"),
		})
	})
	if err != nil {
		return err
	}
	return nil
}

func updateTwilioOptions(opts Iterator, api *management.Management) error {
	md := make(map[string]*string)
	opts.Elem(func(d ResourceData) {
		md["sid"] = String(d, "sid")
		md["auth_token"] = String(d, "auth_token")
		md["from"] = String(d, "from")
		md["messaging_service_sid"] = String(d, "messaging_service_sid")
		md["enrollment_message"] = String(d, "enrollment_message")
		md["verification_message"] = String(d, "verification_message")
	})

	err := api.Guardian.MultiFactor.SMS.UpdateTwilio(&management.MultiFactorProviderTwilio{
		From:                md["from"],
		MessagingServiceSid: md["messaging_service_sid"],
		AuthToken:           md["auth_token"],
		SID:                 md["sid"],
	})
	if err != nil {
		return err
	}
	err = api.Guardian.MultiFactor.SMS.UpdateTemplate(&management.MultiFactorSMSTemplate{
		EnrollmentMessage:   md["enrollment_message"],
		VerificationMessage: md["verification_message"],
	})
	if err != nil {
		return err
	}
	return nil
}

func readGuardian(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	mt, err := api.Guardian.MultiFactor.Phone.MessageTypes(management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	phoneData := make(map[string]interface{})
	phoneData["message_types"] = mt.MessageTypes
	prv, err := api.Guardian.MultiFactor.Phone.Provider(management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	phoneData["provider"] = prv.Provider

	p, err := api.Guardian.MultiFactor.Policy(management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}

	if len(*p) == 0 {
		_ = d.Set("policy", "never")
	} else {
		_ = d.Set("policy", (*p)[0])
	}

	var md map[string]interface{}
	switch *prv.Provider {
	case "twilio":
		md, err = flattenTwilioOptions(ctx, api)
	case "auth0":
		md, err = flattenAuth0Options(ctx, api)
	}
	if err != nil {
		return diag.FromErr(err)
	}

	if factorShouldBeUpdated(d, "phone") {
		phoneData["options"] = []interface{}{md}
		_ = d.Set("phone", []interface{}{phoneData})
	} else {
		_ = d.Set("phone", nil)
	}
	return nil
}

func hasBlockPresentInNewState(d *schema.ResourceData, factor string) bool {
	if ok := d.HasChange(factor); ok {
		_, n := d.GetChange(factor)
		newState := n.([]interface{})
		return len(newState) > 0
	}
	return false
}

func flattenAuth0Options(ctx context.Context, api *management.Management) (map[string]interface{}, error) {
	md := make(map[string]interface{})
	t, err := api.Guardian.MultiFactor.SMS.Template(management.Context(ctx))
	if err != nil {
		return nil, err
	}
	md["enrollment_message"] = t.EnrollmentMessage
	md["verification_message"] = t.VerificationMessage
	return md, nil
}

func flattenTwilioOptions(ctx context.Context, api *management.Management) (map[string]interface{}, error) {
	md := make(map[string]interface{})
	t, err := api.Guardian.MultiFactor.SMS.Template(management.Context(ctx))
	if err != nil {
		return nil, err
	}

	md["enrollment_message"] = t.EnrollmentMessage
	md["verification_message"] = t.VerificationMessage
	tw, err := api.Guardian.MultiFactor.SMS.Twilio(management.Context(ctx))
	if err != nil {
		return nil, err
	}

	md["auth_token"] = tw.AuthToken
	md["from"] = tw.From
	md["messaging_service_sid"] = tw.MessagingServiceSid
	md["sid"] = tw.SID
	return md, nil
}

func typeAssertToStringArray(from []interface{}) *[]string {
	length := len(from)
	if length < 1 {
		return nil
	}
	stringArray := make([]string, length)
	for i, v := range from {
		stringArray[i] = v.(string)
	}
	return &stringArray
}

// func isFactorEnabled(factor string, api *management.Management) (*bool, error) {
// 	mfs, err := api.Guardian.MultiFactor.List()
// 	if err != nil {
// 		return nil, err
// 	}
// 	for _, mf := range mfs {
// 		if *mf.Name == factor {
// 			return mf.Enabled, nil
// 		}
// 	}
// 	return nil, fmt.Errorf("factor %s is not among the possible factors", factor)
// }

// Determines if the factor should be updated. This depends on if it is in the state, if it is about to be added to the state.
func factorShouldBeUpdated(d *schema.ResourceData, factor string) bool {
	_, ok := d.GetOk(factor)
	return ok || hasBlockPresentInNewState(d, factor)
}
