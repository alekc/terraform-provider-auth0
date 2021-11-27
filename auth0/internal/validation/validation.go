package validation

import (
	"fmt"
	"net/url"

	tfv "github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// IsURLWithNoFragment is a SchemaValidateFunc which tests if the provided value
// is of type string and a valid URL with no fragment.
func IsURLWithNoFragment(i interface{}, k string) (warnings []string, errors []error) {

	v, ok := i.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected type of %q to be string", k))
		return
	}

	if v == "" {
		errors = append(errors, fmt.Errorf("expected %q url to not be empty, got %v", k, i))
		return
	}

	u, err := url.Parse(v)
	if err != nil {
		errors = append(errors, fmt.Errorf("expected %q to be a valid url, got %v: %+v", k, v, err))
		return
	}

	if u.Host == "" {
		errors = append(errors, fmt.Errorf("expected %q to have a host, got %v", k, v))
		return
	}

	if u.Fragment != "" {
		errors = append(errors, fmt.Errorf("expected %q to have a url with an empty fragment. %s", k, v))
	}

	return
}

func IsAuth0Strategy(i interface{}, k string) (warnings []string, errors []error) {
	return tfv.StringInSlice([]string{
		"ad", "adfs", "amazon", "apple", "dropbox", "bitbucket", "aol",
		"auth0-adldap", "auth0-oidc", "auth0", "baidu", "bitly",
		"box", "custom", "daccount", "dwolla", "email",
		"evernote-sandbox", "evernote", "exact", "facebook",
		"fitbit", "flickr", "github", "google-apps",
		"google-oauth2", "guardian", "instagram", "ip", "linkedin",
		"miicard", "oauth1", "oauth2", "office365", "oidc", "paypal",
		"paypal-sandbox", "pingfederate", "planningcenter",
		"renren", "salesforce-community", "salesforce-sandbox",
		"salesforce", "samlp", "sharepoint", "shopify", "sms",
		"soundcloud", "thecity-sandbox", "thecity",
		"thirtysevensignals", "twitter", "untappd", "vkontakte",
		"waad", "weibo", "windowslive", "wordpress", "yahoo",
		"yammer", "yandex", "line",
	}, true)(i, k)
}
