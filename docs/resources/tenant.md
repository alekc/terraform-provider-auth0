---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "auth0_tenant Resource - terraform-provider-auth0"
subcategory: ""
description: |-
  With this resource, you can manage Auth0 tenants, including setting logos and support contact information, setting error pages, and configuring default tenant behaviors.
  ~> Auth0 does not currently support creating tenants through the Management API. Therefore this resource can only manage an existing tenant created through the Auth0 dashboard.
  Auth0 does not currently support adding/removing extensions on tenants through their API. The Auth0 dashboard must be used to add/remove extensions.
---

# auth0_tenant (Resource)

With this resource, you can manage Auth0 tenants, including setting logos and support contact information, setting error pages, and configuring default tenant behaviors.

~> Auth0 does not currently support creating tenants through the Management API. Therefore this resource can only manage an existing tenant created through the Auth0 dashboard.

Auth0 does not currently support adding/removing extensions on tenants through their API. The Auth0 dashboard must be used to add/remove extensions.



<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- **allowed_logout_urls** (List of String) URLs that Auth0 may redirect to after logout
- **change_password** (Block List, Max: 1) Configuration settings for change password page (see [below for nested schema](#nestedblock--change_password))
- **default_audience** (String)
- **default_directory** (String) Name of the connection to be used for Password Grant exchanges. Options include `auth0-adldap`, `ad`, `auth0`, `email`, `sms`, `waad`, and `adfs`
- **default_redirection_uri** (String)
- **enabled_locales** (List of String) Supported locales for the user interface. The first locale in the list will be used to set the default locale
- **error_page** (Block List, Max: 1) Configuration settings for error pages (see [below for nested schema](#nestedblock--error_page))
- **flags** (Block List, Max: 1) Configuration settings for tenant flags (see [below for nested schema](#nestedblock--flags))
- **friendly_name** (String) Friendly name for the tenant
- **guardian_mfa_page** (Block List, Max: 1) Configuration settings for the Guardian MFA page (see [below for nested schema](#nestedblock--guardian_mfa_page))
- **id** (String) The ID of this resource.
- **idle_session_lifetime** (Number) Number of hours during which a session can be inactive before the user must log in again
- **picture_url** (String) String URL of logo to be shown for the tenant. Recommended size is 150px x 150px. If no URL is provided, the Auth0 logo will be used
- **sandbox_version** (String) Selected sandbox version for the extensibility environment, which allows you to use custom scripts to extend parts of Auth0's functionality
- **session_lifetime** (Number) Number of hours during which a session will stay valid
- **support_email** (String) Support email address for authenticating users
- **support_url** (String) Support URL for authenticating users
- **universal_login** (Block List, Max: 1) (see [below for nested schema](#nestedblock--universal_login))

<a id="nestedblock--change_password"></a>
### Nested Schema for `change_password`

Required:

- **enabled** (Boolean) Indicates whether or not to use the custom change password page
- **html** (String) HTML format with supported Liquid syntax. Customized content of the change password page


<a id="nestedblock--error_page"></a>
### Nested Schema for `error_page`

Required:

- **html** (String) HTML format with supported Liquid syntax. Customized content of the error page
- **show_log_link** (Boolean) Indicates whether or not to show the link to logs as part of the default error page
- **url** (String) URL to redirect to when an error occurs rather than showing the default error page


<a id="nestedblock--flags"></a>
### Nested Schema for `flags`

Optional:

- **change_pwd_flow_v1** (Boolean) Indicates whether or not to use the older v1 change password flow. Not recommended except for backward compatibility
- **disable_clickjack_protection_headers** (Boolean) Indicated whether or not classic Universal Login prompts include additional security headers to prevent clickjacking
- **enable_apis_section** (Boolean) Indicates whether or not the APIs section is enabled for the tenant
- **enable_client_connections** (Boolean) Indicates whether or not all current connections should be enabled when a new client is created
- **enable_custom_domain_in_emails** (Boolean) Indicates whether or not the tenant allows custom domains in emails
- **enable_dynamic_client_registration** (Boolean) Indicates whether or not the tenant allows dynamic client registration
- **enable_legacy_logs_search_v2** (Boolean) Indicates whether or not to use the older v2 legacy logs search
- **enable_pipeline2** (Boolean) Indicates whether or not advanced API Authorization scenarios are enabled
- **enable_public_signup_user_exists_error** (Boolean) Indicates whether or not the public sign up process shows a user_exists error if the user already exists
- **universal_login** (Boolean) Indicates whether or not the tenant uses universal login
- **use_scope_descriptions_for_consent** (Boolean)


<a id="nestedblock--guardian_mfa_page"></a>
### Nested Schema for `guardian_mfa_page`

Required:

- **enabled** (Boolean) Indicates whether or not to use the custom change password page
- **html** (String) HTML format with supported Liquid syntax. Customized content of the change password page


<a id="nestedblock--universal_login"></a>
### Nested Schema for `universal_login`

Optional:

- **colors** (Block List, Max: 1) (see [below for nested schema](#nestedblock--universal_login--colors))

<a id="nestedblock--universal_login--colors"></a>
### Nested Schema for `universal_login.colors`

Optional:

- **page_background** (String)
- **primary** (String)


