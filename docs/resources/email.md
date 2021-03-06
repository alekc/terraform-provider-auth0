---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "auth0_email Resource - terraform-provider-auth0"
subcategory: ""
description: |-
  With Auth0, you can have standard welcome, password reset,
  and account verification email-based workflows built right into Auth0.
  This resource allows you to configure email providers so you can route all emails that are part of Auth0's
  authentication workflows through the supported high-volume email service of your choice.
---

# auth0_email (Resource)

With Auth0, you can have standard welcome, password reset, 
and account verification email-based workflows built right into Auth0. 
This resource allows you to configure email providers so you can route all emails that are part of Auth0's
authentication workflows through the supported high-volume email service of your choice.

## Example Usage

```terraform
provider "auth0" {}

resource "auth0_email" "my_email_provider" {
  name                 = "ses"
  enabled              = true
  default_from_address = "accounts@example.com"
  credentials {
    access_key_id     = "AKIAXXXXXXXXXXXXXXXX"
    secret_access_key = "7e8c2148xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    region            = "us-east-1"
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **default_from_address** (String) Email address to use as `from` when no other address specified

### Optional

- **enabled** (Boolean) Whether the provider is enabled (`true`) or disabled (`false`)
- **id** (String) The ID of this resource.
- **mailgun** (Block List, Max: 1) Configuration for the mailgun email integration (see [below for nested schema](#nestedblock--mailgun))
- **mandrill** (Block List, Max: 1) Configuration for the mandrill email integration (see [below for nested schema](#nestedblock--mandrill))
- **sendgrid** (Block List, Max: 1) Configuration for the sendgrid email integration (see [below for nested schema](#nestedblock--sendgrid))
- **ses** (Block List, Max: 1) Configuration for the Aws ses email integration (see [below for nested schema](#nestedblock--ses))
- **smtp** (Block List, Max: 1) Configuration for the generic SMTP email integration (see [below for nested schema](#nestedblock--smtp))
- **sparkpost** (Block List, Max: 1) Configuration for the sparkpost email integration (see [below for nested schema](#nestedblock--sparkpost))

<a id="nestedblock--mailgun"></a>
### Nested Schema for `mailgun`

Required:

- **api_key** (String, Sensitive) API Key
- **domain** (String) Your Domain registered with Mailgun

Optional:

- **region** (String) Mailgun region. If set must be `eu`


<a id="nestedblock--mandrill"></a>
### Nested Schema for `mandrill`

Required:

- **api_key** (String, Sensitive) API Key


<a id="nestedblock--sendgrid"></a>
### Nested Schema for `sendgrid`

Required:

- **api_key** (String, Sensitive) API Key


<a id="nestedblock--ses"></a>
### Nested Schema for `ses`

Required:

- **access_key_id** (String, Sensitive) Access key ID
- **region** (String) Ses region
- **secret_access_key** (String, Sensitive) Secret Access key. It's not advisable to store it in clear


<a id="nestedblock--smtp"></a>
### Nested Schema for `smtp`

Required:

- **host** (String) SMTP Host
- **pass** (String, Sensitive)
- **port** (Number)
- **user** (String)


<a id="nestedblock--sparkpost"></a>
### Nested Schema for `sparkpost`

Required:

- **api_key** (String, Sensitive) API Key

Optional:

- **region** (String) Sparkpost region. If set must be `eu`


