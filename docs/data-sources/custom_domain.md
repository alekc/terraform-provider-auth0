---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "auth0_custom_domain Data Source - terraform-provider-auth0"
subcategory: ""
description: |-
  A custom domain configured for this tenant
---

# auth0_custom_domain (Data Source)

A custom domain configured for this tenant

## Example Usage

```terraform
data "auth0_custom_domain" "my_custom_domain" {
  custom_domain_id = "cd_r8AfFcMRdwjtHwFM"
}

output "custom_domain" {
  value = data.auth0_custom_domain.my_custom_domain.domain
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **custom_domain_id** (String) ID of the custom domain

### Read-Only

- **domain** (String) Name of the custom domain
- **id** (String) ID of the custom domain
- **primary** (Boolean) Indicates whether or not this is a primary domain
- **status** (String) Configuration status for the custom domain. Options include `disabled`, `pending`, `pending_verification`, and `ready`
- **type** (String) Provisioning type for the custom domain. Valid options are: auth0_managed_certs, self_managed_certs
- **verification** (List of Object) Configuration settings for verification (see [below for nested schema](#nestedatt--verification))
- **verification_method** (String) Domain verification method. Options include `txt`

<a id="nestedatt--verification"></a>
### Nested Schema for `verification`

Read-Only:

- **methods** (List of Map of String)

