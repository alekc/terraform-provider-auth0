---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "auth0_guardian Resource - terraform-provider-auth0"
subcategory: ""
description: |-
  Multi-factor Authentication works by requiring additional factors during the login process to
  prevent unauthorized access.
  With this resource you can configure some of the options available for MFA.
---

# auth0_guardian (Resource)

Multi-factor Authentication works by requiring additional factors during the login process to
prevent unauthorized access. 

With this resource you can configure some of the options available for MFA.



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **policy** (String)

### Optional

- **id** (String) The ID of this resource.
- **phone** (Block List, Max: 1) (see [below for nested schema](#nestedblock--phone))

<a id="nestedblock--phone"></a>
### Nested Schema for `phone`

Required:

- **message_types** (List of String)
- **provider** (String)

Optional:

- **options** (Block List, Max: 1) (see [below for nested schema](#nestedblock--phone--options))

<a id="nestedblock--phone--options"></a>
### Nested Schema for `phone.options`

Optional:

- **auth_token** (String, Sensitive)
- **enrollment_message** (String)
- **from** (String)
- **messaging_service_sid** (String)
- **sid** (String)
- **verification_message** (String)


