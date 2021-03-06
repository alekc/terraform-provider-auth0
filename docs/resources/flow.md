---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "auth0_flow Resource - terraform-provider-auth0"
subcategory: ""
description: |-
  Update the actions that are bound (i.e. attached) to a trigger. Once an action is created and deployed, it must be
  attached (i.e. bound) to a trigger so that it will be executed as part of a flow.
  The order in which the actions are provided will determine the order in which they are executed.
---

# auth0_flow (Resource)

Update the actions that are bound (i.e. attached) to a trigger. Once an action is created and deployed, it must be
attached (i.e. bound) to a trigger so that it will be executed as part of a flow.

The order in which the actions are provided will determine the order in which they are executed.

## Example Usage

```terraform
resource "auth0_action" "myaction" {
  name = "First action"
  trigger {
    id = "post-login"
  }
  code   = "exports.onExecutePostLogin = async (event, api) => {};"
  deploy = true
}
resource "auth0_action" "myaction2" {
  name = "Second Action"
  trigger {
    id = "post-login"
  }
  code   = "exports.onExecutePostLogin = async (event, api) => {};"
  deploy = true
}
resource "auth0_flow" "bind" {
  trigger_id = "post-login"
  action {
    display_name = "action1"
    id           = auth0_action.myaction.id # you can link the action either by id
  }
  action {
    display_name = "action2"
    name         = auth0_action.myaction2.name # or by the name
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **trigger_id** (String) Execution stage of this rule. Can be post-login, credentials-exchange, pre-user-registration, post-user-registration, post-change-password, or send-phone-message

### Optional

- **action** (Block List) The list of triggers that this action supports. At this time, an action can only target a single trigger at a time (see [below for nested schema](#nestedblock--action))
- **id** (String) The ID of this resource.

<a id="nestedblock--action"></a>
### Nested Schema for `action`

Optional:

- **display_name** (String) How will the action be displayed on dashboard ui
- **id** (String) Action ID. Either id or name must be specified (if both, id has priority)
- **name** (String) Action name. Either id or name must be specified (if both, id has priority)


