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