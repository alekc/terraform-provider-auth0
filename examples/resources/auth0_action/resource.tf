resource "auth0_flow" "myaction" {
  name = "my Action"
  trigger {
    id = "post-login"
  }
  dependency {
    name = "lodash"
    version = "1.0.0"
  }
  dependency {
    name = "glob"
    version = "7.1.7"
  }
  secret {
    name = "foo"
    value = "fooval"
  }
  secret {
    name = "bar"
    value = "barval"
  }

  code = "exports.onExecutePostLogin = async (event, api) => {};"
}