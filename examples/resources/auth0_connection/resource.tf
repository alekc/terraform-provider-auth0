resource "auth0_connection" "my_connection" {
  name                 = "auth0-connection"
  display_name         = "Custom name"
  is_domain_connection = false
  realms               = ["foo", "bar"]
  auth0 {
    validation {
      username {
        min = 1
        max = 10
      }
    }
    password_policy      = "excellent"
    non_persistent_attrs = ["foo", "bar"]
    password_history {
      enable = true
      size   = 3
    }
    password_no_personal_info {
      enable = true
    }
    password_dictionary {
      enable     = true
      dictionary = ["password"]
    }
    password_complexity_options {
      min_length = 5
    }
    mfa_active                     = false
    mfa_return_enroll_settings     = false
    enabled_database_customization = true
    brute_force_protection         = false
    import_mode                    = true
    disable_signup                 = true
    requires_username              = true
    custom_scripts = {
      get_user = "myFunction"
    }
    configuration = {
      "foo" = "secretbar"
    }
  }
}
