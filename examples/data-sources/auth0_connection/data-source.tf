data "auth0_connection" "google" {
  id = "con_kCHSjpjWJba3YN6E"
}

output "client_id" {
  value = data.auth0_connection.google.options[0].client_id
}

output "client_secret" {
  value     = data.auth0_connection.google.options[0].client_secret
  sensitive = true
}
