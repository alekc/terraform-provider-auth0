provider "auth0" {
  version = "> 1.1.0"
}

resource "auth0_client_connection" "my_client_connection" {
  client_id = "obvious_fake"
  connection_id = "con_fake"
}