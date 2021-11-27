data "auth0_connections" "connections" {
  name = "Test-DB-1"
  strategy = ["sms", "email"]
}

output "connection_ids" {
  value = data.auth0_connections.connections.connections[*].id
}