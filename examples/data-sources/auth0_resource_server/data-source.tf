data "auth0_resource_server" "my_resource_server" {
  id = "619fd5eec6e6fd003ef57fde"
}

output "api_audience" {
  value = data.auth0_resource_server.my_resource_server.identifier
}
