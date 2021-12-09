data "auth0_custom_domain" "my_custom_domain" {
  custom_domain_id = "cd_r8AfFcMRdwjtHwFM"
}

output "custom_domain" {
  value = data.auth0_custom_domain.my_custom_domain.domain
}
