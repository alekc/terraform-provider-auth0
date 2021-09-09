Auth0 Terraform Provider
========================

[![Build](https://github.com/alekc/terraform-provider-auth0/workflows/Build/badge.svg)](https://github.com/alexkappa/terraform-provider-auth0/actions)
[![Maintainability](https://api.codeclimate.com/v1/badges/6a616125cb75e00d913a/maintainability)](https://codeclimate.com/github/alekc/terraform-provider-auth0/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/6a616125cb75e00d913a/test_coverage)](https://codeclimate.com/github/alekc/terraform-provider-auth0/test_coverage)
[![Gitter](https://badges.gitter.im/terraform-provider-auth0/community.svg)](https://gitter.im/terraform-provider-auth0/community)

History
-----
This project was forked from `github/alexkappa/terraform-provider-auth0` due to apparent abandonment / slow release cycle. 
The split happened on version `0.21.0`


Usage
-----

**Terraform 0.13+**

Terraform 0.13 and higher uses the [Terraform Registry](https://registry.terraform.io/) to download and install providers. To install this provider, copy and paste this code into your Terraform configuration. Then, run `terraform init`.

```tf
terraform {
  required_providers {
    auth0 = {
      source  = "alekc/auth0"
      version = "0.21.1"
    }
  }
}

provider "auth0" {}
```

```sh
$ terraform init
```

**Terraform 0.12.x**

For older versions of Terraform, binaries are available at the [releases](https://github.com/alekc/terraform-provider-auth0/releases) page. Download one that corresponds to your operating system / architecture, and move to the `~/.terraform.d/plugins/` directory. Finally, run terraform init.

```
provider "auth0" {}
```


```sh
$ terraform init
```

See the [Auth0 Provider documentation](https://registry.terraform.io/providers/alekc/auth0/latest/docs) for all the available resources.

Contributing
------------

See [CONTRIBUTING.md](CONTRIBUTING.md).
