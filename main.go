package main

import (
	"context"
	"flag"
	"log"

	"github.com/alekc/terraform-provider-auth0/auth0"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

// If you do not have terraform installed, you can remove the formatting command, but its suggested to
// ensure the documentation is formatted properly.
//go:generate terraform fmt -recursive ./example/

// Run the docs generation tool, check its repository for more information on how it works and how docs
// can be customized.
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs

func main() {
	var debugMode bool

	flag.BoolVar(&debugMode, "debuggable", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	if debugMode {
		err := plugin.Debug(context.Background(), "registry.terraform.io/alekc/auth0",
			&plugin.ServeOpts{
				ProviderFunc: auth0.Provider,
			})
		if err != nil {
			log.Println(err.Error())
		}
		return
	}

	plugin.Serve(&plugin.ServeOpts{ProviderFunc: auth0.Provider})
}
