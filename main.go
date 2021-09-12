package main

import (
	"context"
	"flag"
	"log"

	"github.com/alekc/terraform-provider-auth0/auth0"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

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
