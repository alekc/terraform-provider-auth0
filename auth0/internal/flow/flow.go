package flow

import (
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"gopkg.in/auth0.v5/management"
)

func DefaultManagementError(err error, d *schema.ResourceData) diag.Diagnostics {
	if mErr, ok := err.(management.Error); ok {
		if mErr.Status() == http.StatusNotFound {
			d.SetId("")
			return nil
		}
	}
	return diag.FromErr(err)
}
