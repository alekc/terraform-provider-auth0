package auth0

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"gopkg.in/auth0.v5/management"
)

func find(s []string, searchterm string) int {
	sort.Strings(s)
	i := sort.SearchStrings(s, searchterm)
	if s[i] == searchterm {
		return i
	} else {
		return -1
	}
}

func contains(s []string, searchterm string) bool {
	i := find(s, searchterm)
	return i < len(s)
}

func newClientConnection() *schema.Resource {
	return &schema.Resource{
		CreateContext: CreateClientConnection,
		ReadContext:   ReadClientConnection,
		DeleteContext: DeleteClientConnection,
		Importer: &schema.ResourceImporter{
			State: ImportClientConnection,
		},

		Schema: map[string]*schema.Schema{
			"client_id": {
				Description: "Id of the client to add to the connection",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
			},
			"connection_id": {
				Description: "Id of the connection",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
			},
		},
	}
}

func CreateClientConnection(
	ctx context.Context,
	d *schema.ResourceData,
	m interface{},
) diag.Diagnostics {
	api := m.(*management.Management)
	connectionID := d.Get("connection_id").(string)

	c, err := api.Connection.Read(connectionID, management.Context(ctx))
	c.EnabledClients = append(c.EnabledClients, d.Get("client_id"))

	err = api.Connection.Update(connectionID, getPatchObject(c), management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(resource.PrefixedUniqueId(fmt.Sprintf("%s-", connectionID)))

	return ReadClientConnection(ctx, d, m)
}

func ReadClientConnection(
	ctx context.Context,
	d *schema.ResourceData,
	m interface{},
) diag.Diagnostics {
	api := m.(*management.Management)
	connId := d.Get("connection_id").(string)

	c, err := api.Connection.Read(connId, management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	expectedClientID := d.Get("client_id").(string)
	enabled := false
	for _, v := range c.EnabledClients {
		if v.(string) == expectedClientID {
			enabled = true
			break
		}
	}

	if enabled {
		_ = d.Set("client_id", expectedClientID)
	} else {
		_ = d.Set("client_id", nil)
		d.SetId("")
	}

	return nil
}

func DeleteClientConnection(
	ctx context.Context,
	d *schema.ResourceData,
	m interface{},
) diag.Diagnostics {
	api := m.(*management.Management)
	connId := d.Get("connection_id").(string)
	expectedClientID := d.Get("client_id").(string)

	c, err := api.Connection.Read(connId, management.Context(ctx))
	enabledClients := make([]interface{}, len(c.EnabledClients)-1)
	offset := 0
	for i, v := range c.EnabledClients {
		if v.(string) == expectedClientID {
			offset = -1
			continue
		}
		enabledClients[i+offset] = v
	}

	if len(enabledClients) == 0 {
		// Currently we can't set enabled_clients to an empty list as it will be ignored.
		return diag.FromErr(errors.New("Can not disable client connection as it's the only one. See: https://github.com/go-auth0/auth0/issues/241."))
	}

	c.EnabledClients = enabledClients

	err = api.Connection.Update(connId, getPatchObject(c), management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	return ReadClientConnection(ctx, d, m)
}

func ImportClientConnection(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	idParts := strings.SplitN(d.Id(), ":", 2)
	if len(idParts) != 2 || idParts[0] == "" || idParts[1] == "" {
		return nil, fmt.Errorf("unexpected format of ID (%q), expected <connection_id>:<client_id>", d.Id())
	}

	connectionID := idParts[0]
	clientID := idParts[1]

	d.Set("connection_id", connectionID)
	d.Set("client_id", clientID)
	d.SetId(fmt.Sprintf("%s-%s", connectionID, clientID))

	return []*schema.ResourceData{d}, nil
}

func getPatchObject(c *management.Connection) *management.Connection {
	patchC := &management.Connection{
		EnabledClients: c.EnabledClients,
	}

	return patchC
}
