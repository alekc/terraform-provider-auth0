package auth0

import (
	"context"

	"github.com/alekc/terraform-provider-auth0/auth0/internal/flow"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

func newRole() *schema.Resource {
	return &schema.Resource{

		CreateContext: createRole,
		UpdateContext: updateRole,
		ReadContext:   readRole,
		DeleteContext: deleteRole,
		Description: "With this resource, " +
			"you can created and manage collections of permissions that can be assigned to users, " +
			"which are otherwise known as roles. Permissions (scopes) are created on auth0_resource_server, " +
			"then associated with roles and optionally, users using this resource",
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name for this role",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Role's description",
			},
			"permissions": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Configuration settings for permissions (scopes) attached to the role",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Name of the permission (scope)",
						},
						"resource_server_identifier": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Unique identifier for the resource server",
						},
					},
				},
			},
		},
	}
}

func createRole(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	c := expandRole(d)
	api := m.(*management.Management)
	if err := api.Role.Create(c, management.Context(ctx)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(auth0.StringValue(c.ID))

	// Enable partial state mode. Sub-resources can potentially cause partial
	// state. Therefore we must explicitly tell Terraform what is safe to
	// persist and what is not.
	//
	// See: https://www.terraform.io/docs/extend/writing-custom-providers.html
	d.Partial(true)
	if err := assignRolePermissions(ctx, d, m); err != nil {
		return diag.FromErr(err)
	}
	// We succeeded, disable partial mode. This causes Terraform to save
	// all fields again.
	d.Partial(false)

	return readRole(ctx, d, m)
}

func readRole(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	c, err := api.Role.Read(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}

	d.SetId(c.GetID())
	_ = d.Set("name", c.Name)
	_ = d.Set("description", c.Description)

	var permissions []*management.Permission

	var page int
	for {
		l, err := api.Role.Permissions(d.Id(), management.Page(page), management.Context(ctx))
		if err != nil {
			return diag.FromErr(err)
		}
		for _, permission := range l.Permissions {
			permissions = append(permissions, permission)
		}
		if !l.HasNext() {
			break
		}
		page++
	}

	_ = d.Set("permissions", flattenRolePermissions(permissions))

	return nil
}

func updateRole(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	c := expandRole(d)
	api := m.(*management.Management)
	err := api.Role.Update(d.Id(), c, management.Context(ctx))
	if err != nil {
		return diag.FromErr(err)
	}
	d.Partial(true)
	if err := assignRolePermissions(ctx, d, m); err != nil {
		return diag.FromErr(err)
	}
	d.Partial(false)
	return readRole(ctx, d, m)
}

func deleteRole(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	api := m.(*management.Management)
	err := api.Role.Delete(d.Id(), management.Context(ctx))
	if err != nil {
		return flow.DefaultManagementError(err, d)
	}
	return diag.FromErr(err)
}

func expandRole(d *schema.ResourceData) *management.Role {
	return &management.Role{
		Name:        String(d, "name"),
		Description: String(d, "description"),
	}
}

func assignRolePermissions(ctx context.Context, d *schema.ResourceData, m interface{}) error {

	add, rm := Diff(d, "permissions")

	var addPermissions []*management.Permission
	for _, addPermission := range add {
		permission := addPermission.(map[string]interface{})
		addPermissions = append(addPermissions, &management.Permission{
			Name:                     auth0.String(permission["name"].(string)),
			ResourceServerIdentifier: auth0.String(permission["resource_server_identifier"].(string)),
		})
	}

	var rmPermissions []*management.Permission
	for _, rmPermission := range rm {
		permission := rmPermission.(map[string]interface{})
		rmPermissions = append(rmPermissions, &management.Permission{
			Name:                     auth0.String(permission["name"].(string)),
			ResourceServerIdentifier: auth0.String(permission["resource_server_identifier"].(string)),
		})
	}

	api := m.(*management.Management)

	if len(rmPermissions) > 0 {
		err := api.Role.RemovePermissions(d.Id(), rmPermissions, management.Context(ctx))
		if err != nil {
			return err
		}
	}

	if len(addPermissions) > 0 {
		err := api.Role.AssociatePermissions(d.Id(), addPermissions, management.Context(ctx))
		if err != nil {
			return err
		}
	}

	return nil
}

func flattenRolePermissions(permissions []*management.Permission) []interface{} {
	var v []interface{}
	for _, permission := range permissions {
		v = append(v, map[string]interface{}{
			"name":                       permission.Name,
			"resource_server_identifier": permission.ResourceServerIdentifier,
		})
	}
	return v
}
