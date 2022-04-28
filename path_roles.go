package kubesecrets

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v2"
	rbacv1 "k8s.io/api/rbac/v1"
)

const (
	defaultRoleType = "Role"
	rolesPath       = "roles/"
)

type roleEntry struct {
	Name               string        `json:"name" mapstructure:"name"`
	K8sNamespace       []string      `json:"allowed_kubernetes_namespaces" mapstructure:"allowed_kubernetes_namespaces"`
	TokenMaxTTL        time.Duration `json:"token_max_ttl" mapstructure:"token_max_ttl"`
	TokenTTL           time.Duration `json:"token_ttl" mapstructure:"token_ttl"`
	ServiceAccountName string        `json:"service_account_name" mapstructure:"service_account_name"`
	K8sRoleName        string        `json:"kubernetes_role_name" mapstructure:"kubernetes_role_name"`
	K8sRoleType        string        `json:"kubernetes_role_type" mapstructure:"kubernetes_role_type"`
	RoleRules          string        `json:"generated_role_rules" mapstructure:"generated_role_rules"`
	NameTemplate       string        `json:"name_template" mapstructure:"name_template"`
	Metadata           metadata      `json:"additional_metadata" mapstructure:"additional_metadata"`
}

type metadata struct {
	Labels      map[string]string `json:"labels,omitempty" mapstructure:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" mapstructure:"annotations,omitempty"`
}

func (r *roleEntry) toResponseData() (map[string]interface{}, error) {
	respData := map[string]interface{}{}
	if err := mapstructure.Decode(r, &respData); err != nil {
		return nil, err
	}
	// Format the TTLs as seconds
	respData["token_ttl"] = r.TokenTTL.Seconds()
	respData["token_max_ttl"] = r.TokenMaxTTL.Seconds()

	return respData, nil
}

func (b *backend) pathRoles() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: rolesPath + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"allowed_kubernetes_namespaces": {
					Type:        framework.TypeCommaStringSlice,
					Description: `A list of the valid Kubernetes namespaces in which this role can be used for creating service accounts. If set to "*" all namespaces are allowed.`,
					Required:    true,
				},
				"token_max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The maximum valid ttl for generated Kubernetes tokens. If not set or set to 0, will use system default.",
					Required:    false,
				},
				"token_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The default ttl for generated Kubernetes service accounts. If not set or set to 0, will use system default.",
					Required:    false,
				},
				"service_account_name": {
					Type:        framework.TypeString,
					Description: "The pre-existing service account to generate tokens for. Mutually exclusive with all role parameters. If set, only a Kubernetes token will be created.",
					Required:    false,
				},
				"kubernetes_role_name": {
					Type:        framework.TypeString,
					Description: "The pre-existing Role or ClusterRole to bind a generated service account to. If set, Kubernetes token, service account, and role binding objects will be created.",
					Required:    false,
				},
				"kubernetes_role_type": {
					Type:        framework.TypeString,
					Description: "Specifies whether the Kubernetes role is a Role or ClusterRole.",
					Required:    false,
					Default:     defaultRoleType,
				},
				"generated_role_rules": {
					Type:        framework.TypeString,
					Description: "The Role or ClusterRole rules to use when generating a role. Accepts either a JSON or YAML object. If set, the entire chain of Kubernetes objects will be generated.",
					Required:    false,
				},
				"name_template": {
					Type:        framework.TypeString,
					Description: "The name template to use when generating service accounts, roles and role bindings. If unset, a default template is used.",
					Required:    false,
				},
				"additional_metadata": {
					Type:        framework.TypeMap,
					Description: "Additional labels and annotations to apply to all generated object in Kubernetes.",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathRoleExistenceCheck("name"),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			HelpSynopsis:    rolesHelpSynopsis,
			HelpDescription: rolesHelpDescription,
		},
		{
			Pattern: rolesPath + "?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRolesListHelpSynopsis,
			HelpDescription: pathRolesListHelpDescription,
		},
	}
}

func (b *backend) pathRoleExistenceCheck(roleFieldName string) framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
		rName := d.Get(roleFieldName).(string)
		r, err := getRole(ctx, req.Storage, rName)
		if err != nil {
			return false, err
		}
		return r != nil, nil
	}
}

func (b *backend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	respData, err := entry.toResponseData()
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("role name must be specified"), nil
	}

	entry, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		entry = &roleEntry{
			Name: name,
		}
	}

	if k8sNamespaces, ok := d.GetOk("allowed_kubernetes_namespaces"); ok {
		entry.K8sNamespace = k8sNamespaces.([]string)
	}
	if tokenMaxTTLRaw, ok := d.GetOk("token_max_ttl"); ok {
		entry.TokenMaxTTL = time.Duration(tokenMaxTTLRaw.(int)) * time.Second
	}
	if tokenTTLRaw, ok := d.GetOk("token_ttl"); ok {
		entry.TokenTTL = time.Duration(tokenTTLRaw.(int)) * time.Second
	}
	if svcAccount, ok := d.GetOk("service_account_name"); ok {
		entry.ServiceAccountName = svcAccount.(string)
	}
	if k8sRoleName, ok := d.GetOk("kubernetes_role_name"); ok {
		entry.K8sRoleName = k8sRoleName.(string)
	}

	if k8sRoleType, ok := d.GetOk("kubernetes_role_type"); ok {
		entry.K8sRoleType = k8sRoleType.(string)
	}
	if entry.K8sRoleType == "" {
		entry.K8sRoleType = defaultRoleType
	}

	if roleRules, ok := d.GetOk("generated_role_rules"); ok {
		entry.RoleRules = roleRules.(string)
	}
	if nameTemplate, ok := d.GetOk("name_template"); ok {
		entry.NameTemplate = nameTemplate.(string)
	}
	if metadata, ok := d.GetOk("additional_metadata"); ok {
		if err := mapstructure.Decode(metadata, &entry.Metadata); err != nil {
			return logical.ErrorResponse("additional_metadata should be a nested map, with only 'labels' and 'annotations' as the top level keys"), nil
		}
	}

	// Sanity checks
	if len(entry.K8sNamespace) == 0 {
		return logical.ErrorResponse("allowed_kubernetes_namespaces must be set"), nil
	}
	if !onlyOneSet(entry.ServiceAccountName, entry.K8sRoleName, entry.RoleRules) {
		return logical.ErrorResponse("one (and only one) of service_account_name, kubernetes_role_name or generated_role_rules must be set"), nil
	}
	if strings.ToLower(entry.K8sRoleType) != "role" && strings.ToLower(entry.K8sRoleType) != "clusterrole" {
		return logical.ErrorResponse("kubernetes_role_type must be either 'Role' or 'ClusterRole'"), nil
	}
	// Try parsing the role rules as json or yaml
	if entry.RoleRules != "" {
		testPolicyRules := struct {
			Rules []rbacv1.PolicyRule `json:"rules"`
		}{}
		err := json.Unmarshal([]byte(entry.RoleRules), &testPolicyRules)
		if err != nil {
			// Try yaml
			if err := yaml.Unmarshal([]byte(entry.RoleRules), &testPolicyRules); err != nil {
				return logical.ErrorResponse("failed to parse 'generated_role_rules' as k8s.io/api/rbac/v1/Policy object"), nil
			}
		}
	}

	if err := setRole(ctx, req.Storage, name, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (resp *logical.Response, err error) {
	rName := d.Get("name").(string)
	if err := req.Storage.Delete(ctx, "roles/"+rName); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (resp *logical.Response, err error) {
	roles, err := req.Storage.List(ctx, rolesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	return logical.ListResponse(roles), nil
}

func onlyOneSet(vars ...string) bool {
	count := 0
	for _, v := range vars {
		if v != "" {
			count++
		}
	}
	return count == 1
}

func getRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, rolesPath+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role roleEntry

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

func setRole(ctx context.Context, s logical.Storage, name string, entry *roleEntry) error {
	jsonEntry, err := logical.StorageEntryJSON(rolesPath+name, entry)
	if err != nil {
		return err
	}

	if jsonEntry == nil {
		return fmt.Errorf("failed to create storage entry for role %q", name)
	}

	if err := s.Put(ctx, jsonEntry); err != nil {
		return err
	}

	return nil
}

const (
	rolesHelpSynopsis            = `Manage the roles that can be created with this backend.`
	rolesHelpDescription         = `This path lets you manage the roles that can be created with this backend.`
	pathRolesListHelpSynopsis    = `List the existing roles in this backend.`
	pathRolesListHelpDescription = `A list of existing role names will be returned.`
)
