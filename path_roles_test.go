package kubesecrets

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoles(t *testing.T) {
	b, s := getTestBackend(t)

	t.Run("create role - fail", func(t *testing.T) {
		resp, err := testRoleCreate(t, b, s, "badrole", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"*"},
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "one (and only one) of service_account_name, kubernetes_role_name or generated_role_rules must be set")

		resp, err = testRoleCreate(t, b, s, "badrole", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"*"},
			"service_account_name":          "test_svc_account",
			"kubernetes_role_name":          "existing_role",
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "one (and only one) of service_account_name, kubernetes_role_name or generated_role_rules must be set")

		resp, err = testRoleCreate(t, b, s, "badrole", map[string]interface{}{
			"service_account_name": "test_svc_account",
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "allowed_kubernetes_namespaces must be set")

		resp, err = testRoleCreate(t, b, s, "badrole", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"generated_role_rules":          badYAMLRules,
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "failed to parse 'generated_role_rules' as k8s.io/api/rbac/v1/Policy object")

		resp, err = testRoleCreate(t, b, s, "badrole", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"generated_role_rules":          badJSONRules,
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "failed to parse 'generated_role_rules' as k8s.io/api/rbac/v1/Policy object")

		resp, err = testRoleCreate(t, b, s, "badmeta", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"*"},
			"service_account_name":          "test_svc_account",
			"additional_metadata": map[string]interface{}{
				"labels": []string{"one", "two"},
			},
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "additional_metadata should be a nested map, with only 'labels' and 'annotations' as the top level keys")

		resp, err = testRoleCreate(t, b, s, "badrole", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"service_account_name":          "test_svc_account",
			"kubernetes_role_type":          "notARole",
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "kubernetes_role_type must be either 'Role' or 'ClusterRole'")

		resp, err = testRoleCreate(t, b, s, "badttl_tokenmax", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"service_account_name":          "test_svc_account",
			"token_default_ttl":             "11h",
			"token_max_ttl":                 "5h",
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "token_default_ttl 11h0m0s cannot be greater than token_max_ttl 5h0m0s")
	})

	t.Run("delete role - non-existant and blank", func(t *testing.T) {
		resp, err := testRolesDelete(t, b, s, "nope")
		assert.NoError(t, err)
		assert.Nil(t, resp)

		resp, err = testRolesDelete(t, b, s, "")
		assert.EqualError(t, err, "unsupported operation")
		assert.Nil(t, resp)
	})

	t.Run("full role crud", func(t *testing.T) {
		// No roles yet, list is empty
		resp, err := testRolesList(t, b, s)
		require.NoError(t, err)
		assert.Empty(t, resp.Data)

		// Create one with json role rules
		resp, err = testRoleCreate(t, b, s, "jsonrules", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"generated_role_rules":          goodJSONRules,
			"token_default_ttl":             "5h",
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = testRoleRead(t, b, s, "jsonrules")
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"additional_metadata":           map[string]interface{}{},
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"generated_role_rules":          goodJSONRules,
			"kubernetes_role_name":          "",
			"kubernetes_role_type":          "Role",
			"name":                          "jsonrules",
			"name_template":                 "",
			"service_account_name":          "",
			"token_max_ttl":                 time.Duration(0).Seconds(),
			"token_default_ttl":             time.Duration(time.Hour * 5).Seconds(),
		}, resp.Data)

		// Create one with yaml role rules and metadata
		resp, err = testRoleCreate(t, b, s, "yamlrules", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"generated_role_rules":          goodYAMLRules,
			"additional_metadata":           testMetadata,
			"kubernetes_role_type":          "role",
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = testRoleRead(t, b, s, "yamlrules")
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"additional_metadata":           testMetadata,
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"generated_role_rules":          goodYAMLRules,
			"kubernetes_role_name":          "",
			"kubernetes_role_type":          "Role",
			"name":                          "yamlrules",
			"name_template":                 "",
			"service_account_name":          "",
			"token_max_ttl":                 time.Duration(0).Seconds(),
			"token_default_ttl":             time.Duration(0).Seconds(),
		}, resp.Data)

		// update yamlrules (with a duplicate namespace)
		resp, err = testRoleCreate(t, b, s, "yamlrules", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app3", "app4", "App4"},
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())
		resp, err = testRoleRead(t, b, s, "yamlrules")
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"additional_metadata":           testMetadata,
			"allowed_kubernetes_namespaces": []string{"app3", "app4"},
			"generated_role_rules":          goodYAMLRules,
			"kubernetes_role_name":          "",
			"kubernetes_role_type":          "Role",
			"name":                          "yamlrules",
			"name_template":                 "",
			"service_account_name":          "",
			"token_max_ttl":                 time.Duration(0).Seconds(),
			"token_default_ttl":             time.Duration(0).Seconds(),
		}, resp.Data)

		// Now there should be two roles returned from list
		resp, err = testRolesList(t, b, s)
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"jsonrules", "yamlrules"},
		}, resp.Data)

		// Delete one
		resp, err = testRolesDelete(t, b, s, "jsonrules")
		require.NoError(t, err)
		// Now there should be one
		resp, err = testRolesList(t, b, s)
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"yamlrules"},
		}, resp.Data)
		// Delete the last one
		resp, err = testRolesDelete(t, b, s, "yamlrules")
		require.NoError(t, err)
		// Now there should be none
		resp, err = testRolesList(t, b, s)
		require.NoError(t, err)
		assert.Empty(t, resp.Data)
	})
}

func testRoleCreate(t *testing.T, b *backend, s logical.Storage, name string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      rolesPath + name,
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func testRoleRead(t *testing.T, b *backend, s logical.Storage, name string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      rolesPath + name,
		Storage:   s,
	})
}

func testRolesList(t *testing.T, b *backend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      rolesPath,
		Storage:   s,
	})
}

func testRolesDelete(t *testing.T, b *backend, s logical.Storage, name string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      rolesPath + name,
		Storage:   s,
	})
}

var testMetadata = map[string]interface{}{
	"labels": map[string]string{
		"one": "two",
	},
	"annotations": map[string]string{
		"test": "annotation",
	},
}

const (
	goodJSONRules = `"rules": [
	{
		"apiGroups": [
			"admissionregistration.k8s.io"
		],
		"resources": [
			"mutatingwebhookconfigurations"
		],
		"verbs": [
			"get",
			"list",
			"watch",
			"patch"
		]
	}
]`
	badJSONRules = `"rules": [
	{
		apiGroups:
			"admissionregistration.k8s.io"
		"resources": [
			"mutatingwebhookconfigurations"
		],
		"verbs": [
			"get",
			"list",
			"watch",
			"patch"
		],
	}
]`

	goodYAMLRules = `rules:
- apiGroups:
  - admissionregistration.k8s.io
  resources:
  - mutatingwebhookconfigurations
  verbs:
  - get
  - list
  - watch
  - patch
`
	badYAMLRules = `rules:
= apiGroups:
	- admissionregistration.k8s.io
	resources:
	? mutatingwebhookconfigurations
	verbs:
	- get
	- list
	- watch
	- patch
`
)
