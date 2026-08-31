// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

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
		assert.EqualError(t, resp.Error(), "one (at least) of allowed_kubernetes_namespaces or allowed_kubernetes_namespace_selector must be set")

		resp, err = testRoleCreate(t, b, s, "badrole", map[string]interface{}{
			"allowed_kubernetes_namespace_selector": badYAMLSelector,
			"kubernetes_role_name":                  "existing_role",
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "failed to parse 'allowed_kubernetes_namespace_selector' as k8s.io/api/meta/v1/LabelSelector object")

		resp, err = testRoleCreate(t, b, s, "badrole", map[string]interface{}{
			"allowed_kubernetes_namespace_selector": badJSONSelector,
			"kubernetes_role_name":                  "existing_role",
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "failed to parse 'allowed_kubernetes_namespace_selector' as k8s.io/api/meta/v1/LabelSelector object")

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

		badmeta := map[string]interface{}{
			"foo": []string{"one", "two"},
		}
		resp, err = testRoleCreate(t, b, s, "badmeta", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"*"},
			"service_account_name":          "test_svc_account",
			"extra_labels":                  badmeta,
			"extra_annotations":             badmeta,
		})
		assert.NoError(t, err)
		assert.Contains(t, resp.Error().Error(), "Field validation failed")

		resp, err = testRoleCreate(t, b, s, "badrole", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"service_account_name":          "test_svc_account",
			"kubernetes_role_type":          "notARole",
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "kubernetes_role_type must be either 'Role' or 'ClusterRole'")

		// invalid value — tested without service_account_name so the value check is reached
		resp, err = testRoleCreate(t, b, s, "badrole", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"kubernetes_role_name":          "existing_role",
			"kubernetes_role_ref_type":      "notARoleRefType",
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "kubernetes_role_ref_type must be either 'Role' or 'ClusterRole'")

		// service_account_name + any kubernetes_role_ref_type is always rejected regardless of the value
		resp, err = testRoleCreate(t, b, s, "badrole", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"service_account_name":          "test_svc_account",
			"kubernetes_role_ref_type":      "notARoleRefType",
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "kubernetes_role_ref_type has no effect when service_account_name is set")

		resp, err = testRoleCreate(t, b, s, "badrole", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"service_account_name":          "test_svc_account",
			"kubernetes_role_ref_type":      "Role",
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "kubernetes_role_ref_type has no effect when service_account_name is set")

		resp, err = testRoleCreate(t, b, s, "badrole", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"generated_role_rules":          goodJSONRules,
			"kubernetes_role_type":          "Role",
			"kubernetes_role_ref_type":      "ClusterRole",
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "kubernetes_role_ref_type must match kubernetes_role_type when generated_role_rules is set")

		resp, err = testRoleCreate(t, b, s, "badttl_tokenmax", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"service_account_name":          "test_svc_account",
			"token_default_ttl":             "11h",
			"token_max_ttl":                 "5h",
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "token_default_ttl 11h0m0s cannot be greater than token_max_ttl 5h0m0s")

		resp, err = testRoleCreate(t, b, s, "badtemplate", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"service_account_name":          "test_svc_account",
			"name_template":                 "{{.String",
		})
		assert.NoError(t, err)
		assert.EqualError(t, resp.Error(), "unable to initialize name template: unable to parse template: template: template:1: unclosed action")
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

		// Create one with json namespace label selector
		resp, err = testRoleCreate(t, b, s, "jsonselector", map[string]interface{}{
			"allowed_kubernetes_namespaces":         []string{"test"},
			"allowed_kubernetes_namespace_selector": goodJSONSelector,
			"kubernetes_role_name":                  "existing_role",
			"token_default_ttl":                     "5h",
			"token_default_audiences":               []string{"foobar"},
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = testRoleRead(t, b, s, "jsonselector")
		require.NoError(t, err)
		var nilMeta map[string]string
		assert.Equal(t, map[string]interface{}{
			"allowed_kubernetes_namespaces":         []string{"test"},
			"allowed_kubernetes_namespace_selector": goodJSONSelector,
			"extra_labels":                          nilMeta,
			"extra_annotations":                     nilMeta,
			"generated_role_rules":                  "",
			"kubernetes_role_name":                  "existing_role",
			"kubernetes_role_type":                  "Role",
			"kubernetes_role_ref_type":              "Role",
			"name":                                  "jsonselector",
			"name_template":                         "",
			"service_account_name":                  "",
			"token_max_ttl":                         time.Duration(0).Seconds(),
			"token_default_ttl":                     time.Duration(time.Hour * 5).Seconds(),
			"token_default_audiences":               []string{"foobar"},
		}, resp.Data)

		// Create one with yaml namespace selector and metadata
		resp, err = testRoleCreate(t, b, s, "yamlselector", map[string]interface{}{
			"allowed_kubernetes_namespace_selector": goodYAMLSelector,
			"extra_annotations":                     testExtraAnnotations,
			"extra_labels":                          testExtraLabels,
			"kubernetes_role_name":                  "existing_role",
			"kubernetes_role_type":                  "role",
			"token_default_audiences":               []string{"foobar"},
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = testRoleRead(t, b, s, "yamlselector")
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"allowed_kubernetes_namespaces":         []string(nil),
			"allowed_kubernetes_namespace_selector": goodYAMLSelector,
			"extra_annotations":                     testExtraAnnotations,
			"extra_labels":                          testExtraLabels,
			"generated_role_rules":                  "",
			"kubernetes_role_name":                  "existing_role",
			"kubernetes_role_type":                  "Role",
			"kubernetes_role_ref_type":              "Role",
			"name":                                  "yamlselector",
			"name_template":                         "",
			"service_account_name":                  "",
			"token_max_ttl":                         time.Duration(0).Seconds(),
			"token_default_ttl":                     time.Duration(0).Seconds(),
			"token_default_audiences":               []string{"foobar"},
		}, resp.Data)

		// Create one with json role rules
		resp, err = testRoleCreate(t, b, s, "jsonrules", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"generated_role_rules":          goodJSONRules,
			"token_default_ttl":             "5h",
			"token_default_audiences":       []string{"foobar"},
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = testRoleRead(t, b, s, "jsonrules")
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"allowed_kubernetes_namespaces":         []string{"app1", "app2"},
			"allowed_kubernetes_namespace_selector": "",
			"extra_labels":                          nilMeta,
			"extra_annotations":                     nilMeta,
			"generated_role_rules":                  goodJSONRules,
			"kubernetes_role_name":                  "",
			"kubernetes_role_type":                  "Role",
			"kubernetes_role_ref_type":              "Role",
			"name":                                  "jsonrules",
			"name_template":                         "",
			"service_account_name":                  "",
			"token_max_ttl":                         time.Duration(0).Seconds(),
			"token_default_ttl":                     time.Duration(time.Hour * 5).Seconds(),
			"token_default_audiences":               []string{"foobar"},
		}, resp.Data)

		// Create one with yaml role rules and metadata
		resp, err = testRoleCreate(t, b, s, "yamlrules", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1", "app2"},
			"extra_annotations":             testExtraAnnotations,
			"extra_labels":                  testExtraLabels,
			"generated_role_rules":          goodYAMLRules,
			"kubernetes_role_type":          "role",
			"token_default_audiences":       []string{"foobar"},
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = testRoleRead(t, b, s, "yamlrules")
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"allowed_kubernetes_namespaces":         []string{"app1", "app2"},
			"allowed_kubernetes_namespace_selector": "",
			"extra_annotations":                     testExtraAnnotations,
			"extra_labels":                          testExtraLabels,
			"generated_role_rules":                  goodYAMLRules,
			"kubernetes_role_name":                  "",
			"kubernetes_role_type":                  "Role",
			"kubernetes_role_ref_type":              "Role",
			"name":                                  "yamlrules",
			"name_template":                         "",
			"service_account_name":                  "",
			"token_max_ttl":                         time.Duration(0).Seconds(),
			"token_default_ttl":                     time.Duration(0).Seconds(),
			"token_default_audiences":               []string{"foobar"},
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
			"allowed_kubernetes_namespaces":         []string{"app3", "app4"},
			"allowed_kubernetes_namespace_selector": "",
			"extra_annotations":                     testExtraAnnotations,
			"extra_labels":                          testExtraLabels,
			"generated_role_rules":                  goodYAMLRules,
			"kubernetes_role_name":                  "",
			"kubernetes_role_type":                  "Role",
			"kubernetes_role_ref_type":              "Role",
			"name":                                  "yamlrules",
			"name_template":                         "",
			"service_account_name":                  "",
			"token_max_ttl":                         time.Duration(0).Seconds(),
			"token_default_ttl":                     time.Duration(0).Seconds(),
			"token_default_audiences":               []string{"foobar"},
		}, resp.Data)

		// Create one where kubernetes_role_ref_type differs from kubernetes_role_type:
		// a namespaced RoleBinding that references a ClusterRole.
		resp, err = testRoleCreate(t, b, s, "roleref-clusterrole", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1"},
			"kubernetes_role_name":          "my-cluster-role",
			"kubernetes_role_type":          "Role",
			"kubernetes_role_ref_type":      "ClusterRole",
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = testRoleRead(t, b, s, "roleref-clusterrole")
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"allowed_kubernetes_namespaces":         []string{"app1"},
			"allowed_kubernetes_namespace_selector": "",
			"extra_labels":                          nilMeta,
			"extra_annotations":                     nilMeta,
			"generated_role_rules":                  "",
			"kubernetes_role_name":                  "my-cluster-role",
			"kubernetes_role_type":                  "Role",
			"kubernetes_role_ref_type":              "ClusterRole",
			"name":                                  "roleref-clusterrole",
			"name_template":                         "",
			"service_account_name":                  "",
			"token_max_ttl":                         time.Duration(0).Seconds(),
			"token_default_ttl":                     time.Duration(0).Seconds(),
			"token_default_audiences":               []string(nil),
		}, resp.Data)

		// Partial update: update the role without sending kubernetes_role_ref_type and
		// verify the stored ClusterRole value is preserved (not reset to kubernetes_role_type).
		resp, err = testRoleUpdate(t, b, s, "roleref-clusterrole", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1"},
			"kubernetes_role_name":          "my-cluster-role",
			"kubernetes_role_type":          "Role",
			// kubernetes_role_ref_type intentionally omitted
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = testRoleRead(t, b, s, "roleref-clusterrole")
		require.NoError(t, err)
		assert.Equal(t, "ClusterRole", resp.Data["kubernetes_role_ref_type"],
			"partial update must not reset kubernetes_role_ref_type to kubernetes_role_type")

		// Verify case-insensitive input is normalised correctly
		resp, err = testRoleCreate(t, b, s, "roleref-caseinsensitive", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1"},
			"kubernetes_role_name":          "my-role",
			"kubernetes_role_ref_type":      "clusterrole",
		})
		assert.NoError(t, err)
		assert.NoError(t, resp.Error())

		resp, err = testRoleRead(t, b, s, "roleref-caseinsensitive")
		require.NoError(t, err)
		assert.Equal(t, "ClusterRole", resp.Data["kubernetes_role_ref_type"])

		// Now there should be six roles returned from list
		resp, err = testRolesList(t, b, s)
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"jsonrules", "jsonselector", "roleref-caseinsensitive", "roleref-clusterrole", "yamlrules", "yamlselector"},
		}, resp.Data)

		// Delete one
		resp, err = testRolesDelete(t, b, s, "jsonrules")
		require.NoError(t, err)
		// Now there should be five
		resp, err = testRolesList(t, b, s)
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"keys": []string{"jsonselector", "roleref-caseinsensitive", "roleref-clusterrole", "yamlrules", "yamlselector"},
		}, resp.Data)
		// Delete the remaining roles
		resp, err = testRolesDelete(t, b, s, "yamlrules")
		require.NoError(t, err)
		resp, err = testRolesDelete(t, b, s, "jsonselector")
		require.NoError(t, err)
		resp, err = testRolesDelete(t, b, s, "yamlselector")
		require.NoError(t, err)
		resp, err = testRolesDelete(t, b, s, "roleref-clusterrole")
		require.NoError(t, err)
		resp, err = testRolesDelete(t, b, s, "roleref-caseinsensitive")
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

func testRoleUpdate(t *testing.T, b *backend, s logical.Storage, name string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
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

var (
	testExtraLabels = map[string]string{
		"one": "two",
	}
	testExtraAnnotations = map[string]string{
		"test": "annotation",
	}
)

const (
	goodJSONSelector = `{
	"matchLabels": {
	  "stage": "prod",
		"app": "vault"
	}
}`

	badJSONSelector = `{
	"matchLabels":
	  "stage": "prod",
		"app": "vault"
}`

	goodYAMLSelector = `matchLabels:
  stage: prod
  app: vault
`
	badYAMLSelector = `matchLabels:
- stage: prod
- app: vault
`

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

// TestEffectiveRoleRefKind covers the backwards-compatibility fallback in
// roleEntry.EffectiveRoleRefKind: when K8sRoleRefType is empty (a role stored
// before this field was introduced) the method must fall back to K8sRoleType.
func TestEffectiveRoleRefKind(t *testing.T) {
	t.Run("falls back to K8sRoleType when K8sRoleRefType is empty", func(t *testing.T) {
		r := &roleEntry{K8sRoleType: "ClusterRole", K8sRoleRefType: ""}
		assert.Equal(t, "ClusterRole", r.EffectiveRoleRefKind())

		r2 := &roleEntry{K8sRoleType: "Role", K8sRoleRefType: ""}
		assert.Equal(t, "Role", r2.EffectiveRoleRefKind())
	})

	t.Run("returns K8sRoleRefType when explicitly set, ignoring K8sRoleType", func(t *testing.T) {
		r := &roleEntry{K8sRoleType: "Role", K8sRoleRefType: "ClusterRole"}
		assert.Equal(t, "ClusterRole", r.EffectiveRoleRefKind())

		r2 := &roleEntry{K8sRoleType: "ClusterRole", K8sRoleRefType: "Role"}
		assert.Equal(t, "Role", r2.EffectiveRoleRefKind())
	})
}
