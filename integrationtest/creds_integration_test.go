package integrationtest

import (
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test token ttl handling and defaults
func TestCreds_ttl(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()

	// create default config
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{})
	require.NoError(t, err)

	_, err = client.Logical().Write(path+"/roles/testrole", map[string]interface{}{
		"allowed_kubernetes_namespaces": []string{"*"},
		"service_account_name":          "sample-app",
		"token_ttl":                     "1h",
		"token_max_ttl":                 "24h",
	})
	assert.NoError(t, err)

	result, err := client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Equal(t, oneDay, result.Data["token_max_ttl"])
	assert.Equal(t, oneHour, result.Data["token_ttl"])

	result1, err := client.Logical().Write(path+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"ttl":                  "2h",
	})
	assert.NoError(t, err)
	assert.Equal(t, 7200, result1.LeaseDuration)

	// Test different TTL settings
	result2, err := client.Logical().Write(path+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
	})
	assert.NoError(t, err)
	assert.Equal(t, 3600, result2.LeaseDuration)

	// default to token_max_ttl
	_, err = client.Logical().Write(path+"/roles/testrole", map[string]interface{}{
		"token_ttl": "0",
	})
	assert.NoError(t, err)

	result3, err := client.Logical().Write(path+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
	})
	assert.NoError(t, err)
	assert.Equal(t, 86400, result3.LeaseDuration)

	// default to mount's ttl
	_, err = client.Logical().Write(path+"/roles/testrole", map[string]interface{}{
		"token_max_ttl": "0",
	})
	assert.NoError(t, err)
	result4, err := client.Logical().Write(path+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
	})
	assert.NoError(t, err)
	assert.Equal(t, 2764800, result4.LeaseDuration)
}

func TestCreds_service_account_name(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()

	// create default config
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{})
	require.NoError(t, err)

	_, err = client.Logical().Write(path+"/roles/testrole", map[string]interface{}{
		"allowed_kubernetes_namespaces": []string{"*"},
		"service_account_name":          "sample-app",
		"token_ttl":                     "1h",
		"token_max_ttl":                 "24h",
	})
	assert.NoError(t, err)

	roleResponse, err := client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"additional_metadata":           map[string]interface{}{},
		"allowed_kubernetes_namespaces": []interface{}{"*"},
		"generated_role_rules":          "",
		"kubernetes_role_name":          "",
		"kubernetes_role_type":          "Role",
		"name":                          "testrole",
		"name_template":                 "",
		"service_account_name":          "sample-app",
		"token_max_ttl":                 oneDay,
		"token_ttl":                     oneHour,
	}, roleResponse.Data)

	result1, err := client.Logical().Write(path+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"ttl":                  "2h",
	})
	assert.NoError(t, err)
	verifyCredsResponse(t, result1, "test", "sample-app", 7200)

	testRoleBindingToken(t, result1)

	// Clean up lease and delete role
	leases, err := client.Logical().List("sys/leases/lookup/" + path + "/creds/testrole/")
	assert.NoError(t, err)
	assert.Len(t, leases.Data["keys"], 1)

	err = client.Sys().RevokePrefix(path + "/creds/testrole")
	assert.NoError(t, err)

	noLeases, err := client.Logical().List("sys/leases/lookup/" + path + "/creds/testrole/")
	assert.NoError(t, err)
	assert.Empty(t, noLeases)

	_, err = client.Logical().Delete(path + "/roles/testrole")
	assert.NoError(t, err)

	result, err := client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCreds_kubernetes_role_name(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()

	// create default config
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{})
	require.NoError(t, err)

	t.Run("Role type", func(t *testing.T) {
		roleConfig := map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"test"},
			"kubernetes_role_name":          "test-role-list-pods",
			"kubernetes_role_type":          "role",
			"token_ttl":                     "1h",
			"token_max_ttl":                 "24h",
		}
		expectedRoleResponse := map[string]interface{}{
			"additional_metadata":           map[string]interface{}{},
			"allowed_kubernetes_namespaces": []interface{}{"test"},
			"generated_role_rules":          "",
			"kubernetes_role_name":          "test-role-list-pods",
			"kubernetes_role_type":          "role",
			"name":                          "testrole",
			"name_template":                 "",
			"service_account_name":          "",
			"token_max_ttl":                 oneDay,
			"token_ttl":                     oneHour,
		}
		testRoleType(t, client, path, roleConfig, expectedRoleResponse)
	})

	t.Run("ClusterRole type", func(t *testing.T) {
		roleConfig := map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"test"},
			"kubernetes_role_name":          "test-cluster-role-list-pods",
			"kubernetes_role_type":          "Clusterrole",
			"token_ttl":                     "1h",
			"token_max_ttl":                 "24h",
		}
		expectedRoleResponse := map[string]interface{}{
			"additional_metadata":           map[string]interface{}{},
			"allowed_kubernetes_namespaces": []interface{}{"test"},
			"generated_role_rules":          "",
			"kubernetes_role_name":          "test-cluster-role-list-pods",
			"kubernetes_role_type":          "Clusterrole",
			"name":                          "testrole",
			"name_template":                 "",
			"service_account_name":          "",
			"token_max_ttl":                 oneDay,
			"token_ttl":                     oneHour,
		}
		testClusterRoleType(t, client, path, roleConfig, expectedRoleResponse)
	})
}

func TestCreds_generated_role_rules(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()

	// create default config
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{})
	require.NoError(t, err)

	roleRulesYAML := `rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list"]`

	roleRulesJSON := `"rules": [
	{
		"apiGroups": [
			""
		],
		"resources": [
			"pods"
		],
		"verbs": [
			"list"
		]
	}
]`

	t.Run("Role type", func(t *testing.T) {
		roleConfig := map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"test"},
			"generated_role_rules":          roleRulesYAML,
			"kubernetes_role_type":          "RolE",
			"token_ttl":                     "1h",
			"token_max_ttl":                 "24h",
		}
		expectedRoleResponse := map[string]interface{}{
			"additional_metadata":           map[string]interface{}{},
			"allowed_kubernetes_namespaces": []interface{}{"test"},
			"generated_role_rules":          roleRulesYAML,
			"kubernetes_role_name":          "",
			"kubernetes_role_type":          "RolE",
			"name":                          "testrole",
			"name_template":                 "",
			"service_account_name":          "",
			"token_max_ttl":                 oneDay,
			"token_ttl":                     oneHour,
		}
		testRoleType(t, client, path, roleConfig, expectedRoleResponse)
	})

	t.Run("ClusterRole type", func(t *testing.T) {
		roleConfig := map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"test"},
			"generated_role_rules":          roleRulesJSON,
			"kubernetes_role_type":          "clusterRole",
			"token_ttl":                     "1h",
			"token_max_ttl":                 "24h",
		}
		expectedRoleResponse := map[string]interface{}{
			"additional_metadata":           map[string]interface{}{},
			"allowed_kubernetes_namespaces": []interface{}{"test"},
			"generated_role_rules":          roleRulesJSON,
			"kubernetes_role_name":          "",
			"kubernetes_role_type":          "clusterRole",
			"name":                          "testrole",
			"name_template":                 "",
			"service_account_name":          "",
			"token_max_ttl":                 oneDay,
			"token_ttl":                     oneHour,
		}
		testClusterRoleType(t, client, path, roleConfig, expectedRoleResponse)
	})
}
