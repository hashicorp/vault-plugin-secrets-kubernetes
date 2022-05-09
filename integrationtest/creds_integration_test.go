package integrationtest

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	result, err := client.Logical().Read(path + "/roles/testrole")
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
	}, result.Data)

	result1, err := client.Logical().Write(path+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"ttl":                  "2h",
	})
	assert.NoError(t, err)
	assert.Equal(t, 7200, result1.LeaseDuration)
	assert.Equal(t, false, result1.Renewable)
	assert.Equal(t, "sample-app", result1.Data["service_account_name"])
	assert.Equal(t, "test", result1.Data["service_account_namespace"])

	// Try using one of the generated tokens. Listing pods should be allowed in
	// the 'test' namespace, but nowhere else.
	k8sClient := newK8sClient(t, result1.Data["service_account_token"].(string))
	podsList, err := k8sClient.CoreV1().
		Pods(result1.Data["service_account_namespace"].(string)).
		List(context.Background(), metav1.ListOptions{})
	assert.NoError(t, err)
	assert.Len(t, podsList.Items, 1)

	deniedListPods, err := k8sClient.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	assert.EqualError(t, err, `pods is forbidden: User "system:serviceaccount:test:sample-app" cannot list resource "pods" in API group "" in the namespace "default"`)
	assert.Empty(t, deniedListPods)

	// Clean up leases and delete roles
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

	result, err = client.Logical().Read(path + "/roles/testrole")
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

	_, err = client.Logical().Write(path+"/roles/testrole", map[string]interface{}{
		"allowed_kubernetes_namespaces": []string{"test"},
		"kubernetes_role_name":          "test-role-list-pods",
		"token_ttl":                     "1h",
		"token_max_ttl":                 "24h",
	})
	assert.NoError(t, err)

	result, err := client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"additional_metadata":           map[string]interface{}{},
		"allowed_kubernetes_namespaces": []interface{}{"test"},
		"generated_role_rules":          "",
		"kubernetes_role_name":          "test-role-list-pods",
		"kubernetes_role_type":          "Role",
		"name":                          "testrole",
		"name_template":                 "",
		"service_account_name":          "",
		"token_max_ttl":                 oneDay,
		"token_ttl":                     oneHour,
	}, result.Data)

	result1, err := client.Logical().Write(path+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"ttl":                  "2h",
	})
	assert.NoError(t, err)
	assert.Equal(t, 7200, result1.LeaseDuration)
	assert.Equal(t, false, result1.Renewable)
	assert.Contains(t, result1.Data["service_account_name"], "v-token-testrole")
	assert.Equal(t, "test", result1.Data["service_account_namespace"])

	// Try using one of the generated tokens. Listing pods should be allowed in
	// the 'test' namespace, but nowhere else.
	k8sClient := newK8sClient(t, result1.Data["service_account_token"].(string))
	podsList, err := k8sClient.CoreV1().
		Pods(result1.Data["service_account_namespace"].(string)).
		List(context.Background(), metav1.ListOptions{})
	assert.NoError(t, err)
	assert.Len(t, podsList.Items, 1)

	deniedListPods, err := k8sClient.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	assert.Errorf(t, err, `pods is forbidden: User "system:serviceaccount:test:%s" cannot list resource "pods" in API group "" in the namespace "default"`, result1.Data["service_account_name"])
	assert.Empty(t, deniedListPods)

	// Clean up lease and delete roles
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

	result, err = client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Nil(t, result)
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

	roleRules := `rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list"]`

	_, err = client.Logical().Write(path+"/roles/testrole", map[string]interface{}{
		"allowed_kubernetes_namespaces": []string{"test"},
		"generated_role_rules":          roleRules,
		"token_ttl":                     "1h",
		"token_max_ttl":                 "24h",
	})
	assert.NoError(t, err)

	result, err := client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"additional_metadata":           map[string]interface{}{},
		"allowed_kubernetes_namespaces": []interface{}{"test"},
		"generated_role_rules":          roleRules,
		"kubernetes_role_name":          "",
		"kubernetes_role_type":          "Role",
		"name":                          "testrole",
		"name_template":                 "",
		"service_account_name":          "",
		"token_max_ttl":                 oneDay,
		"token_ttl":                     oneHour,
	}, result.Data)

	result1, err := client.Logical().Write(path+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"ttl":                  "2h",
	})
	assert.NoError(t, err)
	assert.Equal(t, 7200, result1.LeaseDuration)
	assert.Equal(t, false, result1.Renewable)
	assert.Contains(t, result1.Data["service_account_name"], "v-token-testrole")
	assert.Equal(t, "test", result1.Data["service_account_namespace"])

	// Try using one of the generated tokens. Listing pods should be allowed in
	// the 'test' namespace, but nowhere else.
	k8sClient := newK8sClient(t, result1.Data["service_account_token"].(string))
	podsList, err := k8sClient.CoreV1().
		Pods(result1.Data["service_account_namespace"].(string)).
		List(context.Background(), metav1.ListOptions{})
	assert.NoError(t, err)
	assert.Len(t, podsList.Items, 1)

	deniedListPods, err := k8sClient.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	assert.Errorf(t, err, `pods is forbidden: User "system:serviceaccount:test:%s" cannot list resource "pods" in API group "" in the namespace "default"`, result1.Data["service_account_name"])
	assert.Empty(t, deniedListPods)

	// Clean up lease and delete roles
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

	result, err = client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Nil(t, result)
}
