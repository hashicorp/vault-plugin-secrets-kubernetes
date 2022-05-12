package integrationtest

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func randomWithPrefix(name string) string {
	return fmt.Sprintf("%s-%d", name, rand.New(rand.NewSource(time.Now().UnixNano())).Int())
}

func newK8sClient(t *testing.T, token string) kubernetes.Interface {
	t.Helper()
	config := rest.Config{
		Host:        os.Getenv("KUBE_HOST"),
		BearerToken: token,
	}
	config.TLSClientConfig.CAData = append(config.TLSClientConfig.CAData, []byte(os.Getenv("KUBERNETES_CA"))...)

	client, err := kubernetes.NewForConfig(&config)
	if err != nil {
		t.Fatalf("error creating k8s client: %s", err)
	}
	return client
}

// Verify a creds response with a generated service account
func verifyCredsResponseGenerated(t *testing.T, result *api.Secret, namespace string, leaseDuration int) {
	t.Helper()
	assert.Equal(t, leaseDuration, result.LeaseDuration)
	assert.Equal(t, false, result.Renewable)
	assert.Contains(t, result.Data["service_account_name"], "v-token-testrole")
	assert.Equal(t, namespace, result.Data["service_account_namespace"])
}

// Verify a creds response with an existing service account
func verifyCredsResponse(t *testing.T, result *api.Secret, namespace, serviceAccount string, leaseDuration int) {
	t.Helper()
	assert.Equal(t, leaseDuration, result.LeaseDuration)
	assert.Equal(t, false, result.Renewable)
	assert.Equal(t, serviceAccount, result.Data["service_account_name"])
	assert.Equal(t, namespace, result.Data["service_account_namespace"])
}

// If it's a token that's bound to a Role, test listing pods in the response's
// namespace, and other namespaces should be denied
func testRoleBindingToken(t *testing.T, credsResponse *api.Secret) {
	t.Helper()
	token := credsResponse.Data["service_account_token"].(string)
	namespace := credsResponse.Data["service_account_namespace"].(string)
	serviceAccountName := credsResponse.Data["service_account_name"].(string)
	canListPods, err := tryListPods(t, namespace, token, 1)
	assert.NoError(t, err)
	assert.True(t, canListPods)

	canListPods, err = tryListPods(t, "default", token, 0)
	assert.Errorf(t, err, `pods is forbidden: User "system:serviceaccount:test:%s" cannot list resource "pods" in API group "" in the namespace "default"`, serviceAccountName)
	assert.False(t, canListPods)
}

func testTokenRevoked(t *testing.T, credsResponse *api.Secret) {
	t.Helper()
	token := credsResponse.Data["service_account_token"].(string)
	namespace := credsResponse.Data["service_account_namespace"].(string)
	serviceAccountName := credsResponse.Data["service_account_name"].(string)

	listPods, err := tryListPods(t, namespace, token, 1)
	assert.Errorf(t, err, `pods is forbidden: User "system:serviceaccount:test:%s" cannot list resource "pods" in API group "" in the namespace "%s"`, serviceAccountName, namespace)
	assert.False(t, listPods)
}

// For a token bound to a ClusterRole, test listing pods in the response's
// namespace, and other resource types should be denied
func testClusterRoleBindingToken(t *testing.T, credsResponse *api.Secret) {
	t.Helper()
	token := credsResponse.Data["service_account_token"].(string)
	namespace := credsResponse.Data["service_account_namespace"].(string)
	serviceAccountName := credsResponse.Data["service_account_name"].(string)
	canListPods, err := tryListPods(t, namespace, token, 1)
	assert.NoError(t, err)
	assert.True(t, canListPods)

	canListPods, err = tryListPods(t, "default", token, 0)
	assert.NoError(t, err)

	canListDeployments, err := tryListDeployments(t, "default", token)
	assert.Errorf(t, err, `pods is forbidden: User "system:serviceaccount:test:%s" cannot list resource "pods" in API group "" in the namespace "default"`, serviceAccountName)
	assert.False(t, canListDeployments)
}

func tryListPods(t *testing.T, namespace, token string, count int) (bool, error) {
	k8sClient := newK8sClient(t, token)
	podsList, err := k8sClient.CoreV1().
		Pods(namespace).
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	if len(podsList.Items) != count {
		return false, fmt.Errorf("expected %d pod(s) in list, not %d", count, len(podsList.Items))
	}

	return true, nil
}

func tryListDeployments(t *testing.T, namespace, token string) (bool, error) {
	k8sClient := newK8sClient(t, token)
	podsList, err := k8sClient.AppsV1().
		Deployments(namespace).
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	if len(podsList.Items) != 1 {
		return false, fmt.Errorf("expected one pod in list, not %d", len(podsList.Items))
	}

	return true, nil
}

func testRoleType(t *testing.T, client *api.Client, mountPath string, roleConfig, expectedRoleResponse map[string]interface{}) {
	t.Helper()

	_, err := client.Logical().Write(mountPath+"/roles/testrole", roleConfig)
	require.NoError(t, err)

	roleResult, err := client.Logical().Read(mountPath + "/roles/testrole")
	assert.NoError(t, err)
	assert.Equal(t, expectedRoleResponse, roleResult.Data)

	result1, err := client.Logical().Write(mountPath+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"cluster_role_binding": false,
		"ttl":                  "2h",
	})
	require.NoError(t, err)
	require.NotNil(t, result1)
	verifyCredsResponseGenerated(t, result1, "test", 7200)

	// Try using the generated token. Listing pods should be allowed in the
	// 'test' namespace, but nowhere else.
	testRoleBindingToken(t, result1)

	leases, err := client.Logical().List("sys/leases/lookup/" + mountPath + "/creds/testrole/")
	assert.NoError(t, err)
	assert.Len(t, leases.Data["keys"], 1)

	// Clean up the lease
	err = client.Sys().RevokePrefix(mountPath + "/creds/testrole")
	assert.NoError(t, err)

	noLeases, err := client.Logical().List("sys/leases/lookup/" + mountPath + "/creds/testrole/")
	assert.NoError(t, err)
	assert.Empty(t, noLeases)

	testTokenRevoked(t, result1)

	// Test ClusterRoleBinding
	// This should fail since k8s doesn't allow a ClusterRoleBinding with a Role
	result2, err := client.Logical().Write(mountPath+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"cluster_role_binding": true,
		"ttl":                  "2h",
	})
	assert.Error(t, err, "a ClusterRoleBinding cannot ref a Role")
	assert.Nil(t, result2)

	// Finally, delete the role
	_, err = client.Logical().Delete(mountPath + "/roles/testrole")
	assert.NoError(t, err)

	result, err := client.Logical().Read(mountPath + "/roles/testrole")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func testClusterRoleType(t *testing.T, client *api.Client, mountPath string, roleConfig, expectedRoleResponse map[string]interface{}) {
	t.Helper()

	_, err := client.Logical().Write(mountPath+"/roles/testrole", roleConfig)
	require.NoError(t, err)

	roleResult, err := client.Logical().Read(mountPath + "/roles/testrole")
	assert.NoError(t, err)
	assert.Equal(t, expectedRoleResponse, roleResult.Data)

	// Generate creds with a RoleBinding
	result1, err := client.Logical().Write(mountPath+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"cluster_role_binding": false,
		"ttl":                  "2h",
	})
	assert.NoError(t, err)
	verifyCredsResponseGenerated(t, result1, "test", 7200)

	// Try using the generated token. Listing pods should be allowed in the
	// 'test' namespace, but nowhere else.
	testRoleBindingToken(t, result1)

	// Generate creds with a ClusterRoleBinding
	result2, err := client.Logical().Write(mountPath+"/creds/testrole", map[string]interface{}{
		"kubernetes_namespace": "test",
		"cluster_role_binding": true,
		"ttl":                  "2h",
	})
	assert.NoError(t, err)
	verifyCredsResponseGenerated(t, result2, "test", 7200)

	// Try the generated token, listing pods should work in any namespace,
	// but listing deployments should be denied
	testClusterRoleBindingToken(t, result2)

	leases, err := client.Logical().List("sys/leases/lookup/" + mountPath + "/creds/testrole/")
	assert.NoError(t, err)
	assert.Len(t, leases.Data["keys"], 2)

	// Clean up leases and delete the role
	err = client.Sys().RevokePrefix(mountPath + "/creds/testrole")
	assert.NoError(t, err)

	noLeases, err := client.Logical().List("sys/leases/lookup/" + mountPath + "/creds/testrole/")
	assert.NoError(t, err)
	assert.Empty(t, noLeases)

	testTokenRevoked(t, result1)
	testTokenRevoked(t, result2)

	_, err = client.Logical().Delete(mountPath + "/roles/testrole")
	assert.NoError(t, err)

	result, err := client.Logical().Read(mountPath + "/roles/testrole")
	assert.NoError(t, err)
	assert.Nil(t, result)
}
