package integrationtest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Set the environment variable INTEGRATION_TESTS to any non-empty value to run
// the tests in this package. The test assumes it has available:
//   - kubectl
//   - A Kubernetes cluster in which:
//       - it can use the `test` namespace
//       - Vault is deployed and accessible
// See `make setup-integration-test` for manual testing.
func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION_TESTS") != "" {
		os.Setenv("VAULT_ADDR", "http://127.0.0.1:38300")
		os.Setenv("VAULT_TOKEN", "root")
		os.Setenv("KUBERNETES_JWT", getVaultJWT())
		os.Setenv("KUBERNETES_CA", getK8sCA())
		os.Setenv("KUBE_HOST", getKubeHost(os.Getenv("KIND_CLUSTER_NAME")))
		os.Setenv("SUPER_JWT", getSuperJWT())
		os.Setenv("BROKEN_JWT", getBrokenJWT())
		os.Exit(m.Run())
	}
}

func TestMount(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, umount := mountHelper(t, client)
	defer umount()
}

func TestConfig(t *testing.T) {
	// Pick up VAULT_ADDR and VAULT_TOKEN from env vars
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	path, umount := mountHelper(t, client)
	defer umount()

	// create
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{
		"disable_local_ca_jwt": true,
		"kubernetes_ca_cert":   "cert",
		"kubernetes_host":      "host",
		"service_account_jwt":  "jwt",
	})
	assert.NoError(t, err)

	result, err := client.Logical().Read(path + "/config")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"disable_local_ca_jwt": true,
		"kubernetes_ca_cert":   "cert",
		"kubernetes_host":      "host",
	}, result.Data)

	// update
	_, err = client.Logical().Write(path+"/config", map[string]interface{}{
		"kubernetes_host": "another-host",
	})
	assert.NoError(t, err)

	result, err = client.Logical().Read(path + "/config")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"disable_local_ca_jwt": true,
		"kubernetes_ca_cert":   "cert",
		"kubernetes_host":      "another-host",
	}, result.Data)

	// delete
	_, err = client.Logical().Delete(path + "/config")
	assert.NoError(t, err)

	result, err = client.Logical().Read(path + "/config")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestRole(t *testing.T) {
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
		"generated_role_rules":          sampleRules,
		"token_default_ttl":             "1h",
		"token_max_ttl":                 "24h",
	})
	assert.NoError(t, err)

	result, err := client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"allowed_kubernetes_namespaces": []interface{}{"*"},
		"extra_annotations":             nil,
		"extra_labels":                  nil,
		"generated_role_rules":          sampleRules,
		"kubernetes_role_name":          "",
		"kubernetes_role_type":          "Role",
		"name":                          "testrole",
		"name_template":                 "",
		"service_account_name":          "",
		"token_max_ttl":                 oneDay,
		"token_default_ttl":             oneHour,
	}, result.Data)

	// update
	_, err = client.Logical().Write(path+"/roles/testrole", map[string]interface{}{
		"allowed_kubernetes_namespaces": []string{"app1", "app2"},
		"extra_annotations":             sampleExtraAnnotations,
		"extra_labels":                  sampleExtraLabels,
		"token_default_ttl":             "30m",
	})

	result, err = client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"allowed_kubernetes_namespaces": []interface{}{"app1", "app2"},
		"extra_annotations":             asMapInterface(sampleExtraAnnotations),
		"extra_labels":                  asMapInterface(sampleExtraLabels),
		"generated_role_rules":          sampleRules,
		"kubernetes_role_name":          "",
		"kubernetes_role_type":          "Role",
		"name":                          "testrole",
		"name_template":                 "",
		"service_account_name":          "",
		"token_max_ttl":                 oneDay,
		"token_default_ttl":             thirtyMinutes,
	}, result.Data)

	result, err = client.Logical().List(path + "/roles")
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"keys": []interface{}{"testrole"}}, result.Data)

	_, err = client.Logical().Delete(path + "/roles/testrole")
	assert.NoError(t, err)

	result, err = client.Logical().Read(path + "/roles/testrole")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func mountHelper(t *testing.T, client *api.Client) (string, func()) {
	t.Helper()

	path := randomWithPrefix("kubernetes")
	fullPath := fmt.Sprintf("sys/mounts/%s", path)
	_, err := client.Logical().Write(fullPath, map[string]interface{}{
		"type": "kubernetes-dev",
	})
	if err != nil {
		t.Fatal(err)
	}

	return path, func() {
		_, err = client.Logical().Delete(fullPath)
		if err != nil {
			t.Fatal(err)
		}
	}
}

const sampleRules = `rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
`

var (
	sampleExtraLabels = map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	sampleExtraAnnotations = map[string]string{
		"key3": "value3",
		"key4": "value4",
	}
)

const (
	thirtyMinutes json.Number = "1800"
	oneHour       json.Number = "3600"
	oneDay        json.Number = "86400"
)

func runCmd(command string) string {
	parts := strings.Split(command, " ")
	fmt.Println(parts)
	cmd := exec.Command(parts[0], parts[1:]...)
	out := &bytes.Buffer{}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		panic(fmt.Sprintf("Got unexpected output: %s, err = %s", out.String(), err))
	}
	return out.String()
}

func getVaultJWT() string {
	return runCmd("kubectl exec --namespace=test vault-0 -- cat /var/run/secrets/kubernetes.io/serviceaccount/token")
}

func getSuperJWT() string {
	name := runCmd("kubectl --namespace=test get serviceaccount super-jwt -o jsonpath={.secrets[0].name}")
	b64token := runCmd(fmt.Sprintf("kubectl --namespace=test get secrets %s -o jsonpath={.data.token}", name))
	token, err := base64.URLEncoding.DecodeString(b64token)
	if err != nil {
		panic(err)
	}
	return string(token)
}

func getBrokenJWT() string {
	name := runCmd("kubectl --namespace=test get serviceaccount broken-jwt -o jsonpath={.secrets[0].name}")
	b64token := runCmd(fmt.Sprintf("kubectl --namespace=test get secrets %s -o jsonpath={.data.token}", name))
	token, err := base64.URLEncoding.DecodeString(b64token)
	if err != nil {
		panic(err)
	}
	return string(token)
}

func getK8sCA() string {
	return runCmd("kubectl exec --namespace=test vault-0 -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
}

func getKubeHost(clusterName string) string {
	cmd := fmt.Sprintf(`kubectl config view --raw --minify --flatten --output=jsonpath={.clusters[?(@.name=="kind-%s")].cluster.server}`, clusterName)
	return runCmd(cmd)
}
