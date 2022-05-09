package integrationtest

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

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

func testCreds(t *testing.T, role string, config map[string]interface{}) {
	t.Helper()
	// TODO(tvoran): if type is clusterrole, try listing deployments instead of
	// pods, since pods will be allowed everywhere
}
