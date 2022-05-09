package kubesecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ryboe/q"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_yaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type client struct {
	k8s kubernetes.Interface
}

func newClient(config *kubeConfig) (*client, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	clientConfig := rest.Config{
		Host:        config.Host,
		BearerToken: config.ServiceAccountJwt,
	}
	if config.CACert != "" {
		// append to clientConfig.TLSClientConfig.CAData
		clientConfig.TLSClientConfig.CAData = append(clientConfig.TLSClientConfig.CAData, []byte(config.CACert)...)
	}
	k8sClient, err := kubernetes.NewForConfig(&clientConfig)
	if err != nil {
		return nil, err
	}
	return &client{k8sClient}, nil
}

func (c *client) createToken(ctx context.Context, namespace, name string, ttl time.Duration) (*authenticationv1.TokenRequestStatus, error) {
	intTTL := int64(ttl.Seconds())
	resp, err := c.k8s.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, name, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &intTTL,
			// Audiences:         audiences,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	q.Q("resp is", resp) // DEBUG

	c.k8s.CoreV1().ServiceAccounts(namespace)
	return &resp.Status, nil
}

func (c *client) createServiceAccount(ctx context.Context, namespace, name string, labels, annotations map[string]string) (*v1.ServiceAccount, error) {
	serviceAccountConfig := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
	}
	return c.k8s.CoreV1().ServiceAccounts(namespace).Create(ctx, serviceAccountConfig, metav1.CreateOptions{})
}

func (c *client) deleteServiceAccount(ctx context.Context, namespace, name string) error {
	return c.k8s.CoreV1().ServiceAccounts(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

func (c *client) createRole(ctx context.Context, namespace, name string, vaultRole *roleEntry) error {
	roleRules, err := makeRules(vaultRole.RoleRules)
	if err != nil {
		return err
	}
	objectMeta := metav1.ObjectMeta{
		Name:        name,
		Labels:      vaultRole.Metadata.Labels,
		Annotations: vaultRole.Metadata.Annotations,
	}

	switch strings.ToLower(vaultRole.K8sRoleType) {
	case "role":
		objectMeta.Namespace = namespace
		roleConfig := &rbacv1.Role{
			ObjectMeta: objectMeta,
			Rules:      roleRules,
		}
		_, err := c.k8s.RbacV1().Roles(namespace).Create(ctx, roleConfig, metav1.CreateOptions{})
		return err

	case "clusterrole":
		roleConfig := &rbacv1.ClusterRole{
			ObjectMeta: objectMeta,
			Rules:      roleRules,
		}
		_, err := c.k8s.RbacV1().ClusterRoles().Create(ctx, roleConfig, metav1.CreateOptions{})
		return err

	default:
		return fmt.Errorf("unknown role type '%s'", vaultRole.K8sRoleType)
	}
}

func (c *client) deleteRole(ctx context.Context, namespace, name, roleType string) error {
	switch strings.ToLower(roleType) {
	case "role":
		return c.k8s.RbacV1().Roles(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	case "clusterrole":
		return c.k8s.RbacV1().ClusterRoles().Delete(ctx, name, metav1.DeleteOptions{})
	default:
		return fmt.Errorf("unsupported role type '%s'", roleType)
	}
}

func (c *client) createRoleBinding(ctx context.Context, namespace, name, k8sRoleName string, isClusterRoleBinding bool, vaultRole *roleEntry) error {
	objectMeta := metav1.ObjectMeta{
		Name:        name,
		Labels:      vaultRole.Metadata.Labels,
		Annotations: vaultRole.Metadata.Annotations,
	}
	subjects := []rbacv1.Subject{
		{
			Kind:      "ServiceAccount",
			Name:      name,
			Namespace: namespace,
		},
	}
	roleRef := rbacv1.RoleRef{
		Kind: vaultRole.K8sRoleType,
		Name: k8sRoleName,
	}

	if isClusterRoleBinding {
		roleConfig := &rbacv1.ClusterRoleBinding{
			ObjectMeta: objectMeta,
			Subjects:   subjects,
			RoleRef:    roleRef,
		}
		_, err := c.k8s.RbacV1().ClusterRoleBindings().Create(ctx, roleConfig, metav1.CreateOptions{})
		return err
	}

	objectMeta.Namespace = namespace
	roleConfig := &rbacv1.RoleBinding{
		ObjectMeta: objectMeta,
		Subjects:   subjects,
		RoleRef:    roleRef,
	}
	_, err := c.k8s.RbacV1().RoleBindings(namespace).Create(ctx, roleConfig, metav1.CreateOptions{})
	return err
}

func (c *client) deleteRoleBinding(ctx context.Context, namespace, name string, isClusterRoleBinding bool) error {
	if isClusterRoleBinding {
		return c.k8s.RbacV1().ClusterRoleBindings().Delete(ctx, name, metav1.DeleteOptions{})
	}
	return c.k8s.RbacV1().RoleBindings(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

func makeRules(rules string) ([]rbacv1.PolicyRule, error) {
	policyRules := struct {
		Rules []rbacv1.PolicyRule `json:"rules"`
	}{}
	decoder := k8s_yaml.NewYAMLOrJSONDecoder(strings.NewReader(rules), len(rules))
	err := decoder.Decode(&policyRules)
	if err != nil {
		return nil, err
	}
	return policyRules.Rules, nil
}
