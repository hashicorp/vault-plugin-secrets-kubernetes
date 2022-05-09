package kubesecrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) kubeServiceAccount() *framework.Secret {
	return &framework.Secret{
		Type: kubeTokenType,
		Fields: map[string]*framework.FieldSchema{
			"service_account_namespace": {
				Type:        framework.TypeString,
				Description: "Kubernetes Namespace",
			},
			"service_account_name": {
				Type:        framework.TypeString,
				Description: "Kubernetes Service Account Name",
			},
			"service_account_token": {
				Type:        framework.TypeString,
				Description: "Kubernetes Service Account Token",
			},
		},
		Revoke: b.kubeTokenRevoke,
	}
}

func (b *backend) kubeTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	namespace := req.Secret.InternalData["service_account_namespace"].(string)
	isClusterRoleBinding := req.Secret.InternalData["cluster_role_binding"].(bool)
	k8sServiceAccount := req.Secret.InternalData["created_service_account"].(string)
	k8sRoleBinding := req.Secret.InternalData["created_role_binding"].(string)
	k8sRole := req.Secret.InternalData["created_role"].(string)
	k8sRoleType := req.Secret.InternalData["created_role_type"].(string)

	if k8sRoleBinding != "" {
		if err := client.deleteRoleBinding(ctx, namespace, k8sRoleBinding, isClusterRoleBinding); err != nil {
			roleType := "RoleBinding"
			if isClusterRoleBinding {
				roleType = "ClusterRoleBinding"
			}
			return nil, fmt.Errorf("failed to delete %s '%s/%s: %s", roleType, namespace, k8sRoleBinding, err)
		}
	}
	if k8sServiceAccount != "" {
		if err := client.deleteServiceAccount(ctx, namespace, k8sServiceAccount); err != nil {
			return nil, fmt.Errorf("failed to delete ServiceAccount '%s/%s': %s", namespace, k8sServiceAccount, err)
		}
	}
	if k8sRole != "" {
		if err := client.deleteRole(ctx, namespace, k8sRole, k8sRoleType); err != nil {
			return nil, fmt.Errorf("failed to delete %s '%s/%s': %s", k8sRoleType, namespace, k8sRole, err)
		}
	}

	return nil, nil
}

// TODO(tvoran): remove since these aren't renewable
func (b *backend) kubeTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, errors.New("internal data 'role' not found")
	}

	role, err := getRole(ctx, req.Storage, roleRaw.(string))
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = role.TokenTTL
	resp.Secret.MaxTTL = role.TokenMaxTTL
	return nil, nil
}
