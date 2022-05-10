package kubesecrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/helper/template"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryboe/q"
)

const (
	pathCreds     = "creds/"
	kubeTokenType = "kube_token"

	pathCredsHelpSyn  = `Request Kubernetes service account credentials for a given Vault role.`
	pathCredsHelpDesc = `
This path creates dynamic Kubernetes service account credentials.
The associated Vault role can be configured to generate tokens for an
existing service account, create a new service account bound to an
existing Role/ClusterRole, or create a new service account and role
bindings. The service account token and any other objects created in
Kubernetes will be automatically deleted when the lease has expired.
`
)

type credsRequest struct {
	Namespace          string        `json:"kubernetes_namespace"`
	ClusterRoleBinding bool          `json:"cluster_role_binding"`
	TTL                time.Duration `json:"ttl"`
	RoleName           string        `json:"role_name"`
}

func (b *backend) pathCredentials() *framework.Path {
	return &framework.Path{
		Pattern: pathCreds + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
			"kubernetes_namespace": {
				Type:        framework.TypeString,
				Description: "The name of the Kubernetes namespace in which to generate the service account",
				Required:    true,
			},
			"cluster_role_binding": {
				Type:        framework.TypeBool,
				Description: "If true, generate a ClusterRoleBinding to grant permissions across the whole cluster instead of within a namespace. Requires the Vault role to have kubernetes_role_type set to ClusterRole.",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "The ttl of the generated Kubernetes service account",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathCredentialsRead,
			logical.UpdateOperation: b.pathCredentialsRead,
		},

		HelpSynopsis:    pathCredsHelpSyn,
		HelpDescription: pathCredsHelpDesc,
	}
}

func (b *backend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	request := &credsRequest{
		RoleName: roleName,
	}
	requestNamespace, ok := d.GetOk("kubernetes_namespace")
	if !ok {
		return nil, errors.New("'kubernetes_namespace' is required")
	}
	request.Namespace = requestNamespace.(string)

	request.ClusterRoleBinding = d.Get("cluster_role_binding").(bool)

	ttlRaw, ok := d.GetOk("ttl")
	if ok {
		request.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	// Validate the request
	if !strutil.StrListContains(roleEntry.K8sNamespaces, "*") && !strutil.StrListContains(roleEntry.K8sNamespaces, request.Namespace) {
		return nil, fmt.Errorf("kubernetes_namespace '%s' is not present in role's allowed_kubernetes_namespaces", request.Namespace)
	}
	// TODO(tvoran): validate that roles.kubernetes_role_type allows the type of
	// role binding requested

	return b.createCreds(ctx, req, roleEntry, request)
}

func (b *backend) createCreds(ctx context.Context, req *logical.Request, role *roleEntry, parsedPayload *credsRequest) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	nameTemplate := role.NameTemplate
	if nameTemplate == "" {
		nameTemplate = defaultNameTemplate
	}

	up, err := template.NewTemplate(template.Template(nameTemplate))
	if err != nil {
		return nil, fmt.Errorf("unable to initialize name template: %w", err)
	}
	um := nameMetadata{
		DisplayName: req.DisplayName,
		RoleName:    role.Name,
	}
	genName, err := up.Generate(um)
	if err != nil {
		return nil, fmt.Errorf("failed to generate name: %w", err)
	}

	// Determine the TTL here, since it might come from the mount if nothing on
	// the vault role or creds payload is specified
	theTTL := time.Duration(0)
	switch {
	case parsedPayload.TTL > 0:
		theTTL = parsedPayload.TTL
	case role.TokenTTL > 0:
		theTTL = role.TokenTTL
	default:
		theTTL = b.System().DefaultLeaseTTL()
	}

	// These are created items to save internally and/or return to the caller
	token := ""
	// TODO(tvoran): because sometimes the service account name is static, and
	// this is returned to the user
	serviceAccountName := ""
	createdServiceAccountName := ""
	createdK8sRoleBinding := ""
	createdK8sRole := ""

	// WAL id's
	serviceAccountWALId := ""
	roleWALId := ""
	bindingWALId := ""

	switch {
	case role.ServiceAccountName != "":
		// Create token for existing service account
		status, err := client.createToken(ctx, parsedPayload.Namespace, role.ServiceAccountName, theTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to create a service account token for %s/%s: %s", parsedPayload.Namespace, role.ServiceAccountName, err)
		}
		serviceAccountName = role.ServiceAccountName
		token = status.Token
	case role.K8sRoleName != "":
		// Create service account for existing role
		// then rolebinding
		// then token
		serviceAccountWALId, err = createServiceAccount(ctx, client, req.Storage, parsedPayload.Namespace, genName, role.Metadata.Labels, role.Metadata.Annotations)
		if err != nil {
			return nil, err
		}

		bindingWALId, err = createRoleBinding(ctx, client, req.Storage, parsedPayload.Namespace, genName, role.K8sRoleName, parsedPayload.ClusterRoleBinding, role)
		if err != nil {
			return nil, err
		}

		status, err := client.createToken(ctx, parsedPayload.Namespace, genName, theTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to create a service account token for %s/%s: %s", parsedPayload.Namespace, genName, err)
		}
		token = status.Token
		serviceAccountName = genName
		createdServiceAccountName = genName
		createdK8sRoleBinding = genName
	case role.RoleRules != "":
		// Create role, service account, binding, token
		roleWALId, err = createRole(ctx, client, req.Storage, parsedPayload.Namespace, genName, role)
		if err != nil {
			return nil, err
		}

		serviceAccountWALId, err = createServiceAccount(ctx, client, req.Storage, parsedPayload.Namespace, genName, role.Metadata.Labels, role.Metadata.Annotations)
		if err != nil {
			return nil, err
		}

		bindingWALId, err = createRoleBinding(ctx, client, req.Storage, parsedPayload.Namespace, genName, genName, parsedPayload.ClusterRoleBinding, role)
		if err != nil {
			return nil, err
		}

		status, err := client.createToken(ctx, parsedPayload.Namespace, genName, theTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to create a service account token for %s/%s: %s", parsedPayload.Namespace, genName, err)
		}
		token = status.Token
		createdK8sRole = genName
		serviceAccountName = genName
		createdServiceAccountName = genName
		createdK8sRoleBinding = genName

	default:
		return nil, fmt.Errorf("one of service_account_name, kubernetes_role_name, or generated_role_rules must be set")
	}

	// Delete any WALs entries that were created
	var errors *multierror.Error
	for _, walId := range []string{roleWALId, serviceAccountWALId, bindingWALId} {
		if walId != "" {
			q.Q("deleting walId", walId) // DEBUG
			if err := framework.DeleteWAL(ctx, req.Storage, walId); err != nil {
				errors = multierror.Append(errors, fmt.Errorf("error deleting WAL: %w", err))
			}
		}
	}
	if errors.ErrorOrNil() != nil {
		return nil, errors
	}

	resp := b.Secret(kubeTokenType).Response(map[string]interface{}{
		"service_account_namespace": parsedPayload.Namespace,
		"service_account_name":      serviceAccountName,
		"service_account_token":     token,
	}, map[string]interface{}{
		// TODO(tvoran): i think the internal data is whatever we need to
		// cleanup on revoke (service_account_name, role, role_binding)
		// "role" is so we can lookup all the leases when a role is deleted
		"role":                      parsedPayload.RoleName,
		"service_account_namespace": parsedPayload.Namespace,
		"cluster_role_binding":      parsedPayload.ClusterRoleBinding,
		"created_service_account":   createdServiceAccountName,
		"created_role_binding":      createdK8sRoleBinding,
		"created_role":              createdK8sRole,
		"created_role_type":         role.K8sRoleType,
	})

	resp.Secret.TTL = theTTL
	if role.TokenMaxTTL > 0 {
		resp.Secret.MaxTTL = role.TokenMaxTTL
	}

	return resp, nil
}

type nameMetadata struct {
	DisplayName string
	RoleName    string
}

func (b *backend) getClient(ctx context.Context, s logical.Storage) (*client, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := b.configWithDynamicValues(ctx, s)
	if err != nil {
		return nil, err
	}

	if b.client == nil {
		if config == nil {
			config = new(kubeConfig)
		}
	}

	b.client, err = newClient(config)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}

// create service account and put a WAL entry
func createServiceAccount(ctx context.Context, client *client, s logical.Storage, namespace, name string, labels, annotations map[string]string) (string, error) {
	_, err := client.createServiceAccount(ctx, namespace, name, labels, annotations)
	if err != nil {
		return "", fmt.Errorf("failed to create service account '%s/%s': %s", namespace, name, err)
	}
	// Write a WAL entry in case subsequent parts don't complete
	walId, err := framework.PutWAL(ctx, s, walServiceAccountKind, &walServiceAccount{
		Namespace:  namespace,
		Name:       name,
		Expiration: time.Now().Add(maxWALAge),
	})
	if err != nil {
		return "", fmt.Errorf("error writing service account WAL: %w", err)
	}

	return walId, nil
}

// create role binding and put a WAL entry
func createRoleBinding(ctx context.Context, client *client, s logical.Storage, namespace, name, k8sRoleName string, isClusterRoleBinding bool, vaultRole *roleEntry) (string, error) {
	err := client.createRoleBinding(ctx, namespace, name, k8sRoleName, isClusterRoleBinding, vaultRole)
	if err != nil {
		return "", fmt.Errorf("failed to create RoleBinding/ClusterRoleBinding '%s' for %s: %s", name, k8sRoleName, err)
	}
	// Write a WAL entry in case the role binding create doesn't complete
	walId, err := framework.PutWAL(ctx, s, walBindingKind, &walRoleBinding{
		Namespace:  namespace,
		Name:       name,
		IsCluster:  isClusterRoleBinding,
		Expiration: time.Now().Add(maxWALAge),
	})
	if err != nil {
		return "", fmt.Errorf("error writing role binding WAL: %w", err)
	}

	return walId, nil
}

// create a role and put a WAL entry
func createRole(ctx context.Context, client *client, s logical.Storage, namespace, name string, vaultRole *roleEntry) (string, error) {
	err := client.createRole(ctx, namespace, name, vaultRole)
	if err != nil {
		return "", fmt.Errorf("failed to create Role/ClusterRole '%s/%s: %s", namespace, name, err)
	}
	// Write a WAL entry in case subsequent parts don't complete
	walId, err := framework.PutWAL(ctx, s, walRoleKind, &walRole{
		Namespace:  namespace,
		Name:       name,
		RoleType:   vaultRole.K8sRoleType,
		Expiration: time.Now().Add(maxWALAge),
	})
	if err != nil {
		return "", fmt.Errorf("error writing service account WAL: %w", err)
	}

	return walId, nil
}
