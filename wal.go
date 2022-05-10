package kubesecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

const (
	walServiceAccountKind = "serviceAccount"
	walRoleKind           = "role"
	walBindingKind        = "roleBinding"
)

// Eventually expire the WAL if for some reason the rollback operation consistently fails
var maxWALAge = 24 * time.Hour

func (b *backend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	switch kind {
	case walServiceAccountKind:
		return b.rollbackServiceAccountWAL(ctx, req, data)
	case walRoleKind:
		return b.rollbackRoleWAL(ctx, req, data)
	case walBindingKind:
		return b.rollbackBindingWAL(ctx, req, data)
	default:
		return fmt.Errorf("unknown rollback type %q", kind)
	}
}

type walServiceAccount struct {
	Namespace  string
	Name       string
	Expiration time.Time
}

func (b *backend) rollbackServiceAccountWAL(ctx context.Context, req *logical.Request, data interface{}) error {
	// Decode the WAL data
	var entry walServiceAccount
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339),
		Result:     &entry,
	})
	if err != nil {
		return err
	}
	err = d.Decode(data)
	if err != nil {
		return err
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return err
	}

	b.Logger().Debug("rolling back service account", "namespace", entry.Namespace, "name", entry.Name)

	// Attempt to delete the Service Account. If we don't succeed within
	// maxWALAge (e.g. client creds have changed and the delete will never
	// succeed), unconditionally remove the WAL.
	if err := client.deleteServiceAccount(ctx, entry.Namespace, entry.Name); err != nil {
		b.Logger().Warn("rollback error deleting service account", "namespace", entry.Namespace, "name", entry.Name, "err", err)

		if time.Now().After(entry.Expiration) {
			return nil
		}
		return err
	}

	return nil
}

type walRole struct {
	Namespace  string
	Name       string
	RoleType   string
	Expiration time.Time
}

func (b *backend) rollbackRoleWAL(ctx context.Context, req *logical.Request, data interface{}) error {
	// Decode the WAL data
	var entry walRole
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339),
		Result:     &entry,
	})
	if err != nil {
		return err
	}
	err = d.Decode(data)
	if err != nil {
		return err
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return err
	}

	b.Logger().Debug("rolling back", "role", entry.RoleType, "namespace", entry.Namespace, "name", entry.Name)

	// Attempt to delete the Role. If we don't succeed within maxWALAge (e.g.
	// client creds have changed and the delete will never succeed),
	// unconditionally remove the WAL.
	if err := client.deleteRole(ctx, entry.Namespace, entry.Name, entry.RoleType); err != nil {
		b.Logger().Warn("rollback error deleting", "roleType", entry.RoleType, "err", err)

		if time.Now().After(entry.Expiration) {
			return nil
		}
		return err
	}

	return nil
}

type walRoleBinding struct {
	Namespace  string
	Name       string
	IsCluster  bool
	Expiration time.Time
}

func (b *backend) rollbackBindingWAL(ctx context.Context, req *logical.Request, data interface{}) error {
	// Decode the WAL data
	var entry walRoleBinding
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339),
		Result:     &entry,
	})
	if err != nil {
		return err
	}
	err = d.Decode(data)
	if err != nil {
		return err
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return err
	}

	b.Logger().Debug("rolling back role binding", "isClusterRoleBinding", entry.IsCluster, "namespace", entry.Namespace, "name", entry.Name)

	// Attempt to delete the RolbBinding. If we don't succeed within maxWALAge
	// (e.g. client creds have changed and the delete will never succeed),
	// unconditionally remove the WAL.
	if err := client.deleteRoleBinding(ctx, entry.Namespace, entry.Name, entry.IsCluster); err != nil {
		b.Logger().Warn("rollback error deleting role binding", "isClusterRoleBinding", entry.IsCluster, "namespace", entry.Namespace, "name", entry.Name, "err", err)

		if time.Now().After(entry.Expiration) {
			return nil
		}
		return err
	}

	return nil
}
