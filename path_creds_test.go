// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package kubesecrets

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoleBindingCombinations validates the four legal/illegal combinations of
// kubernetes_role_type / kubernetes_role_ref_type and the cluster_role_binding
// creds flag:
//
//	✅  Role        + RoleBinding         (default, namespace-scoped)
//	✅  ClusterRole + ClusterRoleBinding  (cluster-wide)
//	✅  RoleBinding → ClusterRole ref     ("reusable template" pattern)
//	❌  Role/any    + ClusterRoleBinding  where roleRef.kind == Role
func TestRoleBindingCombinations(t *testing.T) {
	b, s := getTestBackend(t)

	// helper: create a creds request and return the response
	requestCreds := func(roleName, namespace string, clusterRoleBinding bool) (*logical.Response, error) {
		t.Helper()
		return b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      pathCreds + roleName,
			Storage:   s,
			Data: map[string]interface{}{
				"kubernetes_namespace": namespace,
				"cluster_role_binding": clusterRoleBinding,
			},
		})
	}

	// ── combination 1: Role + RoleBinding ────────────────────────────────────
	// kubernetes_role_type=Role, kubernetes_role_ref_type defaults to Role,
	// cluster_role_binding=false → valid.
	// No real k8s cluster in unit tests so getClient will error; we only assert
	// that Vault's own guard did NOT fire.
	t.Run("Role+RoleBinding is valid", func(t *testing.T) {
		_, err := testRoleCreate(t, b, s, "combo-role-rb", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1"},
			"kubernetes_role_name":          "my-role",
			"kubernetes_role_type":          "Role",
			// kubernetes_role_ref_type omitted → defaults to "Role"
		})
		require.NoError(t, err)

		resp, err := requestCreds("combo-role-rb", "app1", false)
		// getClient will error (no cluster config) — that's fine for a unit test.
		// What must NOT happen is the guard returning "a ClusterRoleBinding cannot ref a Role".
		guardFired := resp != nil && resp.IsError() &&
			resp.Error().Error() == "a ClusterRoleBinding cannot ref a Role"
		assert.False(t, guardFired, "valid combination must not be rejected by Vault's guard")
		_ = err // k8s client error expected
	})

	// ── combination 2: ClusterRole + ClusterRoleBinding ──────────────────────
	// kubernetes_role_type=ClusterRole, cluster_role_binding=true → valid
	t.Run("ClusterRole+ClusterRoleBinding is valid", func(t *testing.T) {
		_, err := testRoleCreate(t, b, s, "combo-cr-crb", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1"},
			"kubernetes_role_name":          "my-cluster-role",
			"kubernetes_role_type":          "ClusterRole",
			// kubernetes_role_ref_type omitted → defaults to "ClusterRole"
		})
		require.NoError(t, err)

		resp, err := requestCreds("combo-cr-crb", "app1", true)
		guardFired := resp != nil && resp.IsError() &&
			resp.Error().Error() == "a ClusterRoleBinding cannot ref a Role"
		assert.False(t, guardFired, "valid combination must not be rejected by Vault's guard")
		_ = err
	})

	// ── combination 3: RoleBinding → ClusterRole ref ("reusable template") ───
	// kubernetes_role_type=Role (→ RoleBinding), kubernetes_role_ref_type=ClusterRole,
	// cluster_role_binding=false → valid
	t.Run("RoleBinding->ClusterRole ref reusable-template is valid", func(t *testing.T) {
		_, err := testRoleCreate(t, b, s, "combo-cr-rb", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1"},
			"kubernetes_role_name":          "my-cluster-role",
			"kubernetes_role_type":          "Role",
			"kubernetes_role_ref_type":      "ClusterRole",
		})
		require.NoError(t, err)

		resp, err := requestCreds("combo-cr-rb", "app1", false)
		guardFired := resp != nil && resp.IsError() &&
			resp.Error().Error() == "a ClusterRoleBinding cannot ref a Role"
		assert.False(t, guardFired, "valid combination must not be rejected by Vault's guard")
		_ = err
	})

	// ── combination 4: Role + ClusterRoleBinding ──────────────────────────────
	// roleRef.kind resolves to Role but cluster_role_binding=true → INVALID
	t.Run("Role+ClusterRoleBinding is rejected", func(t *testing.T) {
		_, err := testRoleCreate(t, b, s, "combo-role-crb", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1"},
			"kubernetes_role_name":          "my-role",
			"kubernetes_role_type":          "Role",
			// kubernetes_role_ref_type omitted → defaults to "Role"
		})
		require.NoError(t, err)

		resp, err := requestCreds("combo-role-crb", "app1", true)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.EqualError(t, resp.Error(), "a ClusterRoleBinding cannot ref a Role")
	})

	// ── combination 4 variant: explicit ClusterRole type but Role ref ─────────
	// kubernetes_role_type=ClusterRole (passes old guard), kubernetes_role_ref_type=Role,
	// cluster_role_binding=true → INVALID (new guard catches this)
	t.Run("explicit Role ref+ClusterRoleBinding is rejected", func(t *testing.T) {
		_, err := testRoleCreate(t, b, s, "combo-explicit-role-ref-crb", map[string]interface{}{
			"allowed_kubernetes_namespaces": []string{"app1"},
			"kubernetes_role_name":          "my-role",
			"kubernetes_role_type":          "ClusterRole",
			"kubernetes_role_ref_type":      "Role",
		})
		require.NoError(t, err)

		resp, err := requestCreds("combo-explicit-role-ref-crb", "app1", true)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.EqualError(t, resp.Error(), "a ClusterRoleBinding cannot ref a Role")
	})
}
