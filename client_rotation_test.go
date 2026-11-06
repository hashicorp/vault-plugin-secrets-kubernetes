// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package kubesecrets

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-secure-stdlib/fileutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestClientServiceAccountTokenRotation(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit_token=%t", explicit), func(t *testing.T) {
			ctx := context.Background()
			b, storage := getTestBackend(t)
			tokenPath := filepath.Join(t.TempDir(), "token")
			require.NoError(t, os.WriteFile(tokenPath, []byte("original"), 0o600))
			// Disable the file cache delay so rotation is deterministic.
			b.localSATokenReader = fileutil.NewCachingFileReader(tokenPath, 0)
			headers := make(chan string, 3)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				headers <- r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"test"}}`)
			}))
			defer server.Close()
			config := &kubeConfig{Host: server.URL, CACert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
			if explicit {
				config.ServiceAccountJwt = "configured"
			}
			entry, err := logical.StorageEntryJSON(configPath, config)
			require.NoError(t, err)
			require.NoError(t, storage.Put(ctx, entry))
			request := func() *client {
				t.Helper()
				c, err := b.getClient(ctx, storage)
				require.NoError(t, err)
				_, err = c.getNamespaceLabelSet(ctx, "test")
				require.NoError(t, err)
				return c
			}
			want := "Bearer original"
			if explicit {
				want = "Bearer configured"
			}
			first := request()
			require.Equal(t, want, <-headers)
			require.Same(t, first, request(), "reuse the client while the token is unchanged")
			require.Equal(t, want, <-headers)
			require.NoError(t, os.WriteFile(tokenPath, []byte("rotated"), 0o600))
			request()
			if !explicit {
				want = "Bearer rotated"
			}
			require.Equal(t, want, <-headers)
		})
	}
}
