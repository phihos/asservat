package bootstrap

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
)

// Exercise the actual fresh-profile factory and SDK over TLS. The synthetic
// response is not proof of persistent backend versions, IAM or installation.
// Reverting this factory to the legacy constructor must fail the empty/null
// cases even though the HTTP write itself completed successfully.
func TestProviderConfigurationAuditStorageRequiresImmutableVersion(t *testing.T) {
	for _, version := range []string{"", "null", "original-version"} {
		t.Run("version="+version, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, err := io.ReadAll(io.LimitReader(r.Body, 5))
				if err != nil || r.Method != http.MethodPut || r.URL.Path != "/audit/configuration-record" || r.Header.Get("If-None-Match") != "*" || string(body) != "data" {
					t.Error("fresh configuration writer lost its bounded conditional create")
				}
				w.Header().Set("ETag", `"original"`)
				if version != "" {
					w.Header().Set("X-Amz-Version-Id", version)
				}
			}))
			defer server.Close()
			writer := &installedConfigurationAudit{input: contracts.HubWorkerDeployment{AuditStore: contracts.OwnerAuditStore{Endpoint: server.URL, Region: "test", Bucket: "audit"}}, http: server.Client()}
			defer writer.Close()
			store, err := writer.storage(contracts.OwnerStorageCredential{AccessKeyID: "synthetic", SecretAccessKey: "synthetic"})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			receipt, err := store.PutSmall(ctx, "configuration-record", []byte("data"))
			if version == "original-version" {
				if err != nil || receipt.VersionID != version {
					t.Fatal("original version was not acknowledged", err)
				}
				if _, err = store.Pin(receipt); err != nil {
					t.Fatal("acknowledged original version could not be pinned", err)
				}
			} else if !errors.Is(err, objectstore.ErrStorage) || receipt != (objectstore.Object{}) {
				t.Fatal("fresh configuration profile acknowledged an unversioned physical write", err)
			}
			for _, unversioned := range []string{"", "null"} {
				pin, err := store.Pin(objectstore.Object{Key: "configuration-record", ETag: `"original"`, Bytes: 4, VersionID: unversioned})
				if !errors.Is(err, artifact.ErrInvalid) || pin != nil {
					t.Fatal("fresh configuration profile accepted an unversioned historical pin", err)
				}
			}
			if calls.Load() != 1 {
				t.Fatal("uncertain version response triggered additional I/O", calls.Load())
			}
		})
	}
}
