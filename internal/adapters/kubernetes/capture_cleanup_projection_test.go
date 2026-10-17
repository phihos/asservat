package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// Actual HTTP covers the fixed CAS and cancellation boundary only. It does
// not establish SQL activation, native guard enforcement or provider grants.
func TestCaptureCleanupProjectionCASPreservesSiblingAndOriginalAttempt(t *testing.T) {
	for _, mode := range []string{"claim", "receipt", "lost-reply", "sibling-change", "claim-replacement", "receipt-replacement", "inventory-change", "unchanged-resource-version", "wrong-api-version", "wrong-kind", "close-during-CAS"} {
		t.Run(mode, func(t *testing.T) {
			resources, complete, _ := workerProjectionStateFixture(t)
			old := complete
			originalClaim := *complete.CleanupProjection
			old.CleanupProjection = nil
			next := complete
			claim := originalClaim
			claim.Receipt = nil
			next.CleanupProjection = &claim
			if mode == "receipt" || mode == "receipt-replacement" {
				old.CleanupProjection = &claim
				next.CleanupProjection = &originalClaim
			}
			switch mode {
			case "sibling-change":
				copy := *next.CapacityProjection
				copy.PublicDigest = preparationDigest("changed sibling")
				next.CapacityProjection = &copy
			case "claim-replacement":
				old.CleanupProjection = &claim
				copy := claim
				copy.OperationID = ownerID(2995)
				next.CleanupProjection = &copy
			case "receipt-replacement":
				old.CleanupProjection = &originalClaim
				copy := originalClaim
				receipt := *copy.Receipt
				receipt.ResourceVersion = "99"
				copy.Receipt = &receipt
				next.CleanupProjection = &copy
			case "inventory-change":
				next.SetupID = ownerID(2996)
			}
			payload, _ := json.Marshal(old)
			object := &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: resources.name(), Namespace: resources.initial.Namespace.Name, UID: types.UID(ownerID(2997)), ResourceVersion: "10"}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": payload}}
			var calls atomic.Int32
			entered, release := make(chan struct{}), make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPut || r.URL.Path != resources.path() {
					t.Error("unexpected effect")
					http.Error(w, "invalid", 400)
					return
				}
				var submitted core.Secret
				if json.NewDecoder(io.LimitReader(r.Body, 128<<10)).Decode(&submitted) != nil {
					http.Error(w, "invalid", 400)
					return
				}
				if submitted.ResourceVersion != "10" || submitted.UID != object.UID {
					t.Error("original CAS identity lost")
				}
				if mode == "close-during-CAS" {
					close(entered)
					<-release
				}
				if mode == "lost-reply" {
					http.Error(w, "unknown committed reply", 500)
					return
				}
				if mode != "unchanged-resource-version" {
					submitted.ResourceVersion = "11"
				}
				// The real versioned API returns this TypeMeta even when typed
				// client-go request encoding omits it. Retain explicit malformed
				// response cases; the production decoder must still reject them.
				submitted.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}
				if mode == "wrong-api-version" {
					submitted.APIVersion = "wrong/v1"
				}
				if mode == "wrong-kind" {
					submitted.Kind = "ConfigMap"
				}
				permissionReply(w, &submitted)
			}))
			defer server.Close()
			defer close(release)
			config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
			client, err := NewPermissionClient(config, resources.initial.ClusterID, cfg.NamespaceRef{Name: resources.initial.Namespace.Name, UID: resources.initial.Namespace.UID}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			bridge := &InitialRuntimeBridge{source: &ConfigurationRoleSource{client: client}, preparer: &InitialPreparer{creator: &InitialNamespaceCreator{api: client.api}}}
			root, cancelRoot := context.WithCancel(context.Background())
			resources.ctx, resources.cancel = root, cancelRoot
			defer resources.Close()
			ctx, end := context.WithTimeout(context.Background(), time.Second)
			defer end()
			ctx, finishBorrow, err := resources.borrowWorkerProjection(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var finishOnce sync.Once
			releaseBorrow := func() { finishOnce.Do(finishBorrow) }
			defer releaseBorrow()
			if mode == "close-during-CAS" {
				finished := make(chan error, 1)
				go func() { _, e := bridge.writeCleanupProjection(ctx, resources, object, next); finished <- e }()
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("CAS not entered")
				}
				closing := make(chan struct{})
				go func() { resources.Close(); close(closing) }()
				select {
				case err = <-finished:
					if err == nil {
						t.Fatal("canceled CAS acknowledged")
					}
				case <-time.After(time.Second):
					t.Fatal("effect ignored resource Close")
				}
				select {
				case <-closing:
					t.Fatal("Close joined before publisher released")
				default:
				}
				releaseBorrow()
				select {
				case <-closing:
				case <-time.After(time.Second):
					t.Fatal("Close not joined")
				}
				return
			}
			out, err := bridge.writeCleanupProjection(ctx, resources, object, next)
			releaseBorrow()
			pass := mode == "claim" || mode == "receipt"
			if pass && (err != nil || !equalJSON(out.State, next)) {
				t.Fatal("exact transition", err)
			}
			if !pass && err == nil {
				t.Fatal("invalid or unknown transition acknowledged")
			}
			want := int32(0)
			if pass || mode == "lost-reply" || mode == "unchanged-resource-version" || mode == "wrong-api-version" || mode == "wrong-kind" {
				want = 1
			}
			if calls.Load() != want {
				t.Fatalf("effect count %d want %d", calls.Load(), want)
			}
		})
	}
}
