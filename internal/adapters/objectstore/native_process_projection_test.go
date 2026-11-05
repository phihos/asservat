package objectstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	processcodec "asservat.local/asservat/internal/adapters/processes"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// This composes the actual worker receiver, outer native reader, installed
// interpreter, all three remote key requests and encrypted TLS range reads.
// The fixture's key authority/certificates are synthetic, not SQL/KMS proof.
func TestTargetDiscoveryActualWorkerReceiverAndOuterNativeReader(t *testing.T) {
	for _, mode := range []string{"current", "wrong-pod", "wrong-version"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			keyScope := value.KeyScope{InstallationID: testProjectionScope().RootID, Purpose: "artifact", KeyID: "synthetic"}
			f := processEncryptedFixture(t, dir, comparisonRemoteFixtureSealer{scope: keyScope})
			verifier, _, _, _ := profileEncryptedVerifier(t, dir, f, false)
			var mu sync.Mutex
			roles := map[string]bool{}
			keyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				request, err := contracts.DecodeKeyRequest(r.Body)
				if err != nil || request.Operation != "unwrap" || request.AuthorityID != f.Scope.RootID || request.Sealed == nil {
					w.WriteHeader(400)
					return
				}
				info, err := authapp.DescribeKeyRequest(value.KeyRequest{Scope: value.KeyScope{InstallationID: request.Scope.InstallationID, Purpose: request.Scope.Purpose, KeyID: request.Scope.KeyID}, AuthorityID: request.AuthorityID, Operation: request.Operation, Binding: request.Binding, Sealed: artifact.SealedKey{Reference: request.Sealed.Reference, Ciphertext: request.Sealed.Ciphertext}})
				if err != nil {
					w.WriteHeader(400)
					return
				}
				mu.Lock()
				used := roles[string(request.Binding)]
				roles[string(request.Binding)] = true
				mu.Unlock()
				if used {
					w.WriteHeader(403)
					return
				}
				key, err := base64.StdEncoding.DecodeString(request.Sealed.Ciphertext)
				if err != nil {
					w.WriteHeader(400)
					return
				}
				defer clear(key)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(contracts.KeyServiceResponse{Format: contracts.KeyServiceFormat, Operation: "unwrap", Output: key, RequestSHA256: hex.EncodeToString(info.RequestDigest[:]), ValidUntil: time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)})
			}))
			defer keyServer.Close()
			client := keyServer.Client()
			client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{keyServer.TLS.Certificates[0]}
			reader, err := NewNativeContextReader(verifier.store, keyScope, keyServer.URL, client)
			if err != nil {
				t.Fatal(err)
			}
			reader.ServeTargetDiscoveries(processcodec.Query)
			scope := f.Scope
			now := time.Now().UTC()
			until := now.Add(10 * time.Second)
			revision := identity.Revision{UID: scope.RootID, Generation: 1, Digest: artifact.Digest{1}}
			path := artifact.DownloadPath{ID: scope.RootID, TargetClusterID: scope.ClusterID, StoreID: f.Source.Expectation.Registration.StoreID, StorageRegion: "fixture", AcquisitionClusterID: scope.RootID, AcquisitionRegion: "fixture", ConnectorClusterID: scope.RootID, ConnectorRegion: "fixture", HubClusterID: scope.RootID, HubRegion: "fixture", WorkerConfiguration: revision, HubConfiguration: revision}
			proof := artifact.DownloadProcessingProof{RootID: scope.RootID, Epoch: scope.RootID, CaptureID: scope.CaptureID, Location: f.Source.Expectation.Registration.Location, Sequence: 1, StateDigest: artifact.Digest{1}, ObservedAt: now, ValidUntil: until}
			operation := value.NativeOperation{Path: path, Processing: proof, Reference: value.NativeReference{InstallationID: scope.RootID, QueryID: scope.RootID, WorkerID: scope.RootID, OperationID: scope.RootID, Fence: 1}, Kind: value.NativeProjection, HubPodUID: scope.RootID, HubProcessEpoch: scope.RootID, WorkerPodUID: scope.RootID, WorkerPublicKey: artifact.Digest{1}, SourceVersion: scope.Version, ParentID: scope.RootID, Generation: 1, StartedAt: now, Until: until}
			worker := value.WorkerCredentialTarget{InstallationID: scope.RootID, QueryID: scope.RootID, WorkerID: scope.RootID, PodUID: scope.RootID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
			ctx, cancel := context.WithDeadline(t.Context(), until)
			defer cancel()
			receiver, err := evidence.NewRegionalApprovedResult(ctx, worker, reader, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				receiver.Close()
				if err := receiver.Wait(context.Background()); err != nil {
					t.Error(err)
				}
			}()
			if mode == "wrong-pod" {
				scope.PodUID = "replacement"
			}
			if mode == "wrong-version" {
				scope.Version[0] ^= 1
			}
			result, err := receiver.ReadApproved(ctx, operation, f.Source, scope)
			if mode != "current" {
				mu.Lock()
				count := len(roles)
				mu.Unlock()
				if err == nil || result.TargetDiscovery != nil || count != 0 {
					t.Fatal("foreign source reached keys", count, err)
				}
				return
			}
			if err != nil || result.TargetDiscovery == nil || !result.Valid(scope) || result.TargetDiscovery.Total != 1 || result.TargetDiscovery.Processes[0].DisplayPID != 1 {
				t.Fatalf("actual worker/read composition refused valid saved process inventory: %v", err)
			}
			mu.Lock()
			count := len(roles)
			mu.Unlock()
			if count != 3 {
				t.Fatal("not three independent remote key bindings", count)
			}
			if _, err = receiver.ReadApproved(ctx, operation, f.Source, scope); err == nil {
				t.Fatal("same read batch replayed")
			}
			mu.Lock()
			count = len(roles)
			mu.Unlock()
			if count != 3 {
				t.Fatal("receiver replay spent another role")
			}
			encoded, _ := json.Marshal(result)
			if bytes.Contains(encoded, []byte("argv")) {
				t.Fatal("uncollected arguments escaped receiver")
			}
		})
	}

}
