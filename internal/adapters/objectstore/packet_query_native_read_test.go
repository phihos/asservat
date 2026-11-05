package objectstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// This composes the actual worker receiver, outer native reader, installed
// interpreter, all three remote key requests and encrypted TLS range reads.
// The fixture's key authority/certificates are synthetic, not SQL/KMS proof.
func TestPacketQueryActualWorkerReceiverAndOuterNativeReader(t *testing.T) {
	for _, rawSource := range []bool{false, true} {
		t.Run(fmt.Sprint(rawSource), func(t *testing.T) {
			dir := t.TempDir()
			keyScope := value.KeyScope{InstallationID: testProjectionScope().RootID, Purpose: "artifact", KeyID: "synthetic"}
			f := packetEncryptedFixtureSource(t, dir, "complete", rawSource, comparisonRemoteFixtureSealer{scope: keyScope})
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
			reader.ServePacketQueries(packets.QueryPCAPNG)
			scope := f.Scope
			scope.DisplayVersion = query.PacketQueryDisplayVersion
			scope.PacketQuery, _ = (query.PacketQuerySelection{Fields: []query.PacketQueryField{query.PacketIndex, query.PacketSourceAddress}, MaxPackets: 100, MaxScanBytes: 1 << 20}).Window()
			if rawSource {
				scope.RawGrantID = scope.RootID
			}
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
			result, err := receiver.ReadApproved(ctx, operation, f.Source, scope)
			if err != nil || result.PacketQuery == nil || !result.Valid(scope) || len(result.PacketQuery.Rows) != 3 || result.PacketQuery.ScannedPackets != 3 {
				t.Fatalf("actual worker/read composition refused valid saved PCAPNG: %v", err)
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
			if rawSource && (result.PacketQuery.Rows[0][1].Text == nil || result.PacketQuery.Rows[1][1] != (query.PacketQueryCell{}) || result.PacketQuery.Rows[2][1] != (query.PacketQueryCell{})) {
				t.Fatal("raw query fabricated incomplete headers")
			}

			encoded, _ := json.Marshal(result)
			if bytes.Contains(encoded, []byte("SYNTHETIC-RAW-PRIVATE-PAYLOAD")) {
				t.Fatal("raw payload escaped receiver")
			}
		})
	}

}
