package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	native "asservat.local/asservat/internal/transport/native"
)

// Facts, stored native provenance and body are synthetic. This test runs an
// actual old/new worker executable against the actual new h2/mTLS hub, never
// a compatibility predicate or mocked old worker implementation.
func TestNativeActualVersionWorkerWire(t *testing.T) {
	manifest := nativeVersionManifestFor(t)
	for _, name := range []string{"old-short", "new-short", "new-long", "old-long-refusal", "old-original-expiry"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			source := nativeVersionSource(t)
			now := time.Now().UTC().Truncate(time.Microsecond)
			until := now.Add(3 * time.Second)
			if name == "old-long-refusal" || name == "new-long" {
				until = now.Add(20 * time.Second)
			}
			id := source.Expectation.Registration.Location.ClusterID
			revision := identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{7}}
			operation := value.NativeOperation{Reference: value.NativeReference{InstallationID: id, SessionID: id, WorkerID: id, OperationID: id, Fence: 1}, Kind: value.NativeResponse, HubPodUID: id, HubProcessEpoch: id, WorkerPodUID: id, WorkerPublicKey: artifact.Digest{1}, SourceVersion: evidence.ContextCopiesDigest(source.Copies), ParentID: id, Generation: 1, StartedAt: now, Until: until}
			operation.Path = artifact.DownloadPath{ID: id, TargetClusterID: id, StoreID: source.Expectation.Registration.StoreID, StorageRegion: "fixture", AcquisitionClusterID: id, AcquisitionRegion: "fixture", ConnectorClusterID: id, ConnectorRegion: "fixture", HubClusterID: id, HubRegion: "fixture", WorkerConfiguration: revision, HubConfiguration: revision}
			operation.Processing = artifact.DownloadProcessingProof{RootID: id, Epoch: id, CaptureID: id, Location: source.Expectation.Registration.Location, Sequence: 1, StateDigest: artifact.Digest{8}, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
			leaseUntil := identity.Earlier(until, now.Add(5*time.Second))
			authority := artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: id, WorkloadUID: id, PodUID: id, Version: operation.SourceVersion, Principal: identity.Principal{Issuer: "https://synthetic.invalid", Subject: "developer", ClientID: "fixture", Kind: identity.Human}}, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: revision, CheckedAt: now, ValidUntil: leaseUntil, AccessUntil: now.Add(time.Minute), DeleteBy: now.Add(2 * time.Minute)}
			const size = 2 * int(artifact.DeliveryBytes)
			delivery := artifact.DownloadDeliveryLease{ResponseID: id, WindowID: id, OwnerID: id, Generation: 1, Sequence: 1, Length: int64(size), StartedAt: now, Until: leaseUntil, Authority: authority}
			lease := value.NativeLease{Operation: operation, Certificate: artifact.Digest{3}, Sequence: 1, ObservedAt: now, Until: leaseUntil}
			gate, err := evidence.NewNativeFrameGate(ctx, func(context.Context) (value.NativeLease, error) { return lease, nil }, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { gate.Close(); _ = gate.Wait(context.Background()) }()
			wire, _ := json.Marshal(operation)
			encoded, _ := json.Marshal(source)
			command := contracts.NativeCommand{Format: contracts.NativeExchangeFormat, Reference: contracts.NativeReference{InstallationID: id, SessionID: id, WorkerID: id, OperationID: id, Fence: 1}, Kind: string(operation.Kind), Source: encoded, Operation: wire, ParentID: id, Generation: 1, LeaseSequence: 1, Until: until.Format(time.RFC3339Nano), WindowID: id, Length: int64(size)}
			hub, err := native.NewHubResponseOperation(gate, command, source, delivery, func(context.Context, value.NativeLease) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer hub.Close()
			keys := nativeVersionCertificates(t, id)
			certificate := keys.certificateForPeer(t, "acquisition", id)
			endpoint, closeServer := nativeVersionServer(t, ctx, hub, command.Reference, keys, certificate)
			defer closeServer()
			keyBytes, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			input := nativeVersionInput{Action: "worker", Endpoint: endpoint, Roots: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: keys.root.Raw}), Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), Hello: contracts.NativeHello{Format: contracts.NativeExchangeFormat, Reference: contracts.NativeReference{InstallationID: id, SessionID: id, WorkerID: id}, Nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", WorkerToken: []byte("synthetic.native.token")}, Worker: value.WorkerCredentialTarget{InstallationID: id, SessionID: id, WorkerID: id, PodUID: id, CreatedAt: now, RunUntil: now.Add(time.Minute)}, WorkerKey: operation.WorkerPublicKey, Source: source, BodyBytes: size}
			clear(keyBytes)
			if name != "old-long-refusal" {
				warmup := operation
				warmup.Kind = value.NativePrepare
				warmup.Until = now.Add(3 * time.Second)
				input.Warmup = &warmup
			}
			binary := manifest.Binaries["old"]
			if name == "new-short" || name == "new-long" {
				binary = manifest.Binaries["new"]
			}
			type outcome struct {
				output nativeVersionOutput
				err    error
			}
			done := make(chan outcome, 1)
			go func() { out, err := invokeNativeVersion(ctx, binary, input); done <- outcome{out, err} }()
			joined := false
			defer func() {
				cancel()
				if !joined {
					<-done
				}
			}()
			terminal := func() nativeVersionOutput {
				t.Helper()
				result := <-done
				joined = true
				if result.err != nil {
					t.Fatal(result.err)
				}
				t.Logf("actual %s worker stage=%s accepted=%t class=%s readerCalls=%d dataFrames=%d dataBytes=%d", binary.Revision[:8], result.output.Stage, result.output.Accepted, result.output.ErrorClass, result.output.ReaderCalls, result.output.DataFrames, result.output.DataBytes)
				return result.output
			}
			first, err := hub.ReadChunk(ctx, delivery, 0, artifact.DeliveryBytes)
			if name == "old-long-refusal" {
				if err == nil {
					clear(first.Bytes)
					t.Fatal("actual old worker accepted new long response")
				}
				out := terminal()
				if out.Accepted || out.Stage != "conversation" || out.NativeState != contracts.NativeUncertain || out.ErrorClass != "protocol" || out.ReaderCalls != 0 || out.DataFrames != 0 || out.DataBytes != 0 {
					t.Fatal("old command refusal was not before reader/data", out.Stage, out.ErrorClass, out.ReaderCalls, out.DataFrames, out.DataBytes)
				}
				return
			}
			if err != nil || !bytes.Equal(first.Bytes, nativeVersionBody(0, int(artifact.DeliveryBytes))) {
				t.Fatal("mixed first native chunk", err)
			}
			clear(first.Bytes)
			if err = hub.AcknowledgeNativeChunk(ctx, delivery, 0, artifact.DeliveryBytes); err != nil {
				t.Fatal("mixed first final-sink ACK", err)
			}
			if name == "old-original-expiry" {
				timer := time.NewTimer(time.Until(operation.Until.Add(25 * time.Millisecond)))
				defer timer.Stop()
				select {
				case <-ctx.Done():
					t.Fatal("fixture expired before original operation")
				case <-timer.C:
				}
				next, err := hub.ReadChunk(ctx, delivery, artifact.DeliveryBytes, artifact.DeliveryBytes)
				clear(next.Bytes)
				if err == nil || hub.AcknowledgeNativeChunk(ctx, delivery, artifact.DeliveryBytes, artifact.DeliveryBytes) == nil {
					t.Fatal("expired old operation produced bytes or successful ACK")
				}
				out := terminal()
				if out.Accepted || out.NativeState == contracts.NativeJoined {
					t.Fatal("expired original operation reported success")
				}
				return
			}
			last, err := hub.ReadChunk(ctx, delivery, artifact.DeliveryBytes, artifact.DeliveryBytes)
			if err != nil || !bytes.Equal(last.Bytes, nativeVersionBody(int(artifact.DeliveryBytes), int(artifact.DeliveryBytes))) {
				t.Fatal("mixed last native chunk", err)
			}
			clear(last.Bytes)
			if err = hub.AcknowledgeNativeChunk(ctx, delivery, artifact.DeliveryBytes, artifact.DeliveryBytes); err != nil {
				t.Fatal("mixed final-sink ACK", err)
			}
			out := terminal()
			if !out.Accepted || out.NativeState != contracts.NativeJoined || out.ReaderCalls != 2 || out.DataFrames != 2 || out.DataBytes != int64(size) {
				t.Fatal("mixed original window failed to positively join", out.Stage, out.ErrorClass, out.ReaderCalls, out.DataFrames, out.DataBytes)
			}
		})
	}
}
func nativeVersionBody(offset, length int) []byte {
	b := make([]byte, length)
	for i := range b {
		b[i] = byte((offset + i) % 251)
	}
	return b
}
func nativeVersionCertificates(t *testing.T, id string) *keyTLSFixture {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	raw, err := x509.CreateCertificate(rand.Reader, ca, ca, public, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &keyTLSFixture{root: root, rootKey: key, roots: roots, serial: 10, scope: value.KeyScope{InstallationID: id}}
}

type nativeVersionAdmission struct {
	hub         *native.HubOperation
	certificate artifact.Digest
	reference   contracts.NativeReference
}

func (a nativeVersionAdmission) OpenNative(ctx context.Context, state *tls.ConnectionState, hello contracts.NativeHello) (native.Conversation, error) {
	if state == nil || !state.HandshakeComplete || state.NegotiatedProtocol != "h2" || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) != 1 || sha256.Sum256(state.PeerCertificates[0].Raw) != a.certificate {
		return nil, artifact.ErrDownloadUnavailable
	}
	hello.Reference = a.reference
	return a.hub.Attach(ctx, hello)
}
func nativeVersionServer(t *testing.T, ctx context.Context, hub *native.HubOperation, reference contracts.NativeReference, keys *keyTLSFixture, client tls.Certificate) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := native.NewHandler(contracts.NativeWorkerPath, listener.Addr().String(), nativeVersionAdmission{hub, sha256.Sum256(client.Certificate[0]), reference}, 1)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	serving := nativeSQLServingCertificate{keys.certificate(t, "server")}
	call, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- native.Serve(call, listener, keys.roots, serving, handler, 2) }()
	return "https://" + listener.Addr().String() + contracts.NativeWorkerPath, func() { cancel(); listener.Close(); <-done }
}
func nativeVersionSource(t *testing.T) evidence.NativeContextSource {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "11111111-1111-4111-8111-111111111111"
	e := artifact.ContextExpectation{ExecutionClass: artifact.ContextNodeExecution, NativeType: artifact.PCAPNGArtifact, Registration: artifact.Registration{Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, StoreID: id, AllocationID: id, PoolRevision: 1, AllocationRevision: 1, NativeLimit: artifact.RemoteNativeLimit, AnchorAt: now, WriteUntil: now.Add(30 * time.Second), ExpiresAt: now.Add(time.Minute), DeleteBy: now.Add(90 * time.Second)}, CaseID: id, OccurrenceID: id, NodeUID: "synthetic-node", NodeBootID: id, PodUID: id, Namespace: "app", NamespaceUID: id, WorkloadUID: id, CollectorVersion: "synthetic", CollectorImageDigest: artifact.Digest{1}, RecipeDigest: artifact.Digest{2}, PlanDigest: artifact.Digest{3}, CaptureUID: id, ActionID: "a0123456789abcdef01234567", DataClass: "metadata", PurposeRef: "synthetic", Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://id.invalid", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: id, AssignmentID: id, BasisDigest: artifact.Digest{4}}}, RequestedAgeSeconds: 60, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 30, RetentionRules: []artifact.RetentionRule{{UID: id, Generation: 1, Digest: artifact.Digest{5}}}, TriggeredAt: now.Add(-20 * time.Second), Lifecycle: &artifact.OngoingLifecycle{TriggerKind: "policy", SourceSessionID: id, SourceStartedAt: now.Add(-2 * time.Minute), SnapshotID: id, RequestedBefore: 30 * time.Second, After: 10 * time.Second, HistoryCoverage: "full", GapReasons: []string{}, WindowCoverage: "full"}}
	source := evidence.NativeContextSource{Expectation: e}
	for i := range source.Copies {
		source.Copies[i] = artifact.CopyReceipt{ETag: "synthetic", Bytes: 128, SHA256: artifact.Digest{byte(i + 1)}}
	}
	if !source.Valid(evidence.ContextCopiesDigest(source.Copies)) {
		t.Fatal("synthetic mixed native provenance invalid", e.Validate())
	}
	return source
}
