package integration

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/client-go/rest"
)

type nativeProofAPISnapshot struct{ Reviews, Gets, Other int64 }

func (s nativeProofAPISnapshot) subtract(p nativeProofAPISnapshot) nativeProofAPISnapshot {
	return nativeProofAPISnapshot{s.Reviews - p.Reviews, s.Gets - p.Gets, s.Other - p.Other}
}

type nativeProofAPICounts struct{ reviews, gets, other atomic.Int64 }
type nativeProofTransport struct {
	next http.RoundTripper
	c    *nativeProofAPICounts
}

func (c *nativeProofAPICounts) wrap(next http.RoundTripper) http.RoundTripper {
	return nativeProofTransport{next, c}
}
func (c *nativeProofAPICounts) snapshot() nativeProofAPISnapshot {
	return nativeProofAPISnapshot{c.reviews.Load(), c.gets.Load(), c.other.Load()}
}
func (t nativeProofTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews":
		t.c.reviews.Add(1)
	case r.Method == http.MethodGet:
		t.c.gets.Add(1)
	default:
		t.c.other.Add(1)
	}
	return t.next.RoundTrip(r)
}

// Only Kubernetes identity and TLS are real here. Operation/SQL authority below
// is explicitly synthetic; the independent SQL/S3 native fixture covers it.
type realProofNativeLeases struct {
	operation value.NativeOperation
	peer      value.KeyPeer
	reads     atomic.Int64
}

func (l *realProofNativeLeases) lease() value.NativeLease {
	now := time.Now()
	return value.NativeLease{Operation: l.operation, Certificate: l.peer.Certificate, Sequence: 1, ObservedAt: now, Until: minPublicationTime(now.Add(5*time.Second), l.operation.Until)}
}
func (l *realProofNativeLeases) LocateNativeOperation(context.Context, string, string, string, value.KeyPeer) (value.NativeLease, error) {
	return l.lease(), nil
}
func (l *realProofNativeLeases) ObserveNativeOperation(context.Context, value.NativeReference, value.KeyPeer) (value.NativeLease, error) {
	l.reads.Add(1)
	return l.lease(), nil
}

type nativeLegacyProofOnly struct{ source *kube.DownloadPeerAttester }

func (r nativeLegacyProofOnly) ReadDownloadPeerProof(c context.Context, session string, peer value.KeyPeer) (value.KeyWorkerProof, error) {
	return r.source.ReadDownloadPeerProof(c, session, peer)
}

func qualifyNativeResponseRealProof(t *testing.T, ctx context.Context, config *rest.Config, client *kube.PermissionClient, source *kube.DownloadPeerAttester, tokens *actualDownloadToken, b value.KeyWorkerBinding, peer value.KeyPeer, tokenExpiry time.Time, counts *nativeProofAPICounts) {
	t.Helper()
	now, id := time.Now(), b.InstallationID
	operation := value.NativeOperation{Reference: value.NativeReference{InstallationID: id, SessionID: b.DownloadID, WorkerID: custodyID(), OperationID: custodyID(), Fence: 1}, Kind: value.NativeResponse, HubPodUID: custodyID(), HubProcessEpoch: custodyID(), WorkerPodUID: b.PodUID, WorkerPublicKey: artifact.Digest{1}, SourceVersion: artifact.Digest{2}, ParentID: custodyID(), Generation: 1, StartedAt: now, Until: now.Add(20 * time.Second)}
	operation.Path = artifact.DownloadPath{ID: custodyID(), TargetClusterID: b.ClusterID, StoreID: custodyID(), StorageRegion: "fixture", AcquisitionClusterID: b.ClusterID, AcquisitionRegion: "fixture", ConnectorClusterID: b.ClusterID, ConnectorRegion: "fixture", HubClusterID: b.ClusterID, HubRegion: "fixture", WorkerConfiguration: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{1}}, HubConfiguration: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{2}}}
	operation.Processing = artifact.DownloadProcessingProof{RootID: custodyID(), Epoch: custodyID(), CaptureID: custodyID(), Location: artifact.Location{ClusterID: b.ClusterID, ArtifactID: custodyID(), AttemptID: custodyID()}, Sequence: 1, StateDigest: artifact.Digest{3}, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	leases := &realProofNativeLeases{operation: operation, peer: peer}
	origins := evidence.NativeOrigins{Locators: leases, Operations: leases, Now: time.Now, Proofs: func(token evidence.DownloadPeerToken) (evidence.DownloadPeerProofReader, error) {
		return kube.NewDownloadPeerAttester(client, b, token)
	}}
	actualToken, err := tokens.ReadDownloadPeerToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(actualToken)
	before := counts.snapshot()
	if _, err := origins.Check(ctx, id, b.DownloadID, operation.Reference.WorkerID, peer, []byte("invalid.worker.token")); err == nil {
		t.Fatal("proof factory ignored the actual supplied token")
	}
	if invalidCost := counts.snapshot().subtract(before); invalidCost != (nativeProofAPISnapshot{Reviews: 1}) {
		t.Fatal("invalid supplied token did not fail at real TokenReview", invalidCost)
	}
	before = counts.snapshot()
	origin, err := origins.Check(ctx, id, b.DownloadID, operation.Reference.WorkerID, peer, actualToken)
	if err != nil {
		t.Fatal("real initial response proof", err)
	}
	initial := counts.snapshot().subtract(before)
	if initial != (nativeProofAPISnapshot{Reviews: 2, Gets: 8}) {
		t.Fatal("response admission repeated or skipped initial identity reads", initial)
	}
	wait := time.NewTimer(time.Until(origin.Proof.FreshUntil.Add(25 * time.Millisecond)))
	defer wait.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-wait.C:
	}
	if origin.Proof.Valid(time.Now()) {
		t.Fatal("original short proof unexpectedly current")
	}
	before = counts.snapshot()
	for range 12 {
		if lease, err := origins.Recheck(ctx, origin); err != nil || !lease.Valid(time.Now()) || lease.Until.After(tokenExpiry) {
			t.Fatal("response did not retain real initial identity under fresh synthetic SQL authority", err)
		}
	}
	repeated := counts.snapshot().subtract(before)
	if repeated != (nativeProofAPISnapshot{}) || leases.reads.Load() != 12 {
		t.Fatal("response checks added Kubernetes calls or skipped current operation observation", repeated, leases.reads.Load())
	}

	origins.Proofs = func(evidence.DownloadPeerToken) (evidence.DownloadPeerProofReader, error) {
		return nativeLegacyProofOnly{source}, nil
	}
	if _, err := origins.Check(ctx, id, b.DownloadID, operation.Reference.WorkerID, peer, actualToken); err == nil {
		t.Fatal("ordinary proof without reviewed response expiry authorized response")
	}

	// Kubernetes issues this real bound token for at least ten minutes. Advance
	// only the trusted attester clock to its actual TokenRequest expiration;
	// TokenReview still authenticates at wall time, then the reviewed-expiry
	// parser must refuse before any live-object read. This does not claim a
	// wall-clock-expired TokenReview response or wait ten minutes.
	if !peer.Valid(tokenExpiry) {
		t.Fatal("fixture certificate must outlive real token expiration")
	}
	expiredClient, err := kube.NewPermissionClient(config, b.ClusterID, cfg.NamespaceRef{Name: b.Namespace, UID: b.NamespaceUID}, func() time.Time { return tokenExpiry })
	if err != nil {
		t.Fatal(err)
	}
	expired, err := kube.NewDownloadPeerAttester(expiredClient, b, tokens)
	if err != nil {
		t.Fatal(err)
	}
	before = counts.snapshot()
	if _, err := expired.ReadNativeResponsePeerProof(ctx, b.DownloadID, peer); err == nil {
		t.Fatal("real reviewed token expiration ignored by trusted clock")
	}
	expiredCost := counts.snapshot().subtract(before)
	if expiredCost != (nativeProofAPISnapshot{Reviews: 1}) {
		t.Fatal("expiration refusal did not follow real TokenReview before live reads", expiredCost)
	}
	t.Logf("real initial response attestation: %+v; 12 current SQL-observation checks after original five-second proof: %+v Kubernetes requests; reviewed-expiry clock refusal: %+v", initial, repeated, expiredCost)
}
