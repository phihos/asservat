package native_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	native "asservat.local/asservat/internal/transport/native"
)

type positiveIdleAdmission struct {
	idle  *evidence.NativeIdle
	calls atomic.Int64
}

func (a *positiveIdleAdmission) OpenNative(ctx context.Context, peer *tls.ConnectionState, h contracts.NativeHello) (native.Conversation, error) {
	a.calls.Add(1)
	if ctx.Err() != nil || peer == nil || peer.NegotiatedProtocol != "h2" || len(peer.VerifiedChains) == 0 || h.Reference != workerHello().Reference || !a.idle.Valid(time.Now()) {
		return nil, contracts.ErrNativeProtocol
	}
	return nil, a.idle
}

// The original worker/SQL/proof authority is synthetic; production Serve,
// Handler, NativeClient, TLS/h2 and bounded joined ownership are exercised.
func syntheticNativeIdle(t *testing.T) *evidence.NativeIdle {
	t.Helper()
	n := time.Now()
	r := identity.Revision{UID: nativeID, Generation: 1, Digest: artifact.Digest{1}}
	p := identity.Principal{Issuer: "https://synthetic.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}
	scope := artifact.DownloadScope{RootID: nativeID, ArtifactID: nativeID, CaptureID: nativeID, ClusterID: nativeID, NamespaceUID: "app", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, Principal: p}
	a := artifact.DownloadAuthority{Scope: scope, PermissionEpoch: nativeID, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: r, CheckedAt: n, ValidUntil: n.Add(5 * time.Second), AccessUntil: n.Add(time.Minute)}
	a.Environment = artifact.DownloadEnvironment{RootID: nativeID, InstallationID: nativeID, Region: "synthetic", StoreID: nativeID, RecoveryEpoch: nativeID, Location: artifact.Location{ClusterID: nativeID, ArtifactID: nativeID, AttemptID: nativeID}, Principal: p, Revision: r, RecoveryRevision: r, ObservedAt: n, ValidUntil: a.ValidUntil}
	profile := value.DownloadWorkerProfile{Configuration: r, InstallationID: nativeID, ClusterID: nativeID, Namespace: "workers", NamespaceUID: "workers-uid", ServiceAccount: "reader", ServiceAccountUID: "reader-uid", Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", ControlConfigUID: "control-uid", PriorityClass: "workers", PriorityClassUID: "priority-uid", ControlDigest: artifact.Digest{1}, CPUMillis: 100, MemoryBytes: 64 << 20, MaxRuntime: time.Minute}
	i := value.DownloadWorkerIntent{ID: nativeID, SessionID: nativeID, Generation: 1, Profile: profile, Authority: a, CreatedAt: n, RunUntil: a.AccessUntil}
	j := value.DownloadWorkerJob{IntentID: nativeID, UID: "job-uid", Spec: artifact.Digest{1}}
	b := value.KeyWorkerBinding{InstallationID: nativeID, DownloadID: nativeID, ClusterID: nativeID, Namespace: profile.Namespace, NamespaceUID: profile.NamespaceUID, ServiceAccount: profile.ServiceAccount, ServiceAccountUID: profile.ServiceAccountUID, Job: i.JobName(), JobUID: j.UID, JobSpec: j.Spec, Pod: "worker", PodUID: nativeID, PodSpec: artifact.Digest{2}}
	idle := &evidence.NativeIdle{Worker: value.DownloadWorkerIdentity{Worker: value.DownloadWorker{Intent: i, Job: j, Binding: b}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, Proof: value.KeyWorkerProof{Binding: b, Peer: value.KeyPeer{InstallationID: nativeID, PeerID: nativeID, Role: "acquisition", Certificate: artifact.Digest{3}, NotBefore: n.Add(-time.Second), NotAfter: n.Add(time.Minute)}, TokenDigest: artifact.Digest{4}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, ObservedAt: n, Until: n.Add(5 * time.Second)}
	if !idle.Valid(n) {
		t.Fatal("synthetic positive idle fixture invalid")
	}
	return idle
}

func TestNativeServeDeliversPositiveIdleBeforeClosingSocket(t *testing.T) {
	cert, clientCert, roots := testCertificates(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	a := &positiveIdleAdmission{idle: syntheticNativeIdle(t)}
	handler, err := native.NewHandler(contracts.NativeWorkerPath, listener.Addr().String(), a, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	done := make(chan error, 1)
	go func() { done <- native.Serve(ctx, listener, roots, syntheticServingCertificate{cert}, handler, 1) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Error("joined server", err)
			}
		case <-time.After(time.Second):
			t.Error("server failed to join")
		}
	})
	client, err := mtls.NewNativeClient("https://"+listener.Addr().String()+contracts.NativeWorkerPath, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}})
	if err != nil {
		t.Fatal(err)
	}
	// Each positive response must release its socket reservation; the next call
	// is an independently opened socket, never a replay by the HTTP transport.
	for attempt := int64(1); attempt <= 3; attempt++ {
		stream, err := client.Open(ctx, workerHello())
		if stream != nil {
			stream.Close()
			t.Fatal("idle created a stream")
		}
		var idle *contracts.NativeNoCommand
		if !errors.As(err, &idle) {
			t.Fatalf("attempt %d: positive idle lost across actual listener: %v (admission calls %d)", attempt, err, a.calls.Load())
		}
		if idle.Reference != workerHello().Reference || idle.Nonce != workerHello().Nonce || !idle.Until.Equal(a.idle.Until) || a.calls.Load() != attempt {
			t.Fatal("idle identity/interval changed or request repeated")
		}
	}
}
