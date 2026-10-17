package bootstrap

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

type observationSetupReader struct {
	base     *runtimeFixture
	deadline time.Time
	called   bool
}

func (s *observationSetupReader) ReadOwnerConfiguration(ctx context.Context) (value.OwnerConfigurationObservation, error) {
	s.called = true
	s.deadline, _ = ctx.Deadline()
	<-ctx.Done()
	// A dependency returning a newly current observation after cancellation
	// cannot revive the original installation proof interval.
	return s.base.ReadOwnerConfiguration(context.Background())
}

func observationRuntimeConfig(t *testing.T) (*runtimeFixture, OwnerObservationRuntimeConfig) {
	t.Helper()
	f, _, _ := newRuntimeFixture(t)
	f.configuration.Pool.Port = 9443
	f.configuration.Pool.NativePort = 9444
	f.configuration.Pool.NativeBootstrap = value.OwnerBootstrapProfile
	p := value.OwnerObservationPin{RootID: runtimeID, SourceUID: runtimeID, Pool: f.configuration.Pool, TemplateDigest: artifact.Digest{1}, ImageDigest: artifact.Digest{2}, ProtectionDigest: f.configuration.ProtectionDigest}
	w := &installedObservationFixture{base: f, pin: p, bound: time.Now().Add(5 * time.Second)}
	return f, OwnerObservationRuntimeConfig{Pin: p, PodUID: runtimeID, Configuration: f, ServerEnrollment: f, ClientEnrollment: f, Registry: f, Proofs: f, Routes: f, Protection: f, Workloads: w, Peers: []mtls.OwnerObservationPeer{{Binding: value.PeerBinding{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, PeerID: runtimeID, Role: value.ConnectorPeer}, Roots: f.configuration.IssuerRoots}}, Connections: 2, Concurrency: 1}
}

func TestOwnerObservationRuntimeSetupRetainsOriginalProofDeadline(t *testing.T) {
	f, config := observationRuntimeConfig(t)
	s := &observationSetupReader{base: f}
	config.Configuration = s
	until := time.Now().Add(40 * time.Millisecond)
	setup, cancel := context.WithDeadline(context.Background(), until)
	defer cancel()
	got, e := newOwnerObservationRuntime(context.Background(), setup, config)
	if got != nil {
		got.Close()
	}
	if e == nil || !s.called || !s.deadline.Equal(until) || f.signings.Load() != 0 || f.routes.Load() != 0 {
		t.Fatal("expired original setup proof entered runtime or was extended", e)
	}
}

func TestOwnerObservationRuntimeNeedsNoWorkerOrRequestRouter(t *testing.T) {
	f, config := observationRuntimeConfig(t)
	r, e := NewOwnerObservationRuntime(context.Background(), config)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if !r.Binding().Valid() || r.Binding().PodUID != runtimeID || r.Ready() || f.signings.Load() != 0 || f.routes.Load() != 0 {
		t.Fatal("constructor inferred readiness or performed enrollment/route effects")
	}
	r.Close()
	if _, _, e := r.server.ReadinessRequest(); e == nil {
		t.Fatal("closed observation runtime retained server key")
	}
}
