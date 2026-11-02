package capture

import (
	"context"
	"errors"
	"testing"

	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type fakePeers struct {
	requests []targets.PeerRequest
	err      error
}

func (p *fakePeers) ResolvePacketPeers(_ context.Context, r targets.PeerRequest) (targets.PeerResolution, error) {
	p.requests = append(p.requests, r)
	return targets.PeerResolution{Request: r, Members: []targets.PeerMember{{Kind: "Pod", UID: "db-a", IP: "10.0.0.11"}, {Kind: "Pod", UID: "db-a", IP: "fd00::11"}}}, p.err
}

func kubernetesPeerEdit() planning.ProfileEdit {
	return planning.ProfileEdit{ActionID: "sample", Field: "packetPeers", Peers: &planning.PeerSelection{CIDRs: [][]string{}, Protocol: "tcp", Resolution: "frozen", MaxEndpoints: 8, MaxStaleness: "5s",
		Kubernetes: []targets.PeerEntry{{Resource: &targets.PeerResourceRef{Kind: "StatefulSet", Namespace: "payments", Name: "db"}}}}}
}

// ADR-283 PR 2: Kubernetes peers are resolved once in the target's region
// after eligibility and shown in a plan-only preview; submission is refused
// until the membership verifier exists.
func TestKubernetesPeerPreviewIsPlanOnly(t *testing.T) {
	f := newInvestigationFixture()
	f.svc.Filters = &stubFilters{}
	peers := &fakePeers{}
	f.svc.Peers = peers
	ctx := context.Background()
	r, err := f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition(kubernetesPeerEdit())))
	if err != nil {
		t.Fatal(err)
	}
	if len(peers.requests) != 1 || peers.requests[0].Namespace != r.Plan.Input.Target.Request.Namespace || peers.requests[0].ClusterID != r.Plan.Input.Target.Request.ClusterID || peers.requests[0].MaxEndpoints != 8 {
		t.Fatalf("region asked %+v", peers.requests)
	}
	a := r.Plan.Actions[0]
	if r.Recordable || a.PeerEndpoints != 2 || a.PeerPrefixes != 2 || a.Filter != "(net 10.0.0.11/32 or net fd00::11/128) and tcp" || len(r.Plan.Input.Peers) != 1 || r.Plan.Input.Peers[0].ResolvedAt.IsZero() {
		t.Fatalf("plan %+v recordable %v", a, r.Recordable)
	}
	if _, err := f.request(t, r.Preview, "peers-1"); !errors.Is(err, value.ErrRecorderUnavailable) || f.admissions.Load() != 0 {
		t.Fatal("a Kubernetes peer plan reached admission", err)
	}
	// Region refusals become composition refusals at the peers path; an
	// installation without the resolver refuses with its own reason.
	peers.err = targets.ErrPeerUnsupported
	_, err = f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition(kubernetesPeerEdit())))
	var refusal planning.CompositionError
	if !errors.As(err, &refusal) || refusal.Code != planning.CompositionRecorderUnavailable || refusal.Path != "profile_composition.components[0] action sample.parameters.peers.entries" {
		t.Fatal(err)
	}
	f.svc.Peers = nil
	_, err = f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition(kubernetesPeerEdit())))
	if !errors.As(err, &refusal) || refusal.Code != planning.CompositionRecorderUnavailable {
		t.Fatal(err)
	}
}
