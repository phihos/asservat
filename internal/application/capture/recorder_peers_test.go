package capture

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"

	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type fakePeers struct {
	requests []targets.PeerRequest
	err      error
	members  []targets.PeerMember
}

func (p *fakePeers) ResolvePacketPeers(_ context.Context, r targets.PeerRequest) (targets.PeerResolution, error) {
	p.requests = append(p.requests, r)
	members := p.members
	if members == nil {
		members = []targets.PeerMember{{Kind: "Pod", UID: "db-a", IP: "10.0.0.11"}, {Kind: "Pod", UID: "db-a", IP: "fd00::11"}}
	}
	return targets.PeerResolution{Request: r, Members: members}, p.err
}

func kubernetesPeerEdit() planning.ProfileEdit {
	return planning.ProfileEdit{ActionID: "sample", Field: "packetPeers", Peers: &planning.PeerSelection{CIDRs: [][]string{}, Protocol: "tcp", Resolution: "frozen", MaxEndpoints: 8, MaxStaleness: "5s",
		Kubernetes: []targets.PeerEntry{{Resource: &targets.PeerResourceRef{Kind: "StatefulSet", Namespace: "payments", Name: "db"}}}}}
}

// ADR-283 PR 2: Kubernetes peers are resolved once in the target's region
// after eligibility. Without a node recorder the preview is plan-only and
// submission is refused like any other plan-only composition.
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

// A packet + syscall composition with Kubernetes peers leaves the group path
// like a single recording does and gets the explicit composition refusal:
// Kubernetes peers resolve only for one packet capture (use cidrs here).
func TestKubernetesPeerGroupPreviewFallsBackToPlanOnly(t *testing.T) {
	f := newInvestigationFixture()
	f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
	f.target.ExecutionClass, f.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	f.svc.Filters = &stubFilters{}
	f.svc.Recorders = bothRecorders{availableRecording{f}}
	peers := &fakePeers{}
	f.svc.Peers = peers
	c := mixedComposition()
	c.Components[0].Edits = append(c.Components[0].Edits, kubernetesPeerEdit())
	ctx := context.Background()
	_, err := f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(c))
	var refusal planning.CompositionError
	if !errors.As(err, &refusal) || refusal.Code != planning.CompositionRecorderUnavailable || !strings.Contains(refusal.Reason, "one packet capture") {
		t.Fatal("mixed composition with Kubernetes peers", err, refusal.Reason)
	}
}

// ADR-283 part 3: with a node recorder a frozen Kubernetes peer plan is
// recordable. Submission resolves the frozen query again and is admitted
// only for exactly the reviewed members; a changed set or a full verifier is
// refused before admission reserves anything.
func TestKubernetesPeerRecordingSubmissionRechecksMembers(t *testing.T) {
	f := newInvestigationFixture()
	f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
	f.target.ExecutionClass, f.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	f.svc.Recorders, f.svc.Filters = availableRecording{f}, &stubFilters{}
	peers := &fakePeers{}
	f.svc.Peers = peers
	ctx := context.Background()
	preview := func() RecorderPreviewResult {
		t.Helper()
		r, err := f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition(kubernetesPeerEdit())))
		if err != nil || !r.Recordable || r.Plan.Actions[0].PeerEndpoints != 2 {
			t.Fatalf("preview %+v %v", r.Plan.Actions, err)
		}
		return r
	}
	var refusal planning.CompositionError
	for i, tc := range []struct {
		members []targets.PeerMember
		err     error
		code    string
	}{
		{members: []targets.PeerMember{{Kind: "Pod", UID: "db-b", IP: "10.0.0.11"}, {Kind: "Pod", UID: "db-a", IP: "fd00::11"}}, code: planning.CompositionPeersChanged},
		{members: []targets.PeerMember{{Kind: "Pod", UID: "db-a", IP: "10.0.0.11"}}, code: planning.CompositionPeersChanged},
		{err: targets.ErrPeerMissing, code: planning.CompositionPeersChanged},
		{err: targets.ErrPeerVerifierBusy, code: planning.CompositionRecorderUnavailable},
	} {
		r := preview()
		peers.members, peers.err = tc.members, tc.err
		_, err := f.request(t, r.Preview, fmt.Sprintf("peers-changed-%d", i))
		if !errors.As(err, &refusal) || refusal.Code != tc.code || refusal.Path != "profile_composition.components[0] action sample.parameters.peers" || f.admissions.Load() != 0 {
			t.Fatalf("%d: %v admissions %d", i, err, f.admissions.Load())
		}
		peers.members, peers.err = nil, nil
	}
	r := preview()
	asked := len(peers.requests)
	// This fixture's admission does not model recordings past admission;
	// reaching it with exactly one recheck of the frozen query is the point.
	_, err := f.request(t, r.Preview, "peers-same")
	if errors.As(err, &refusal) || f.admissions.Load() != 1 || len(peers.requests) != asked+1 || !peers.requests[asked].Equal(r.Plan.Input.Peers[0].Request) {
		t.Fatalf("unchanged peers not admitted: %v", err)
	}
}

type fakeProfileEndpoints struct{ calls int }

func (p *fakeProfileEndpoints) ResolveProfileEndpoint(_ context.Context, r targets.ProfileEndpointRequest) (targets.ProfileEndpointResolution, error) {
	p.calls++
	return targets.ProfileEndpointResolution{Request: r, SourceKind: targets.ProfileEndpointTemplateBinding, SourceName: "go-pprof-loopback", AddressMode: "targetLoopback", Port: 6060, DeclaredPortName: "diagnostics", PathPolicy: "go-pprof/v1", DefinitionDigest: artifact.Digest{1}, EndpointDigest: artifact.Digest{2}}, nil
}

func TestProfileEndpointPreviewRemainsPlanOnly(t *testing.T) {
	f := newInvestigationFixture()
	endpoints := &fakeProfileEndpoints{}
	f.svc.ProfileEndpoints = endpoints
	c := planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "cpu", Profile: planning.ProfileRef{Catalog: "builtin", Name: "go-cpu", Version: "v1"}}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s"}
	ctx := context.Background()
	r, err := f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(&c))
	if err != nil {
		t.Fatal(err)
	}
	if endpoints.calls != 1 || r.Recordable || r.Plan.Approval == nil || len(r.Plan.Input.Endpoints) != 1 {
		t.Fatalf("profile preview %+v calls=%d", r, endpoints.calls)
	}
	if _, err = f.request(t, r.Preview, "profile-1"); !errors.Is(err, value.ErrRecorderUnavailable) || f.admissions.Load() != 0 {
		t.Fatal("profile reached admission", err)
	}
	f.identityChange = "scopes"
	_, err = f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(&c))
	if err == nil || endpoints.calls != 1 {
		t.Fatal("ineligible caller resolved endpoint", err)
	}
}
