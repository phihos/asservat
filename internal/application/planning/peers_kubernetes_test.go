package planning

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

func kubernetesPeersEdit(ns string, entries ...targets.PeerEntry) value.ProfileEdit {
	for i := range entries {
		if entries[i].Pods != nil {
			entries[i].Pods.Namespace = ns
		} else {
			entries[i].Resource.Namespace = ns
		}
	}
	return value.ProfileEdit{ActionID: "sample", Field: "packetPeers", Peers: &value.PeerSelection{CIDRs: [][]string{}, Kubernetes: entries, Protocol: "tcp", Ports: []int{5432}, Resolution: "frozen", MaxEndpoints: 16, MaxStaleness: "5s"}}
}

func deploymentPeer(name string) targets.PeerEntry {
	return targets.PeerEntry{Resource: &targets.PeerResourceRef{Kind: "Deployment", Name: name}}
}

// resolvedPeers answers the plan's needed request with members, as the
// preview service does after the region's reply.
func resolvedPeers(t *testing.T, in value.RecorderInput, now time.Time, members ...targets.PeerMember) (value.RecorderInput, PeerResolutionNeeded) {
	t.Helper()
	_, err := CompileRecorder(in, &fakeCompiler{program: fixtureProgram}, now)
	var needed PeerResolutionNeeded
	if !errors.As(err, &needed) {
		t.Fatalf("Kubernetes peers compiled without a resolution: %v", err)
	}
	in.Peers = append(in.Peers, targets.PeerResolution{Request: needed.Request, Members: members, ResolvedAt: now.Add(-time.Second)})
	return in, needed
}

// ADR-283 PR 2: resolved Kubernetes peers add host prefixes to the same
// expression as CIDRs; the plan records the members' digest and generation
// time, and the plan cannot be recorded until the membership verifier exists.
func TestKubernetesPeersCompileResolvedHostPrefixes(t *testing.T) {
	in, now := recorderInput(t, network(), "packetCapture")
	ns := in.Target.Request.Namespace.Name
	edit := kubernetesPeersEdit(ns, deploymentPeer("db"))
	edit.Peers.CIDRs = [][]string{{"10.0.0.11", "192.168.0.0/16"}}
	in.Composition = network(edit, text("sample", "packetFilter", "tcp or host 203.0.113.9"))
	members := []targets.PeerMember{{Kind: "Pod", UID: "pod-a", IP: "10.0.0.11"}, {Kind: "Pod", UID: "pod-b", IP: "10.0.0.12"}, {Kind: "Pod", UID: "pod-a", IP: "fd00::11"}}
	in, needed := resolvedPeers(t, in, now, members...)
	if needed.Request.ClusterID != in.Target.Request.ClusterID || needed.Request.Namespace != in.Target.Request.Namespace || needed.Request.MaxEndpoints != 16 || len(needed.Request.Entries) != 1 || needed.Path != "profile_composition.components[0] action sample.parameters.peers" {
		t.Fatalf("needed %+v", needed)
	}
	c := &fakeCompiler{program: fixtureProgram}
	plan, err := CompileRecorder(in, c, now)
	if err != nil {
		t.Fatal(err)
	}
	// 10.0.0.11 is both an authored CIDR and a member: one prefix.
	want := "((net 10.0.0.11/32 or net 10.0.0.12/32 or net 192.168.0.0/16 or net fd00::11/128) and tcp and (port 5432)) and (tcp or host 203.0.113.9)"
	if len(c.compiled) != 1 || c.compiled[0] != want {
		t.Fatalf("compiled %q", c.compiled)
	}
	a := plan.Actions[0]
	if a.PeerEndpoints != 3 || a.PeerPrefixes != 4 || len(a.PeerMembersDigest) != 64 {
		t.Fatalf("summary %+v", a)
	}
	var scope recorderScope
	if err := json.Unmarshal(plan.CanonicalScope, &scope); err != nil || len(scope.Filters) != 1 {
		t.Fatal(err)
	}
	k := scope.Filters[0].Peers.Kubernetes
	if k == nil || k.Endpoints != 3 || k.MembersDigest != a.PeerMembersDigest || k.NamespaceUID != in.Target.Request.Namespace.UID || k.ResolvedAt != now.Add(-time.Second).UTC().Format(time.RFC3339Nano) {
		t.Fatalf("kubernetes record %+v", k)
	}
	summary, _, err := RecorderScopeSummary(plan.CanonicalScope)
	if err != nil || summary[0].PeerEndpoints != 3 || summary[0].PeerMembersDigest != a.PeerMembersDigest {
		t.Fatalf("scope summary %+v %v", summary, err)
	}
	if !VerifyRecorderPlan(plan, &fakeCompiler{program: fixtureProgram}, now) {
		t.Fatal("plan does not recompile from its input")
	}
	// The members digest binds UIDs and IPs.
	other, _ := recorderInput(t, in.Composition, "packetCapture")
	other.Peers = []targets.PeerResolution{in.Peers[0]}
	other.Peers[0].Members = []targets.PeerMember{{Kind: "Pod", UID: "pod-z", IP: "10.0.0.11"}, {Kind: "Pod", UID: "pod-b", IP: "10.0.0.12"}, {Kind: "Pod", UID: "pod-a", IP: "fd00::11"}}
	replaced, err := CompileRecorder(other, &fakeCompiler{program: fixtureProgram}, now)
	if err != nil || replaced.Actions[0].PeerMembersDigest == a.PeerMembersDigest || replaced.Actions[0].Filter != a.Filter {
		t.Fatal("a replaced member kept the members digest", err)
	}
	// Submission is refused with the reason; the context and recording paths
	// fail closed as well.
	in.NodeRecorder = true
	recordable, err := CompileRecorder(in, &fakeCompiler{program: fixtureProgram}, now)
	if err != nil {
		t.Fatal(err)
	}
	got := AcceptableRecorder(recordable)
	if got.Acceptable() || got.Code != "RecorderUnavailable" || got.Reason != KubernetesPeersAcceptance || !strings.HasSuffix(got.Path, ".parameters.peers") {
		t.Fatalf("acceptance %+v", got)
	}
	if _, _, err := RecordingFor(recordable); err == nil {
		t.Fatal("a Kubernetes peer plan produced a node recording")
	}
}

// The plan does not depend on the order in which the region listed objects:
// members arrive canonical, and an unordered answer is never used.
func TestKubernetesPeerDigestIgnoresListOrder(t *testing.T) {
	in, now := recorderInput(t, network(), "packetCapture")
	in.Composition = network(kubernetesPeersEdit(in.Target.Request.Namespace.Name, deploymentPeer("db")))
	snapshot := targets.PeerSnapshot{Namespace: in.Target.Request.Namespace.Name,
		Workloads:   []targets.PeerWorkload{{Kind: "Deployment", Name: "db", UID: "dep"}},
		ReplicaSets: []targets.PeerOwned{{Name: "db-1", UID: "rs", ControllerKind: "Deployment", ControllerUID: "dep"}},
		Pods: []targets.PeerPod{
			{Name: "a", UID: "pod-a", IPs: []string{"10.0.0.12"}, ControllerKind: "ReplicaSet", ControllerUID: "rs", Phase: "Running"},
			{Name: "b", UID: "pod-b", IPs: []string{"10.0.0.11", "fd00::b"}, ControllerKind: "ReplicaSet", ControllerUID: "rs", Phase: "Running"},
		}}
	var digest []byte
	for _, reverse := range []bool{false, true} {
		s := snapshot
		if reverse {
			s.Pods = []targets.PeerPod{snapshot.Pods[1], snapshot.Pods[0]}
		}
		_, err := CompileRecorder(in, &fakeCompiler{program: fixtureProgram}, now)
		var needed PeerResolutionNeeded
		if !errors.As(err, &needed) {
			t.Fatal(err)
		}
		members, err := targets.ResolvePeers(needed.Request, s)
		if err != nil {
			t.Fatal(err)
		}
		x := in
		x.Peers = []targets.PeerResolution{{Request: needed.Request, Members: members, ResolvedAt: now}}
		plan, err := CompileRecorder(x, &fakeCompiler{program: fixtureProgram}, now)
		if err != nil {
			t.Fatal(err)
		}
		if digest != nil && !bytes.Equal(digest, plan.ScopeDigest[:]) {
			t.Fatal("LIST order changed the plan")
		}
		digest = plan.ScopeDigest[:]
	}
	x := in
	_, needed := resolvedPeers(t, in, now)
	x.Peers = []targets.PeerResolution{{Request: needed.Request, Members: []targets.PeerMember{{Kind: "Pod", UID: "b", IP: "10.0.0.12"}, {Kind: "Pod", UID: "a", IP: "10.0.0.11"}}, ResolvedAt: now}}
	if _, err := CompileRecorder(x, &fakeCompiler{program: fixtureProgram}, now); !errors.As(err, new(PeerResolutionNeeded)) {
		t.Fatalf("an unordered answer was used: %v", err)
	}
}

func TestKubernetesPeerRefusals(t *testing.T) {
	in, now := recorderInput(t, network(), "packetCapture")
	ns := in.Target.Request.Namespace.Name
	path := "profile_composition.components[0] action sample.parameters.peers"
	follow := kubernetesPeersEdit(ns, deploymentPeer("db"))
	follow.Peers.Resolution = "follow"
	badLabel := kubernetesPeersEdit(ns, targets.PeerEntry{Pods: &targets.PeerPodSelector{MatchLabels: map[string]string{"app": "-db"}}})
	for name, tc := range map[string]struct {
		edit       value.ProfileEdit
		code, path string
		reason     string
	}{
		"other namespace": {kubernetesPeersEdit("kube-system", deploymentPeer("db")), value.CompositionInvalid, path + ".entries[0].resourceRef.namespace", "target's namespace"},
		"follow":          {follow, value.CompositionRecorderUnavailable, path + ".resolution", "frozen"},
		"bad label":       {badLabel, value.CompositionInvalid, path + ".entries[0]", "1 to 16 labels"},
	} {
		x := in
		x.Composition = network(tc.edit)
		_, err := CompileRecorder(x, &fakeCompiler{program: fixtureProgram}, now)
		refusal(t, err, tc.code, tc.path)
		if !strings.Contains(err.Error(), tc.reason) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Empty resolution never means all traffic.
	in.Composition = network(kubernetesPeersEdit(ns, deploymentPeer("db")))
	empty, _ := resolvedPeers(t, in, now)
	_, err := CompileRecorder(empty, &fakeCompiler{program: fixtureProgram}, now)
	refusal(t, err, value.CompositionInvalid, path+".entries")
	// A resolution from the future, or one the plan does not use, is refused.
	future, _ := resolvedPeers(t, in, now, targets.PeerMember{Kind: "Pod", UID: "a", IP: "10.0.0.1"})
	future.Peers[0].ResolvedAt = now.Add(time.Second)
	if _, err := CompileRecorder(future, &fakeCompiler{program: fixtureProgram}, now); !errors.As(err, new(PeerResolutionNeeded)) {
		t.Fatalf("future resolution used: %v", err)
	}
	unused, _ := recorderInput(t, network(peersEdit("any", nil, []string{"10.0.0.0/8"})), "packetCapture")
	unused.Peers = future.Peers
	unused.Peers[0].ResolvedAt = now
	if _, err := CompileRecorder(unused, &fakeCompiler{program: fixtureProgram}, now); !errors.Is(err, value.ErrInvalid) {
		t.Fatalf("unused resolution accepted: %v", err)
	}
	// Without target facts (policy, group split, validation) the remedy.
	err = ValidateComposition(in.Composition, &fakeCompiler{program: fixtureProgram})
	refusal(t, err, value.CompositionRecorderUnavailable, path+".entries[0]")
	// Region failures map to refusals at the peers path.
	needed := PeerResolutionNeeded{Request: targets.PeerRequest{MaxEndpoints: 4}, Path: path}
	for want, cause := range map[string]error{path + ".maxEndpoints": targets.ErrPeerLimit, path + ".entries": targets.ErrPeerUnsupported} {
		var e value.CompositionError
		if !errors.As(PeerResolutionRefusal(needed, cause), &e) || e.Path != want {
			t.Fatalf("%v: %v", cause, e)
		}
	}
	if err := PeerResolutionRefusal(needed, targets.ErrPeerMissing); !strings.Contains(err.Error(), "unavailable in the target's namespace") {
		t.Fatal(err)
	}
	if err := PeerResolutionRefusal(needed, targets.ErrUnavailable); !errors.Is(err, targets.ErrUnavailable) {
		t.Fatal(err)
	}
}

// The authored edit round-trips through the provenance: cidrs entries first,
// then Kubernetes entries; a Service carries serviceMode and readyOnly.
func TestKubernetesPeerEditWire(t *testing.T) {
	e := kubernetesPeersEdit("shop", targets.PeerEntry{Resource: &targets.PeerResourceRef{Kind: "Service", Name: "db", ServiceMode: "backends"}}, targets.PeerEntry{Pods: &targets.PeerPodSelector{MatchLabels: map[string]string{"app": "db"}}})
	e.Peers.CIDRs = [][]string{{"10.0.0.0/8"}}
	b, err := json.Marshal(peersEditWire(e.Peers))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"entries":[{"cidrs":["10.0.0.0/8"]},{"resourceRef":{"kind":"Service","namespace":"shop","name":"db","serviceMode":"backends","readyOnly":false}},{"podSelector":{"namespace":"shop","matchLabels":{"app":"db"}}}],"protocol":"tcp","ports":[5432],"resolution":"frozen","maxEndpoints":16,"maxStaleness":"5s"}`
	if string(b) != want {
		t.Fatalf("wire %s", b)
	}
}
