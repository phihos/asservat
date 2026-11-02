package planning

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
)

func peersEdit(protocol string, ports []int, entries ...[]string) value.ProfileEdit {
	return value.ProfileEdit{ActionID: "sample", Field: "packetPeers", Peers: &value.PeerSelection{CIDRs: entries, Protocol: protocol, Ports: ports, Resolution: "frozen", MaxEndpoints: 1, MaxStaleness: "5s"}}
}

// ADR-283: CIDR peers compile into one hub program with the authored filter.
// The compiler sees exactly the generated expression; a user `or host` stays
// inside its own parentheses and cannot widen the peer scope (SC-NET-001).
func TestCIDRPeersCompileIntoTheHubFilter(t *testing.T) {
	for name, tc := range map[string]struct {
		edits []value.ProfileEdit
		want  string
		user  string
		count int
	}{
		"ipv4 masked":   {[]value.ProfileEdit{peersEdit("any", nil, []string{"10.0.0.5/8"})}, "(net 10.0.0.0/8)", "", 1},
		"ipv6":          {[]value.ProfileEdit{peersEdit("any", nil, []string{"2001:db8::/32", "fd00::1"})}, "(net 2001:db8::/32 or net fd00::1/128)", "", 2},
		"mixed + ports": {[]value.ProfileEdit{peersEdit("udp", []int{5353, 53}, []string{"2001:db8::1"}, []string{"192.168.0.0/16", "10.1.2.3"})}, "(net 10.1.2.3/32 or net 192.168.0.0/16 or net 2001:db8::1/128) and udp and (port 53 or port 5353)", "", 3},
		"icmp":          {[]value.ProfileEdit{peersEdit("icmp", nil, []string{"10.0.0.0/24"})}, "(net 10.0.0.0/24) and (icmp or icmp6)", "", 1},
		"or host cannot widen": {[]value.ProfileEdit{peersEdit("tcp", []int{5432}, []string{"10.0.0.0/24"}), text("sample", "packetFilter", "  tcp  or host 203.0.113.9 ")},
			"((net 10.0.0.0/24) and tcp and (port 5432)) and (tcp or host 203.0.113.9)", "tcp or host 203.0.113.9", 1},
	} {
		c := &fakeCompiler{program: fixtureProgram}
		in, now := recorderInput(t, network(tc.edits...), "packetCapture")
		plan, err := CompileRecorder(in, c, now)
		if err != nil {
			t.Fatal(name, err)
		}
		if len(c.compiled) != 1 || c.compiled[0] != tc.want {
			t.Fatalf("%s: compiled %q", name, c.compiled)
		}
		a := plan.Actions[0]
		if a.Filter != tc.want || a.PeerPrefixes != tc.count || a.FilterDigest != FilterProgramDigest(fixtureProgram) {
			t.Fatalf("%s: summary %+v", name, a)
		}
		var scope recorderScope
		if err := json.Unmarshal(plan.CanonicalScope, &scope); err != nil || len(scope.Filters) != 1 {
			t.Fatal(name, err)
		}
		f := scope.Filters[0]
		if f.Expression != tc.want || f.Peers == nil || len(f.Peers.Prefixes) != tc.count || len(f.Peers.Digest) != 64 {
			t.Fatalf("%s: filter record %+v", name, f)
		}
		wantAuthored := ""
		if tc.user != "" {
			wantAuthored = hexDigest(artifact.Digest(sha256.Sum256([]byte(tc.user))))
		}
		if f.Peers.AuthoredFilterDigest != wantAuthored {
			t.Fatalf("%s: authored filter digest %q", name, f.Peers.AuthoredFilterDigest)
		}
		// The recipe keeps the authored filter, not the generated expression.
		var recipe recipeSpec
		var params packetParameters
		if json.Unmarshal(scope.Recipe, &recipe) != nil || json.Unmarshal(recipe.Actions[0].Parameters, &params) != nil || params.Filter != tc.user {
			t.Fatalf("%s: recipe filter %q", name, params.Filter)
		}
		summary, _, err := RecorderScopeSummary(plan.CanonicalScope)
		if err != nil || summary[0].Filter != tc.want || summary[0].PeerPrefixes != tc.count {
			t.Fatalf("%s: scope summary %+v %v", name, summary, err)
		}
		if !VerifyRecorderPlan(plan, &fakeCompiler{program: fixtureProgram}, now) {
			t.Fatal(name, "plan does not recompile")
		}
	}
}

// The peer-set digest is order independent; follow resolves like frozen
// for CIDRs; a different set changes the plan digest.
func TestCIDRPeerSetDigest(t *testing.T) {
	compile := func(e value.ProfileEdit) (value.RecorderPlan, recorderScope) {
		in, now := recorderInput(t, network(e), "packetCapture")
		plan, err := CompileRecorder(in, &fakeCompiler{program: fixtureProgram}, now)
		if err != nil {
			t.Fatal(err)
		}
		var scope recorderScope
		_ = json.Unmarshal(plan.CanonicalScope, &scope)
		return plan, scope
	}
	a, sa := compile(peersEdit("tcp", []int{443, 80}, []string{"10.0.0.0/8", "2001:db8::/32"}))
	b, sb := compile(peersEdit("tcp", []int{80, 443}, []string{"2001:db8::/32"}, []string{"10.0.0.0/8"}))
	if sa.Filters[0].Peers.Digest != sb.Filters[0].Peers.Digest || sa.Filters[0].Expression != sb.Filters[0].Expression {
		t.Fatal("peer-set digest depends on authored order")
	}
	if a.ScopeDigest == b.ScopeDigest {
		t.Fatal("authored provenance must stay in the plan digest")
	}
	follow := peersEdit("tcp", []int{80, 443}, []string{"10.0.0.0/8", "2001:db8::/32"})
	follow.Peers.Resolution = "follow"
	_, sf := compile(follow)
	if sf.Filters[0].Expression != sa.Filters[0].Expression || sf.Filters[0].Peers.Digest != sa.Filters[0].Peers.Digest {
		t.Fatal("follow resolves CIDRs differently from frozen")
	}
	_, sc := compile(peersEdit("tcp", []int{80, 443}, []string{"10.0.0.0/16", "2001:db8::/32"}))
	if sc.Filters[0].Peers.Digest == sa.Filters[0].Peers.Digest {
		t.Fatal("a different peer set kept its digest")
	}
}

func TestCIDRPeerRefusals(t *testing.T) {
	path := "profile_composition.components[0] action sample.parameters"
	many := make([]string, 60)
	for i := range many {
		many[i] = fmt.Sprintf("10.0.%d.0/24", i)
	}
	for name, tc := range map[string]struct {
		edits      []value.ProfileEdit
		compiler   *fakeCompiler
		code, path string
		reason     string
	}{
		"empty set":             {[]value.ProfileEdit{peersEdit("any", nil)}, nil, value.CompositionInvalid, path + ".peers.entries", "matches no traffic"},
		"name":                  {[]value.ProfileEdit{peersEdit("any", nil, []string{"db.payments.svc"})}, nil, value.CompositionInvalid, path + ".peers.entries[0].cidrs", "never resolved"},
		"zone":                  {[]value.ProfileEdit{peersEdit("any", nil, []string{"fe80::1%eth0"})}, nil, value.CompositionInvalid, path + ".peers.entries[0].cidrs", "not an IP"},
		"duplicate":             {[]value.ProfileEdit{peersEdit("any", nil, []string{"10.0.0.0/8"}, []string{"10.9.0.0/8"})}, nil, value.CompositionInvalid, path + ".peers.entries[1].cidrs", "selected twice"},
		"icmp ports":            {[]value.ProfileEdit{peersEdit("icmp", []int{80}, []string{"10.0.0.0/8"})}, nil, value.CompositionInvalid, path + ".peers.ports", "ICMP has no ports"},
		"protocol":              {[]value.ProfileEdit{peersEdit("sctp", nil, []string{"10.0.0.0/8"})}, nil, value.CompositionInvalid, path + ".peers.protocol", ""},
		"resolution":            {[]value.ProfileEdit{{ActionID: "sample", Field: "packetPeers", Peers: &value.PeerSelection{CIDRs: [][]string{{"10.0.0.0/8"}}, Protocol: "any", Resolution: "live", MaxEndpoints: 1, MaxStaleness: "5s"}}}, nil, value.CompositionInvalid, path + ".peers.resolution", ""},
		"no compiler":           {[]value.ProfileEdit{peersEdit("any", nil, []string{"10.0.0.0/8"})}, nil, value.CompositionNoCompiler, path + ".peers", ""},
		"too many tokens":       {[]value.ProfileEdit{peersEdit("any", nil, many)}, &fakeCompiler{program: fixtureProgram}, value.CompositionFilterRejected, path + ".peers", "fewer or broader peer prefixes"},
		"too many instructions": {[]value.ProfileEdit{peersEdit("any", nil, []string{"10.0.0.0/8"})}, &fakeCompiler{program: make([]value.BPFInstruction, value.MaxFilterInstructions+1)}, value.CompositionFilterRejected, path + ".peers", "fewer or broader peer prefixes"},
		"break out": {[]value.ProfileEdit{peersEdit("any", nil, []string{"10.0.0.0/8"}), text("sample", "packetFilter", "tcp) or (host 203.0.113.9")},
			&fakeCompiler{program: fixtureProgram}, value.CompositionFilterRejected, path + ".filter", "balance"},
		"user term":       {[]value.ProfileEdit{peersEdit("any", nil, []string{"10.0.0.0/8"}), text("sample", "packetFilter", "host db")}, &fakeCompiler{program: fixtureProgram}, value.CompositionFilterRejected, path + ".filter", "names are never resolved"},
		"kubernetes edit": {[]value.ProfileEdit{{ActionID: "sample", Field: "packetPeers", Unmodeled: true}}, nil, value.CompositionInvalid, "profile_composition.components[0].overrides[0]", "use cidrs"},
	} {
		var compiler FilterCompiler
		if tc.compiler != nil {
			compiler = tc.compiler
		}
		err := ValidateComposition(network(tc.edits...), compiler)
		refusal(t, err, tc.code, tc.path)
		if !strings.Contains(err.Error(), tc.reason) {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "break out" && len(tc.compiler.compiled) != 0 {
			t.Fatal("an unbalanced filter reached libpcap")
		}
	}
	// Kubernetes entries of a profile definition are refused with the remedy,
	// never ignored or widened.
	for _, raw := range []string{
		`{"entries":[{"resourceRef":{"kind":"Deployment","namespace":"a","name":"db"}}],"protocol":"any","resolution":"frozen","maxEndpoints":1,"maxStaleness":"5s"}`,
		`{"entries":[{"cidrs":["10.0.0.0/8"]},{"podSelector":{"namespace":"a","matchLabels":{"app":"db"}}}],"protocol":"any","resolution":"follow","maxEndpoints":1,"maxStaleness":"5s"}`,
	} {
		_, err := packetPeers("p", json.RawMessage(raw), nil)
		var e value.CompositionError
		if !errors.As(err, &e) || e.Code != value.CompositionRecorderUnavailable || !strings.Contains(e.Reason, "use cidrs") {
			t.Fatalf("kubernetes peers: %v", err)
		}
	}
}

// Whole-pod peers add no filter and no provenance: existing plans keep their
// scope bytes and digests.
func TestWholePodPeersAddNothing(t *testing.T) {
	for _, c := range []value.ProfileComposition{network(), network(text("sample", "packetFilter", "tcp port 8080"))} {
		compiler := &fakeCompiler{program: fixtureProgram}
		in, now := recorderInput(t, c, "packetCapture")
		plan, err := CompileRecorder(in, compiler, now)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(plan.CanonicalScope, []byte("peerSetDigest")) || plan.Actions[0].PeerPrefixes != 0 {
			t.Fatalf("whole-pod plan gained peer provenance: %s", plan.CanonicalScope)
		}
		if len(compiler.compiled) > 0 && compiler.compiled[0] != "tcp port 8080" {
			t.Fatalf("whole-pod filter changed: %q", compiler.compiled)
		}
	}
}

// The combined expression is the frozen-compilation key: acceptance, the
// node recording and its context recompile the reviewed program without a
// compiler.
func TestCIDRPeersReplayAtAcceptance(t *testing.T) {
	in, now := recorderInput(t, network(peersEdit("tcp", []int{5432}, []string{"10.0.0.0/24", "2001:db8::/64"}), text("sample", "packetFilter", "tcp or host 203.0.113.9"), text("sample", "packetAfter", "15s"), text("sample", "actionTimeout", "20s")), "packetCapture")
	in.NodeRecorder = true
	in.Target.ExecutionClass, in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = artifact.ContextAPIExecution, "", "", ""
	plan, err := CompileRecorder(in, &fakeCompiler{program: fixtureProgram}, now)
	if err != nil {
		t.Fatal(err)
	}
	filters, err := RecorderFiltersOf(plan)
	if err != nil || len(filters) != 1 {
		t.Fatal(err)
	}
	replay, err := CompileRecorder(in, frozenFilters(filters), now)
	if err != nil || replay.ScopeDigest != plan.ScopeDigest || !bytes.Equal(replay.CanonicalScope, plan.CanonicalScope) {
		t.Fatal("frozen replay differs", err)
	}
	rec, _, err := RecordingFor(plan)
	want := "((net 10.0.0.0/24 or net 2001:db8::/64) and tcp and (port 5432)) and (tcp or host 203.0.113.9)"
	if err != nil || rec.Filter == nil || rec.Filter.Expression != want {
		t.Fatalf("recording %+v %v", rec.Filter, err)
	}
	recorder, err := RecorderContextFor(&rec)
	if err != nil {
		t.Fatal(err)
	}
	ctxIn, _ := contextInput(t)
	ctxIn.Retention, ctxIn.Recorder, ctxIn.CaseID, ctxIn.Target = in.Retention, recorder, "", in.Target
	ctxIn.Capability.ExecutionClass = artifact.ContextAPIExecution
	cp, err := CompileContext(ctxIn, now)
	if err != nil || cp.ScopeDigest != plan.ScopeDigest || !bytes.Equal(cp.CanonicalScope, plan.CanonicalScope) {
		t.Fatal("the context plan of the acceptance differs from the reviewed plan", err)
	}
}

// Policy recorders share the manual compilation, peers included.
func TestPolicyRecorderAppliesCIDRPeers(t *testing.T) {
	c := network(peersEdit("tcp", nil, []string{"10.0.0.0/24"}), text("sample", "actionExecutionMode", "onTrigger"), text("sample", "packetBefore", "0s"), text("sample", "packetAfter", "2s"), text("sample", "actionTimeout", "10s"))
	compiler := &fakeCompiler{program: fixtureProgram}
	p, err := CompilePolicyRecorder(c, compiler)
	if err != nil {
		t.Fatal(err)
	}
	if p.Filter == nil || p.Action.Filter != "(net 10.0.0.0/24) and tcp" || p.Action.PeerPrefixes != 1 || !bytes.Contains(p.Scope, []byte("peerSetDigest")) {
		t.Fatalf("policy peers: %+v", p.Action)
	}
}

// Raw packets need a pinned program; CIDR peers provide one without a
// separate packetFilter.
func TestRawPacketsNarrowedByCIDRPeers(t *testing.T) {
	c := network(peersEdit("tcp", []int{8080}, []string{"10.0.0.0/24"}), text("sample", "actionExecutionMode", "onTrigger"), text("sample", "packetBefore", "0s"), text("sample", "packetAfter", "10s"))
	c.Resolved = []value.CatalogProfile{rawCatalogProfile(t, `{"kind":"rawPackets","snaplen":96}`)}
	c.Components[0].Profile = value.ProfileRef{Catalog: "namespace", Name: "raw-capture", Version: "v1"}
	in, now := recorderInput(t, c, "packetCapture")
	p, err := CompileRecorder(in, &fakeCompiler{program: fixtureProgram}, now)
	if err != nil || p.Approval == nil || p.Actions[0].Filter != "(net 10.0.0.0/24) and tcp and (port 8080)" {
		t.Fatal(err)
	}
}
