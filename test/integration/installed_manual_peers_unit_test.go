package integration

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
)

// ADR-283 manual-peers focus: the public request is valid, converts through
// the preview's wire conversion and compiles through the actual planner
// (synthetic facts and region answer, test filter compiler; no capture)
// into a filter limited to the resolved peer's host prefix.
func TestInstalledManualPeersRequestCompiles(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-peers")
	const cluster = "00000000-0000-4000-8000-000000000001"
	input := approvedRecordingArguments(cluster, "payments", "api")
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.ValidateInput("preview_capture", raw); err != nil {
		t.Fatal("manual peers request is not a public capture input", err)
	}
	compositionJSON, _ := json.Marshal(input["profile_composition"])
	var public contracts.CaptureComposition
	if err := json.Unmarshal(compositionJSON, &public); err != nil {
		t.Fatal(err)
	}
	composition, err := conversion.CompositionFromWire(public)
	if err != nil {
		t.Fatal("peer composition conversion", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	target := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: targets.Request{ClusterID: cluster, Namespace: configuration.NamespaceRef{Name: "payments", UID: "namespace"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "namespace", Name: "api-a", UID: "pod", ControllerUID: "replicaset"}, PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "policies", Generation: 1, Digest: artifact.Digest{1}}, Complete: true, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 600, MaximumSeconds: 3600, DeletionBudgetSeconds: 10}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: 600, AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	in := planvalue.RecorderInput{CaptureID: cluster, Executor: identity.Principal{Issuer: "https://identity.example.test", Subject: "requester", ClientID: "console", Kind: identity.Human}, Target: target, Composition: *composition, Retention: retention, Deadline: now.Add(time.Minute), NodeRecorder: true, RequireApproval: true}
	_, err = compiler.CompileRecorder(in, recordingCompiler{}, now)
	var needed compiler.PeerResolutionNeeded
	if !errors.As(err, &needed) {
		t.Fatal("Kubernetes peer request compiled without a region resolution", err)
	}
	if len(needed.Request.Entries) != 1 || needed.Request.Entries[0].Resource == nil || *needed.Request.Entries[0].Resource != (targets.PeerResourceRef{Kind: "Pod", Namespace: "payments", Name: manualPeersClient}) || needed.Request.Namespace != target.Request.Namespace {
		t.Fatalf("needed peer request %+v", needed.Request)
	}
	in.Peers = []targets.PeerResolution{{Request: needed.Request, Members: []targets.PeerMember{{Kind: "Pod", UID: "11111111-1111-4111-8111-111111111111", IP: "10.244.1.7"}}, ResolvedAt: now.Add(-time.Second)}}
	plan, err := compiler.CompileRecorder(in, recordingCompiler{}, now)
	if err != nil {
		t.Fatal("peer request cannot compile through the actual planner", err)
	}
	a := plan.Actions[0]
	if !strings.Contains(a.Filter, "net 10.244.1.7/32") || a.PeerEndpoints != 1 || len(a.PeerMembersDigest) != 64 {
		t.Fatalf("peer filter %q endpoints %d digest %q", a.Filter, a.PeerEndpoints, a.PeerMembersDigest)
	}
	t.Logf("compiled peer filter %q; acceptance %+v", a.Filter, compiler.AcceptableRecorder(plan))
}

// The preview warning the focus reads (internal/transport/presentation
// recorderWarnings) carries the endpoint count and bounded members digest.
func TestInstalledManualPeersPreviewEndpoints(t *testing.T) {
	warnings := []string{"Packet filter compiled on the hub to 12 instructions: ...",
		"Peers: 1 Kubernetes endpoints resolved at preview (members digest 0123456789ab...), 1 prefixes in total, intersected with the packet filter; traffic to or from other addresses is not recorded. Membership is frozen at preview and shown for review."}
	if n, digest, ok := manualPeersEndpoints(warnings); !ok || n != 1 || digest != "0123456789ab..." {
		t.Fatal("peer preview warning not read", n, digest, ok)
	}
	if _, _, ok := manualPeersEndpoints([]string{"Peers: 2 CIDR prefixes, intersected with the packet filter"}); ok {
		t.Fatal("CIDR warning read as Kubernetes endpoints")
	}
}

// The tshark gate of the manual-peers focus on synthetic field lines.
func TestInstalledManualPeersPacketFields(t *testing.T) {
	const peer = "10.244.1.7"
	for name, tc := range map[string]struct {
		out string
		ok  bool
	}{
		"peer both ways": {"10.244.1.7\t10.244.0.5\t41000,8080\n10.244.0.5\t10.244.1.7\t8080,41000\n", true},
		"proxy packet":   {"10.244.1.7\t10.244.0.5\t41000,8080\n172.18.0.2\t10.244.0.5\t52000,8080\n", false},
		"other port":     {"10.244.1.7\t10.244.0.5\t41000,9090\n", false},
		"empty":          {"", false},
	} {
		if _, err := checkManualPeersFields(tc.out, peer); (err == nil) != tc.ok {
			t.Fatal(name, err)
		}
	}
}
