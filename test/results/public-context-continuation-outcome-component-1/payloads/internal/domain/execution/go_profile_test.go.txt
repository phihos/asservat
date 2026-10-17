package execution

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func profileRequestForTest() GoProfileRequest {
	const id = "00000000-0000-4000-8000-000000000001"
	n := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	return GoProfileRequest{Binding: artifact.Binding{ClusterID: id, ArtifactID: id, AttemptID: id, MediaType: GoProfileMediaType}, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: id, Name: "app-0", UID: id, ControllerUID: id, NodeName: "node"}, NodeUID: id, NodeBootID: id, SourceRef: "go-debug", EndpointDigest: artifact.Digest{1}, Parameters: GoProfileParameters{Type: "heap", Mode: "snapshot"}, NativeLimit: DefaultGoProfileBytes, NotBefore: n, Deadline: n.Add(5 * time.Second)}
}

func TestGoProfileParametersUseFiniteRuntimeSemantics(t *testing.T) {
	for _, p := range []GoProfileParameters{
		{Type: "cpu", Mode: "interval", Duration: 10 * time.Second},
		{Type: "cpu", Mode: "interval", Duration: 60 * time.Second},
		{Type: "runtimeTrace", Mode: "interval", Duration: 15 * time.Second},
		{Type: "heap", Mode: "snapshot"}, {Type: "heap", Mode: "snapshot", ForceGC: true},
		{Type: "heap", Mode: "delta", Duration: 10 * time.Second},
		{Type: "goroutine", Mode: "snapshot"}, {Type: "allocs", Mode: "cumulative"},
		{Type: "threadcreate", Mode: "cumulative"}, {Type: "mutex", Mode: "cumulative"}, {Type: "block", Mode: "delta", Duration: time.Second},
	} {
		if !p.Valid() {
			t.Fatalf("supported: %+v", p)
		}
	}
	for _, p := range []GoProfileParameters{
		{Type: "cpu", Mode: "interval"}, {Type: "cpu", Mode: "interval", Duration: 61 * time.Second},
		{Type: "cpu", Mode: "interval", Duration: 1500 * time.Millisecond},
		{Type: "runtimeTrace", Mode: "interval", Duration: 16 * time.Second},
		{Type: "heap", Mode: "snapshot", Duration: time.Second},
		{Type: "heap", Mode: "delta", Duration: time.Second, ForceGC: true},
		{Type: "mutex", Mode: "cumulative", ForceGC: true},
		{Type: "cmdline", Mode: "snapshot"}, {Type: "symbol", Mode: "snapshot"},
		{Type: "goroutineleak", Mode: "snapshot"}, {Type: "cpu", Mode: "ongoing", Duration: time.Second},
	} {
		if p.Valid() {
			t.Fatalf("unsupported became a request: %+v", p)
		}
	}
}

func TestGoProfileRequestRetainsExactNodeAndOriginalBounds(t *testing.T) {
	r := profileRequestForTest()
	if err := r.Validate(r.NotBefore); err != nil {
		t.Fatal(err)
	}
	bare := r
	bare.Pin.ControllerUID = ""
	if bare.Validate(bare.NotBefore) != nil {
		t.Fatal("bare Pod lost existing empty-controller semantics")
	}
	for name, change := range map[string]func(*GoProfileRequest){
		"missing-boot":      func(v *GoProfileRequest) { v.NodeBootID = "" },
		"unbound-source":    func(v *GoProfileRequest) { v.EndpointDigest = artifact.Digest{} },
		"wrong-native-type": func(v *GoProfileRequest) { v.Binding.MediaType = "application/json" },
		"oversized":         func(v *GoProfileRequest) { v.NativeLimit = MaximumGoProfileBytes + 1 },
		"zero-bytes":        func(v *GoProfileRequest) { v.NativeLimit = 0 },
		"missing-margin": func(v *GoProfileRequest) {
			v.Parameters = GoProfileParameters{Type: "cpu", Mode: "interval", Duration: 5 * time.Second}
		},
		"unbounded-finish": func(v *GoProfileRequest) { v.Deadline = v.NotBefore.Add(time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			v := r
			change(&v)
			if v.Validate(v.NotBefore) == nil {
				t.Fatal("invalid acquisition input accepted")
			}
		})
	}
	if r.Validate(r.Deadline) == nil || r.Validate(r.NotBefore.Add(-time.Microsecond)) == nil {
		t.Fatal("original interval lost")
	}
	r.Parameters = GoProfileParameters{Type: "cpu", Mode: "interval", Duration: 60 * time.Second}
	r.Deadline = r.NotBefore.Add(65 * time.Second)
	if r.Validate(r.NotBefore) != nil {
		t.Fatal("mechanism cannot express separately admitted maximum CPU duration")
	}
}

func TestGoProfileObservationNeverExtendsActionDeadline(t *testing.T) {
	r := profileRequestForTest()
	o := GoProfileCurrent{CheckedAt: r.NotBefore, ValidUntil: r.Deadline}
	if !o.Valid(r, r.NotBefore) || o.Valid(r, r.Deadline) {
		t.Fatal("observation expiry")
	}
	o.ValidUntil = o.ValidUntil.Add(time.Microsecond)
	if o.Valid(r, r.NotBefore) {
		t.Fatal("current observation extended action")
	}
	r.Deadline = r.NotBefore.Add(10 * time.Second)
	o.ValidUntil = r.NotBefore.Add(6 * time.Second)
	if o.Valid(r, r.NotBefore) {
		t.Fatal("observation extended five-second freshness")
	}
}
