package analysis

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func sourceTestScope() ContextProjectionScope {
	id := "00000000-0000-4000-8000-000000000001"
	return ContextProjectionScope{RootID: id, CaseID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "w", PodUID: "p",
		Version: artifact.Digest{1}, SourceProjectionDigest: ContextSourceProjectionDigest(), SourceFormat: artifact.ContextFormat, DisplayVersion: ContextDisplayVersion,
		Selection: LineSelection{LineStart: 1, MaxLines: 200}, Principal: identity.Principal{Issuer: "https://issuer.invalid", Subject: "s", ClientID: "c", Kind: identity.Human}}
}

// ADR-282: the pod-status scope keeps its serialized form (stored queries,
// decision digests); the extract scope adds exactly the two new fields.
func TestProjectionScopeSourcesAreClosedAndCompatible(t *testing.T) {
	pod := sourceTestScope()
	if !pod.Valid() {
		t.Fatal("pod-status scope invalid")
	}
	b, _ := json.Marshal(pod)
	if strings.Contains(string(b), "NativeType") || strings.Contains(string(b), "Headers") {
		t.Fatalf("pod-status scope changed its serialized form: %s", b)
	}
	http := pod
	http.NativeType, http.SourceFormat, http.DisplayVersion, http.SourceProjectionDigest = artifact.HTTPHeadersArtifact, artifact.HTTPHeadersFormat, HTTPHeadersDisplayVersion, artifact.Digest{}
	http.Selection, http.Headers = LineSelection{}, HTTPHeaderWindow{Limit: 100}
	if !http.Valid() {
		t.Fatal("extract scope invalid")
	}
	var back ContextProjectionScope
	if b, _ = json.Marshal(http); json.Unmarshal(b, &back) != nil || back != http {
		t.Fatalf("extract scope did not round trip: %s", b)
	}
	for name, mutate := range map[string]func(*ContextProjectionScope){
		"line-selection":   func(s *ContextProjectionScope) { s.Selection = LineSelection{LineStart: 1, MaxLines: 1} },
		"no-window":        func(s *ContextProjectionScope) { s.Headers = HTTPHeaderWindow{} },
		"unbound-cursor":   func(s *ContextProjectionScope) { s.Headers.Start = 5 },
		"pod-digest":       func(s *ContextProjectionScope) { s.SourceProjectionDigest = ContextSourceProjectionDigest() },
		"pod-format":       func(s *ContextProjectionScope) { s.SourceFormat = artifact.ContextFormat },
		"pod-display":      func(s *ContextProjectionScope) { s.DisplayVersion = ContextDisplayVersion },
		"raw-type":         func(s *ContextProjectionScope) { s.NativeType = artifact.RawPCAPNGArtifact },
		"oversized-window": func(s *ContextProjectionScope) { s.Headers.Limit = HTTPHeaderPageRecords + 1 },
	} {
		s := http
		mutate(&s)
		if s.Valid() {
			t.Fatalf("%s accepted", name)
		}
	}
	p := pod
	p.Headers = HTTPHeaderWindow{Limit: 1}
	if p.Valid() {
		t.Fatal("pod-status scope accepted a record window")
	}
	if _, ok := LookupProjectionSource(artifact.PCAPNGArtifact); ok {
		t.Fatal("pcapng is not a projection source")
	}
	w := HTTPHeaderWindow{Start: 3, Limit: 10, Binding: "0123456789abcdef0123456789abcdef"}
	if !w.Valid() || w.Selection(pod.CaseID, pod.ArtifactID).Window() != w || !w.Selection(pod.CaseID, pod.ArtifactID).Valid() {
		t.Fatal("window and selection disagree")
	}
}

// ADR-282 slice 5: a result is exactly the scope's branch; an extract query
// is admitted by get_http_headers and starts one read batch.
func TestProjectionResultMatchesItsScope(t *testing.T) {
	pod := sourceTestScope()
	http := pod
	http.NativeType, http.SourceFormat, http.DisplayVersion, http.SourceProjectionDigest = artifact.HTTPHeadersArtifact, artifact.HTTPHeadersFormat, HTTPHeadersDisplayVersion, artifact.Digest{}
	http.Selection, http.Headers = LineSelection{}, HTTPHeaderWindow{Limit: 2}
	if pod.BeginTool() != "get_file_excerpt" || pod.ReadBatches() != 2 || http.BeginTool() != "get_http_headers" || http.ReadBatches() != 1 {
		t.Fatal("scope tool or batch count")
	}
	status := PodStatusProjection{Format: artifact.ContextFormat, NamespaceUID: pod.NamespaceUID, PodUID: pod.PodUID, ResourceVersion: "1", ObservedAt: time.Unix(1, 0),
		Phase: "Running", Ready: "True", Initialized: "True", Scheduled: "True"}
	page := HTTPHeaderPage{ProjectionDigest: artifact.Digest{3}, Total: 1, Records: []HTTPHeaderRecord{{Timestamp: time.Unix(2, 0), Method: "GET", Status: 200}}}
	for name, c := range map[string]struct {
		r     ProjectionResult
		scope ContextProjectionScope
		ok    bool
	}{
		"pod":               {ProjectionResult{PodStatus: status}, pod, true},
		"page":              {ProjectionResult{Headers: page}, http, true},
		"invalid cursor":    {ProjectionResult{InvalidCursor: true}, http, true},
		"pod as page":       {ProjectionResult{PodStatus: status}, http, false},
		"page as pod":       {ProjectionResult{Headers: page}, pod, false},
		"cursor with page":  {ProjectionResult{Headers: page, InvalidCursor: true}, http, false},
		"cursor on pod":     {ProjectionResult{PodStatus: status, InvalidCursor: true}, pod, false},
		"other pod":         {ProjectionResult{PodStatus: func() PodStatusProjection { s := status; s.PodUID = "other"; return s }()}, pod, false},
		"empty extract":     {ProjectionResult{}, http, false},
		"page and pod both": {ProjectionResult{PodStatus: status, Headers: page}, http, false},
	} {
		if c.r.Valid(c.scope) != c.ok {
			t.Fatal(name)
		}
	}
	if HTTPHeaderPageWireBytes+4<<10 > 64<<10 || HTTPHeaderQueryUnits != 2 {
		t.Fatal("page wire bound or query units changed")
	}
}

func TestProfileProjectionSourcePreservesAuthoredLimit(t *testing.T) {
	p, ok := LookupProjectionSource(artifact.PprofArtifact)
	if !ok {
		t.Fatal("missing profile source")
	}
	for _, limit := range []int64{1, 16 << 20, artifact.MaxPprofBytes} {
		if !p.Matches(artifact.PprofArtifact, artifact.PprofFormat, "raw", "profile", limit, artifact.Digest{}) {
			t.Fatal("authored finite bound refused", limit)
		}
	}
	for _, limit := range []int64{0, -1, artifact.MaxPprofBytes + 1} {
		if p.Matches(artifact.PprofArtifact, artifact.PprofFormat, "raw", "profile", limit, artifact.Digest{}) {
			t.Fatal("invalid bound accepted", limit)
		}
	}
	pod, _ := LookupProjectionSource(artifact.PodStatusArtifact)
	if pod.Matches(pod.NativeType, pod.Format, pod.DataClass, pod.EvidenceType, pod.NativeLimit-1, pod.ProjectionDigest) {
		t.Fatal("unrelated source exact bound changed")
	}
}
