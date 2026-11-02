package analysis

import (
	"encoding/json"
	"strings"
	"testing"

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
