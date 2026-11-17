package postgres

import (
	"encoding/json"
	"strings"
	"testing"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

func syscallScopeFixture(t *testing.T, native string, view analysis.SyscallView) analysis.ContextProjectionScope {
	t.Helper()
	const id = "8e3eeae7-0c1f-43f4-912e-fb408c02e7cb"
	source, _ := analysis.LookupProjectionSourceFor(native, view.DisplayVersion())
	s := analysis.ContextProjectionScope{RootID: id, CaseID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, NativeType: native, SourceFormat: source.Format, DisplayVersion: source.DisplayVersion, Syscalls: analysis.SyscallWindow{View: view, Limit: 100}, Principal: identity.Principal{Issuer: "https://fixture.invalid", Subject: "reader", ClientID: "fixture", Kind: identity.Human}}
	if !s.Valid() {
		t.Fatal("invalid synthetic syscall scope")
	}
	return s
}

func TestSyscallProjectionPublishedSourceKeepsRawClassification(t *testing.T) {
	for _, kind := range []string{artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact} {
		for _, view := range []analysis.SyscallView{analysis.SyscallSummaryView, analysis.SyscallEventsView} {
			s := syscallScopeFixture(t, kind, view)
			source, _ := s.Source()
			e := artifact.ContextExpectation{NativeType: kind, DataClass: source.DataClass, Registration: artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}}
			if !scopeSource(s, e) {
				t.Fatal("published syscall source refused")
			}
			r := app.ContextProjectionEvidence{NativeType: kind, SourceFormat: source.Format, DataClass: source.DataClass, Retained: privacy.RetainedArtifact{Registration: e.Registration, Input: privacy.Input{EvidenceType: "syscallTrace"}}}
			if !projectionSource(r) {
				t.Fatal("processing source refused")
			}
			for _, change := range []func(*artifact.ContextExpectation){
				func(e *artifact.ContextExpectation) { e.NativeType = artifact.PprofArtifact },
				func(e *artifact.ContextExpectation) { e.Registration.NativeLimit-- },
				func(e *artifact.ContextExpectation) { e.DataClass = "extract" },
				func(e *artifact.ContextExpectation) {
					if e.DataClass == "raw" {
						e.DataClass = "metadata"
					} else {
						e.DataClass = "raw"
					}
				},
			} {
				bad := e
				change(&bad)
				if scopeSource(s, bad) {
					t.Fatal("published source was reclassified", bad)
				}
			}
		}
	}
}

func TestSyscallKeyChildEncodingRetainsLegacyBound(t *testing.T) {
	s := syscallScopeFixture(t, artifact.SyscallArgumentsArtifact, analysis.SyscallEventsView)
	s.Syscalls.NameCount = 64
	for i := range s.Syscalls.Names {
		s.Syscalls.Names[i] = strings.Repeat("\x01", 63) + string(rune(i+1))
	}
	if !s.Valid() {
		t.Fatal("invalid maximal escaped filter")
	}
	w, err := json.Marshal(s.Syscalls)
	if err != nil || len(w) <= 16<<10 || len(w) >= 25<<10 {
		t.Fatal("maximal filter encoding changed", len(w), err)
	}
	b := analysis.ContextProjectionKeyBinding{Authority: analysis.ContextProjectionAuthority{Scope: s}}
	if projectionKeyBindingBytes(b) != syscallProjectionKeyBindingBytes || (16<<10)+len(w) >= syscallProjectionKeyBindingBytes {
		t.Fatal("new filter cannot fit beside a maximal legacy binding")
	}
	encoded, err := json.Marshal(b)
	var restored analysis.ContextProjectionKeyBinding
	if err != nil || queryDecode(encoded, syscallProjectionKeyBindingBytes, &restored) != nil || restored.Authority.Scope != s || len(encoded) > projectionKeyBindingBytes(restored) {
		t.Fatal("maximal typed filter failed key-child round trip", len(encoded), err)
	}
	b.Authority.Scope.DisplayVersion = "unregistered"
	if projectionKeyBindingBytes(b) != 16<<10 {
		t.Fatal("invalid syscall source enlarged key child")
	}
	b.Authority.Scope = analysis.ContextProjectionScope{NativeType: artifact.PprofArtifact}
	if projectionKeyBindingBytes(b) != 16<<10 {
		t.Fatal("legacy source gained a larger key child")
	}
	t.Logf("maximal escaped filter %d bytes; original16KiB+filter=%d <48KiB key-child bound; partial structural binding=%d bytes (not authority)", len(w), (16<<10)+len(w), len(encoded))
}
