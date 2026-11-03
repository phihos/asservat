package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"bytes"
	"encoding/json"
	"testing"
)

func TestSyscallScopeKeepsExactSourceViewAndSelection(t *testing.T) {
	for _, kind := range []string{artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact} {
		for _, view := range []SyscallView{SyscallSummaryView, SyscallEventsView} {
			scope := testAuthority().Scope
			selection, err := NormalizeSyscallSelection(scope.CaseID, scope.ArtifactID, view, "", 10, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			source, ok := LookupProjectionSourceFor(kind, view.DisplayVersion())
			if !ok || source.OutputClass() != "extract" {
				t.Fatal(source, ok)
			}
			operation := authorization.ReadApproved
			if kind == artifact.SyscallArgumentsArtifact {
				operation = authorization.ReadSyscallProjection
			}
			if source.ReadOperation() != operation {
				t.Fatal(source.ReadOperation())
			}
			scope.NativeType, scope.SourceFormat, scope.SourceProjectionDigest, scope.DisplayVersion = kind, source.Format, source.ProjectionDigest, source.DisplayVersion
			scope.Selection, scope.Syscalls = LineSelection{}, selection.Window()
			if !scope.Valid() || !scope.Candidate().Valid() {
				t.Fatal(scope)
			}
			changed := scope
			if view == SyscallSummaryView {
				changed.DisplayVersion = SyscallEventsDisplayVersion
			} else {
				changed.DisplayVersion = SyscallSummaryDisplayVersion
			}
			if changed.Valid() {
				t.Fatal("scope admitted a different known view")
			}
			changed = scope
			changed.DisplayVersion = "other"
			if changed.Valid() {
				t.Fatal("unknown display admitted")
			}
			changed = scope
			changed.Headers = HTTPHeaderWindow{Limit: 1}
			if changed.Valid() {
				t.Fatal("mixed display branches admitted")
			}
			changed = scope
			changed.Syscalls.Names[63] = "hidden"
			if changed.Valid() {
				t.Fatal("unreviewed trailing filter admitted")
			}
			changed = scope
			changed.Syscalls.NameCount = 65
			if changed.Valid() {
				t.Fatal("invalid filter count admitted")
			}
		}
	}
	// A closed source cannot be changed into an alternative classification.
	source, _ := LookupProjectionSourceFor(artifact.SyscallArgumentsArtifact, SyscallEventsDisplayVersion)
	source.DataClass = "metadata"
	if source.ReadOperation() != "" {
		t.Fatal("source classification supplied its own authority")
	}
}

func TestSyscallWindowOwnsNamesAndPreservesComparableScope(t *testing.T) {
	selection, _ := NormalizeSyscallSelection(headerCase, headerArtifact, SyscallEventsView, "", 0, []string{"read", "write"}, true)
	window := selection.Window()
	selection.Names[0] = "changed"
	if !window.Valid() || window.Names[0] != "read" {
		t.Fatal("window borrowed request filter")
	}
	restored := window.Selection(headerCase, headerArtifact)
	restored.Names[0] = "changed"
	if window.Names[0] != "read" || window != (SyscallWindow{View: SyscallEventsView, Limit: 100, Names: [64]string{"read", "write"}, NameCount: 2, ErrorsOnly: true}) {
		t.Fatal(window)
	}
}

func TestSyscallSelectionIsOmittedFromLegacyScopesAndRoundTripsExactly(t *testing.T) {
	scope := testAuthority().Scope
	for _, value := range []any{scope, scope.Candidate()} {
		body, err := json.Marshal(value)
		if err != nil || bytes.Contains(body, []byte(`"Syscalls"`)) {
			t.Fatal("legacy scope identity gained an empty branch", string(body), err)
		}
	}
	selection, _ := NormalizeSyscallSelection(scope.CaseID, scope.ArtifactID, SyscallEventsView, "", 7, []string{"write", "read"}, true)
	source, _ := LookupProjectionSourceFor(artifact.SyscallRecordsArtifact, SyscallEventsDisplayVersion)
	scope.NativeType, scope.SourceFormat, scope.SourceProjectionDigest, scope.DisplayVersion = source.NativeType, source.Format, source.ProjectionDigest, source.DisplayVersion
	scope.Selection, scope.Syscalls = LineSelection{}, selection.Window()
	body, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	var restored ContextProjectionScope
	if json.Unmarshal(body, &restored) != nil || restored != scope || !restored.Valid() {
		t.Fatal("scope lost exact selection", restored)
	}
}
