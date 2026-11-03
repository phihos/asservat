package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

// SQL132 component parity, not a read permit or syscall parser qualification.
func qualifySavedSyscallQueryFunctions(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	id := custodyID()
	for _, native := range []string{artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact} {
		for _, view := range []analysis.SyscallView{analysis.SyscallSummaryView, analysis.SyscallEventsView} {
			source, _ := analysis.LookupProjectionSourceFor(native, view.DisplayVersion())
			scope := analysis.ContextProjectionScope{RootID: id, CaseID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, NativeType: native, SourceFormat: source.Format, DisplayVersion: source.DisplayVersion, Syscalls: analysis.SyscallWindow{View: view, Limit: 100}, Principal: identity.Principal{Issuer: "https://fixture.invalid", Subject: "reader", ClientID: "fixture", Kind: identity.Human}}
			for _, mode := range []string{"valid", "continuation", "filter", "max-filter", "extra-field", "missing-field", "null-filter", "short-array", "trailing-name", "unsorted", "duplicate", "long-name", "name-count", "fractional-start", "limit", "bad-cursor", "first-cursor", "summary-filter", "line-selection", "headers", "profile", "digest", "format", "other-view", "version"} {
				t.Run(native+"/"+string(view)+"/"+mode, func(t *testing.T) {
					s := scope
					switch mode {
					case "continuation":
						s.Syscalls.Start, s.Syscalls.Binding = 1, strings.Repeat("a", 32)
					case "filter":
						s.Syscalls.NameCount, s.Syscalls.Names[0], s.Syscalls.ErrorsOnly = 1, "write", true
					case "max-filter":
						s.Syscalls.NameCount = 64
						for i := range s.Syscalls.Names {
							s.Syscalls.Names[i] = strings.Repeat("\x01", 63) + string(rune(i+1))
						}
					case "trailing-name":
						s.Syscalls.Names[63] = "hidden"
					case "unsorted":
						s.Syscalls.NameCount, s.Syscalls.Names[0], s.Syscalls.Names[1] = 2, "write", "read"
					case "duplicate":
						s.Syscalls.NameCount, s.Syscalls.Names[0], s.Syscalls.Names[1] = 2, "read", "read"
					case "long-name":
						s.Syscalls.NameCount, s.Syscalls.Names[0] = 1, strings.Repeat("é", 65)
					case "name-count":
						s.Syscalls.NameCount = 65
					case "limit":
						s.Syscalls.Limit = 101
					case "bad-cursor":
						s.Syscalls.Start, s.Syscalls.Binding = 1, strings.Repeat("A", 32)
					case "first-cursor":
						s.Syscalls.Binding = strings.Repeat("a", 32)
					case "summary-filter":
						s.Syscalls.NameCount, s.Syscalls.Names[0] = 1, "read"
						s.Syscalls.View, s.DisplayVersion = analysis.SyscallSummaryView, analysis.SyscallSummaryDisplayVersion
					case "line-selection":
						s.Selection = analysis.LineSelection{LineStart: 1, MaxLines: 1}
					case "headers":
						s.Headers = analysis.HTTPHeaderWindow{Limit: 1}
					case "profile":
						s.Profile = analysis.ProfileSummarySelection{SampleType: "cpu", TopN: 1}
					case "digest":
						s.SourceProjectionDigest[0] = 1
					case "format":
						s.SourceFormat = "wrong"
					case "other-view":
						if view == analysis.SyscallSummaryView {
							s.DisplayVersion = analysis.SyscallEventsDisplayVersion
						} else {
							s.DisplayVersion = analysis.SyscallSummaryDisplayVersion
						}
					case "version":
						s.DisplayVersion = "approved-syscall-events/v2"
					}
					raw, err := json.Marshal(s)
					if err != nil {
						t.Fatal(err)
					}
					var obj map[string]any
					if err := json.Unmarshal(raw, &obj); err != nil {
						t.Fatal(err)
					}
					w := obj["Syscalls"].(map[string]any)
					switch mode {
					case "extra-field":
						w["Arguments"] = true
					case "missing-field":
						delete(w, "ErrorsOnly")
					case "null-filter":
						w["Names"] = nil
					case "short-array":
						w["Names"] = []string{}
					case "fractional-start":
						w["Start"] = .4
					}
					raw, err = json.Marshal(obj)
					if err != nil {
						t.Fatal(err)
					}
					want := mode == "valid" || mode == "continuation" || (mode == "filter" || mode == "max-filter") && view == analysis.SyscallEventsView
					var valid bool
					if err := conn.QueryRow(ctx, "SELECT context_query_scope_source_valid($1::jsonb)", raw).Scan(&valid); err != nil || valid != want {
						t.Fatal("closed source/view/selection", valid, want, err)
					}
					if mode != "extra-field" && mode != "missing-field" && mode != "null-filter" && mode != "short-array" && mode != "fractional-start" && s.Valid() != valid {
						t.Fatal("Go/SQL scope source parity", s.Valid(), valid)
					}
				})
			}
			raw, _ := json.Marshal(scope)
			var units, batches int
			var tool, lane string
			var input, oldInput bool
			if err := conn.QueryRow(ctx, `SELECT context_query_units($1::jsonb),context_query_read_batches($1::jsonb),context_query_begin_tool($1::jsonb),operation_audit_lane($2),operation_audit_human_input_valid($2,'context-query-input/v1'),operation_audit_human_input_valid($2,'context-input/v1')`, raw, scope.BeginTool()).Scan(&units, &batches, &tool, &lane, &input, &oldInput); err != nil || units != analysis.SyscallProjectionQueryUnits || batches != 1 || tool != scope.BeginTool() || lane != "normal" || !input || oldInput {
				t.Fatal("syscall accounting/audit", units, batches, tool, lane, input, oldInput, err)
			}
		}
	}
	// A formerly known source may not smuggle in the new selection branch.
	var legacyValid, rawReview bool
	if err := conn.QueryRow(ctx, `SELECT context_query_scope_source_valid('{"SourceFormat":"asservat-pod-status/v1","DisplayVersion":"approved-pod-status-display/v1","Syscalls":{}}'), operation_audit_lane('request_raw_access')='normal' AND operation_audit_human_input_valid('request_raw_access','context-input/v1')`).Scan(&legacyValid, &rawReview); err != nil || legacyValid || !rawReview {
		t.Fatal("legacy branch/raw review preservation", legacyValid, rawReview, err)
	}
	// Execute the actual installed CHECK expression with JSONB's canonical
	// spacing/escaping. This tests the bound without seeding key authority.
	var keyConstraint string
	if err := conn.QueryRow(ctx, `SELECT pg_get_expr(conbin,conrelid) FROM pg_constraint WHERE conrelid='public.context_query_key_binding'::regclass AND conname='context_query_key_binding_binding_check'`).Scan(&keyConstraint); err != nil {
		t.Fatal("installed key-child constraint", err)
	}
	source, _ := analysis.LookupProjectionSourceFor(artifact.SyscallArgumentsArtifact, analysis.SyscallEventsDisplayVersion)
	scope := analysis.ContextProjectionScope{RootID: id, CaseID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, NativeType: source.NativeType, SourceFormat: source.Format, DisplayVersion: source.DisplayVersion, Syscalls: analysis.SyscallWindow{View: analysis.SyscallEventsView, Limit: 100, NameCount: 64}, Principal: identity.Principal{Issuer: "https://fixture.invalid", Subject: "reader", ClientID: "fixture", Kind: identity.Human}}
	for i := range scope.Syscalls.Names {
		scope.Syscalls.Names[i] = strings.Repeat("\x01", 63) + string(rune(i+1))
	}
	if !scope.Valid() {
		t.Fatal("invalid maximal key-child scope")
	}
	for _, mode := range []string{"max-filter", "legacy", "too-large"} {
		b := analysis.ContextProjectionKeyBinding{Authority: analysis.ContextProjectionAuthority{Scope: scope}}
		encoded, _ := json.Marshal(b)
		var value map[string]any
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatal(err)
		}
		if mode == "legacy" {
			value["Authority"].(map[string]any)["Scope"].(map[string]any)["NativeType"] = artifact.PprofArtifact
		}
		if mode == "too-large" {
			value["synthetic-size-only"] = strings.Repeat("x", 48<<10)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var valid bool
		var bytes int
		if err := conn.QueryRow(ctx, "SELECT "+keyConstraint+",octet_length(binding::text) FROM (SELECT $1::jsonb AS binding) synthetic", encoded).Scan(&valid, &bytes); err != nil || valid != (mode == "max-filter") {
			t.Fatal("narrow canonical key-child bound", mode, valid, bytes, err)
		}
		if mode == "max-filter" {
			t.Logf("maximal64×64escaped filter key-child JSONB: %d bytes; fits48KiB only for syscall scopes; no key authority seeded", bytes)
		}
	}
}
