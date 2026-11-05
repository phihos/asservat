package objectstore

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/syscalls"
	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
)

// Actual approved receiver → outer native reader → startup-installed query
// callback, canonical full-file validation, encrypted TLS ranges and three TLS
// key bindings. The key/source/worker authority is synthetic, not SQL/KMS proof.
func TestRawSyscallQueryActualReceiverEncryptedTLSAndTail(t *testing.T) {
	for _, mode := range []string{"complete", "malformed-tail", "whole-hash", "cancel", "source-error", "unconfigured", "metadata-source", "wrong-pod"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			keyScope := value.KeyScope{InstallationID: testProjectionScope().RootID, Purpose: "artifact", KeyID: "synthetic"}
			kind := "arguments"
			if mode == "metadata-source" {
				kind = "metadata-repeated"
			}
			f := prepareSyscallEncryptedFixture(t, dir, kind, false, mode == "malformed-tail", mode == "whole-hash", comparisonRemoteFixtureSealer{scope: keyScope})
			f.Scope.DisplayVersion, f.Scope.Syscalls.View, f.Scope.RawGrantID = query.SyscallQueryDisplayVersion, query.SyscallQueryView, f.Scope.RootID
			f.Scope.Syscalls.Limit = 1
			if mode == "wrong-pod" {
				f.Scope.PodUID += "-different"
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			out, err, roles, joined, _ := savedPacketProbeRead(t, ctx, cancel, dir, f, mode, func(r *NativeContextReader) {
				if mode != "unconfigured" {
					r.ServeSyscallQueries(syscalls.QuerySyscallArguments)
				}
			})
			if !joined {
				t.Fatal("receiver remained live")
			}
			if mode == "complete" {
				if err != nil || out.SyscallQuery == nil || !out.Valid(f.Scope) || roles != 3 || len(out.SyscallQuery.Events) != 1 || out.SyscallQuery.RecordCount != 3 || out.SyscallQuery.TotalMatching != 3 {
					t.Fatal("actual raw composition", err, roles)
				}
				event := out.SyscallQuery.Events[0]
				if event.Arguments[0].Value != "decimal:1" || event.Arguments[2].Value != "base64:"+base64.StdEncoding.EncodeToString([]byte(syscallProjectionSecret)) {
					t.Fatal("recorded values reinterpreted")
				}
			} else if err == nil || out.SyscallQuery != nil || out.InvalidCursor || out.TooLarge {
				t.Fatal("fault after prefix disclosed result", mode, err)
			}
			if (mode == "unconfigured" || mode == "metadata-source" || mode == "wrong-pod") && roles != 0 {
				t.Fatal("missing parser spent keys", roles)
			}
		})
	}
}

func TestRawSyscallQueryCursorStillAuthenticatesMalformedSource(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		dir := t.TempDir()
		f := prepareSyscallEncryptedFixture(t, dir, "arguments", false, malformed, false)
		f.Scope.DisplayVersion, f.Scope.Syscalls.View, f.Scope.RawGrantID = query.SyscallQueryDisplayVersion, query.SyscallQueryView, f.Scope.RootID
		selection := f.Scope.Syscalls.Selection(f.Scope.CaseID, f.Scope.ArtifactID)
		// Cursor binds a different source version, causing the parser's early typed
		// refusal; the canonical same-stream wrapper must still inspect the tail.
		other := f.Scope.Version
		other[0] ^= 1
		selection, err := query.NormalizeSyscallSelection(f.Scope.CaseID, f.Scope.ArtifactID, query.SyscallQueryView, selection.Cursor(1, other), 1, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		f.Scope.Syscalls = selection.Window()
		verifier, keys, _, _ := profileEncryptedVerifier(t, dir, f, false)
		reader, err := NewContextProjectionReader(verifier.store)
		if err != nil {
			t.Fatal(err)
		}
		reader.ServeSyscallQueries(syscalls.QuerySyscallArguments)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		until, _ := ctx.Deadline()
		result, err := reader.ReadProjectionNative(ctx, f.Source, f.Scope, keys, until)
		cancel()
		if malformed {
			if err == nil || result.InvalidCursor || result.SyscallQuery != nil {
				t.Fatal("bad tail became cursor success", err)
			}
		} else if err != nil || !result.InvalidCursor || keys.calls != 3 {
			t.Fatal("authenticated cursor refusal", err, keys.calls)
		}
	}
}
