package objectstore

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/syscalls"
	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
)

// Constructor-only key TLS pins are synthetic and never contacted. Actual
// encrypted framing and owned TLS range reads verify that the startup callback
// survives construction of the per-operation reader. Key authority/transport is
// independently qualified by the installed workflow, not by this test.
func TestNativeReaderRetainsInstalledSyscallProjector(t *testing.T) {
	for _, kind := range []string{"metadata-repeated", "arguments"} {
		for _, view := range []query.SyscallView{query.SyscallSummaryView, query.SyscallEventsView} {
			for _, enabled := range []bool{false, true} {
				dir := t.TempDir()
				f := prepareSyscallEncryptedFixture(t, dir, kind, false, false, false)
				f.Scope.Syscalls.View, f.Scope.DisplayVersion = view, view.DisplayVersion()
				verifier, keys, _, _ := profileEncryptedVerifier(t, dir, f, false)
				keyHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{{}}}}}
				installed, err := NewNativeContextReader(verifier.store, value.KeyScope{InstallationID: f.Scope.RootID, Purpose: "artifact", KeyID: "synthetic"}, "https://keys.invalid", keyHTTP)
				if err != nil {
					t.Fatal(err)
				}
				if enabled {
					installed.ServeSyscallProjections(syscalls.ProjectSyscalls)
				}
				reader, err := installed.projectionReader()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				until, _ := ctx.Deadline()
				result, err := reader.ReadProjectionNative(ctx, f.Source, f.Scope, keys, until)
				cancel()
				if enabled {
					if err != nil || !result.Valid(f.Scope) || keys.calls != 3 {
						t.Fatal("installed projector lost before exact regional read", kind, view, err, keys.calls)
					}
				} else if err == nil || result.SyscallSummary != nil || result.SyscallEvents != nil || keys.calls != 0 {
					t.Fatal("missing projector performed key reads or supplied output", kind, view, err, keys.calls)
				}
			}
		}
	}
}
