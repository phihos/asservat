package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type downloadReportIdentity struct{ i identity.Identity }

func (d downloadReportIdentity) ResolveIdentity(context.Context) (identity.Identity, error) {
	return d.i, nil
}

// Unused ports panic if reached: a refused key lookup precedes them.
type downloadReportPorts struct {
	evidence.ContextDownloadRoutes
	evidence.ContextDownloadSources
	evidence.CurrentDownloadAuthority
	evidence.ContextDownloadControlLedger
	evidence.ContextDownloadPlans
	err error
}

func (d downloadReportPorts) LookupDownloadKey(context.Context, artifact.DownloadKeyQuery) (artifact.DownloadKeyLookup, error) {
	return artifact.DownloadKeyLookup{}, d.err
}

// A refusal from one injected preparation sub-step names that stage, its
// closed class and the remaining deadline bucket, and no dependency text.
func TestDownloadRefusalReportNamesTheRefusingStage(t *testing.T) {
	now := time.Now()
	rev := identity.Revision{UID: "00000000-0000-4000-8000-000000000040", Generation: 1, Digest: [32]byte{40}}
	current := downloadReportIdentity{identity.Identity{Principal: identity.Principal{Issuer: "https://identity.example.test", Subject: "dev", ClientID: "console", Kind: identity.Human}, Policy: rev, Scopes: []string{"evidence:read", "evidence:download"}, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}}
	for _, c := range []struct {
		cause error
		want  string
	}{
		{errors.New("private key endpoint token"), "prepare/key-lookup (unavailable) left@>=2s"},
		{fmt.Errorf("private: %w", context.DeadlineExceeded), "prepare/key-lookup (cancelled) left@>=2s"},
	} {
		var lines []string
		ports := downloadReportPorts{err: c.cause}
		s := evidence.ContextDownloadCoordinator{RootID: "00000000-0000-4000-8000-000000000001", InstallationID: "00000000-0000-4000-8000-000000000002",
			Routes: ports, Sources: ports, Authority: ports, Sessions: ports, Plans: ports,
			Refused: downloadRefusalReport(func(line, _ string) { lines = append(lines, line) }, time.Now), Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000003" }}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := s.PrepareContextDownload(ctx, current, "00000000-0000-4000-8000-000000000004", "key")
		cancel()
		if !errors.Is(err, artifact.ErrDownloadUnavailable) || errors.Is(err, c.cause) {
			t.Fatalf("returned class changed: %v", err)
		}
		if len(lines) != 1 || lines[0] != c.want || strings.Contains(lines[0], "private") {
			t.Fatalf("%q, want %q", lines, c.want)
		}
	}
}

// The worker executable names its fixed startup phase and closed class; the
// generic text alone left native72's 30-second stop unexplained.
func TestDownloadWorkerDiagnosticNamesStartupStep(t *testing.T) {
	err := workerStep("credentials", fmt.Errorf("%w: provider detail must not appear", artifact.ErrDownloadExpired))
	got := DownloadWorkerDiagnostic(err)
	if !strings.HasPrefix(got, "service stopped at credentials (expired): ") || strings.Contains(got, "provider detail") {
		t.Fatal(got)
	}
	if got := DownloadWorkerDiagnostic(errors.New("unlabelled")); !strings.HasPrefix(got, "service stopped at startup (unavailable): ") {
		t.Fatal(got)
	}
	if workerStep("native", nil) != nil {
		t.Fatal("a nil phase result became a stop")
	}
}
