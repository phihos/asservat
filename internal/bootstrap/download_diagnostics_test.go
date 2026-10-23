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

type downloadReportRecovery struct{ err error }

func (d downloadReportRecovery) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return artifact.RecoveryProof{}, d.err
}

// Unused ports panic if reached: a refused recovery read precedes them.
type downloadReportPorts struct {
	evidence.ContextDownloadRoutes
	evidence.ContextDownloadSources
	evidence.CurrentDownloadAuthority
	evidence.ContextDownloadControlLedger
	evidence.ContextDownloadPlans
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
		{errors.New("private recovery endpoint token"), "prepare/recovery (unavailable) left@>=2s"},
		{fmt.Errorf("private: %w", context.DeadlineExceeded), "prepare/recovery (cancelled) left@>=2s"},
	} {
		var lines []string
		ports := downloadReportPorts{}
		s := evidence.ContextDownloadCoordinator{RootID: "00000000-0000-4000-8000-000000000001", InstallationID: "00000000-0000-4000-8000-000000000002",
			Recovery: downloadReportRecovery{c.cause}, Routes: ports, Sources: ports, Authority: ports, Sessions: ports, Plans: ports,
			Refused: downloadRefusalReport(func(line string) { lines = append(lines, line) }, time.Now), Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000003" }}
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
