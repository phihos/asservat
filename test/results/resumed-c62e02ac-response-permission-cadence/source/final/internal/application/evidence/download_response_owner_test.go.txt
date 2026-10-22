package evidence

import (
	"context"
	"testing"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
)

type responseOwnerProbe struct {
	CurrentDownloadAuthority
	closed, checks int
}

func (p *responseOwnerProbe) CheckDownloadCurrent(ctx context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	if p.closed != 0 {
		return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
	}
	p.checks++
	return p.CurrentDownloadAuthority.CheckDownloadCurrent(ctx, current, scope)
}

func TestResponseTransferOneAuthorityOwnerSurvivesShortBatchesAndCloses(t *testing.T) {
	f, transfer, request := newResponseTransferFixture(t, artifact.DownloadWindowBytes+17)
	f.advanceBetweenWindows = true
	probe := &responseOwnerProbe{CurrentDownloadAuthority: f}
	created := 0
	transfer.NewResponseAuthority = func(ctx context.Context, scope artifact.DownloadScope) (CurrentDownloadAuthority, func(), error) {
		created++
		until, ok := ctx.Deadline()
		if scope != f.s.Scope || !ok || !until.Equal(request.HardUntil) {
			t.Fatal("owner was not bound to the original response")
		}
		return probe, func() { probe.closed++ }, nil
	}
	if err := transfer.Transfer(t.Context(), f, request, f, f); err != nil {
		t.Fatal(err)
	}
	if created != 1 || probe.closed != 1 || probe.checks != 3 || f.batches != 3 || f.s.State != artifact.DownloadCompleted {
		t.Fatal("short batches closed/recreated the response owner", created, probe.closed, probe.checks, f.batches, f.s.State)
	}
}
