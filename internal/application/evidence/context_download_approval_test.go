package evidence

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"context"
	"errors"
	"testing"
)

type approvalPreparationAuthority struct {
	*downloadControlFixture
	err      error
	prepared int
}

func (a *approvalPreparationAuthority) CheckDownloadPreparation(ctx context.Context, i identities.CurrentIdentity, s artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	a.prepared++
	if a.err != nil {
		return artifact.DownloadAuthority{}, a.err
	}
	return a.downloadControlFixture.CheckDownloadCurrent(ctx, i, s)
}
func (a *approvalPreparationAuthority) CheckDownloadCurrent(ctx context.Context, i identities.CurrentIdentity, s artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	if a.err != nil {
		return artifact.DownloadAuthority{}, a.err
	}
	return a.downloadControlFixture.CheckDownloadCurrent(ctx, i, s)
}
func TestRawDownloadApprovalOnlyForFreshPreparation(t *testing.T) {
	f, s := newDownloadControlFixture(t)
	a := &approvalPreparationAuthority{downloadControlFixture: f, err: authorization.ErrApprovalRequired}
	s.Authority = a
	if _, err := s.PrepareContextDownload(t.Context(), f, f.a.Scope.ArtifactID, "same-key"); !errors.Is(err, authorization.ErrApprovalRequired) || f.found || countDownloadCalls(f, "reserve") != 0 || countDownloadCalls(f, "source") != 0 {
		t.Fatal("missing approval allocated or lost type", err, f.calls)
	}
	a.err = nil
	if _, err := s.PrepareContextDownload(t.Context(), f, f.a.Scope.ArtifactID, "same-key"); err != nil {
		t.Fatal(err)
	}
	if !f.found || a.prepared != 2 {
		t.Fatal("original fresh preparation not reused")
	}
	a.err = authorization.ErrApprovalRequired
	if _, err := s.PrepareContextDownload(t.Context(), f, f.a.Scope.ArtifactID, "same-key"); errors.Is(err, authorization.ErrApprovalRequired) || err == nil || a.prepared != 2 {
		t.Fatal("accepted replay reopened review", err)
	}
	if _, err := s.GetContextDownload(t.Context(), f, f.session.ID); errors.Is(err, authorization.ErrApprovalRequired) || err == nil {
		t.Fatal("status reopened review", err)
	}
}
