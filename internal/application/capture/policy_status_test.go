package capture

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
)

type statusPermissionsHook struct {
	f     *activationFixture
	after func()
}

func (s statusPermissionsHook) Permissions(ctx context.Context, target authorization.Target) (authorization.Projection, error) {
	p, err := s.f.Permissions(ctx, target)
	if s.after != nil {
		s.after()
	}
	return p, err
}
func TestPolicyStatusSharedBudgetsRequireCurrentViewerAfterCreatorDeparture(t *testing.T) {
	f := newActivationFixture(t)
	result, err := f.activation().Activate(context.Background(), f, "restarts", "status-budget", true)
	if err != nil {
		t.Fatal(err)
	}
	a := f.accepted[0].Authority
	f.status = value.PolicyStatus{PolicyUID: a.PolicyUID, ActiveID: result.AcceptanceID, Authority: a, NotAfter: a.NotAfter, ExecutionsSpent: 5, MaxExecutions: a.Limits.MaxExecutions, CollectedBytesSpent: 16384, MaxCollectedBytes: a.Limits.MaxBytes, ObservedBytesSpent: 0, MaxObservedBytes: a.Limits.MaxObservedBytes}
	// The creator has left; another current team maintainer reads the same pool.
	f.author.Principal.Subject = "current-maintainer"
	service := PolicyStatusService{RootID: activationRoot, InstallationID: activationInstallation, Documents: f, Ledger: f, Permissions: f, Recovery: f, Now: time.Now}
	status, until, err := service.Get(context.Background(), f, "restarts")
	if err != nil || status.CollectedBytesSpent != 16384 || status.ExecutionsSpent != 5 || status.MaxCollectedBytes != a.Limits.MaxBytes || status.ObservedBytesSpent != 0 || until.After(f.now.Add(5*time.Second)) {
		t.Fatal("current manager shared status", status, until, err)
	}
	f.author.Groups = []string{"unrelated"}
	if out, _, err := service.Get(context.Background(), f, "restarts"); err == nil || out.ActiveID != "" {
		t.Fatal("former membership disclosed shared policy metadata", err)
	}
	f.author.Groups = []string{"team-a"}
	service.Permissions = statusPermissionsHook{f: f, after: func() { f.author.ValidUntil = time.Now().Add(-time.Second) }}
	if out, _, err := service.Get(context.Background(), f, "restarts"); err == nil || out.ActiveID != "" {
		t.Fatal("blocking permission read bypassed final identity expiry", err)
	}
}
