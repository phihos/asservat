package configuration

import (
	"context"
	"errors"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

type grantSettingsFixture struct {
	now                 time.Time
	policy              value.Policy
	sourceErr, storeErr error
	reads, writes       int
	seen                []value.PolicyGrantSettingsObservation
	source              func(context.Context)
	project             func(context.Context)
}

func (f *grantSettingsFixture) IdentityPolicy(ctx context.Context, _ string) (value.Policy, error) {
	f.reads++
	if f.source != nil {
		f.source(ctx)
	}
	return f.policy, f.sourceErr
}
func (f *grantSettingsFixture) AcceptPolicyGrantSettings(ctx context.Context, o value.PolicyGrantSettingsObservation) error {
	f.writes++
	f.seen = append(f.seen, o)
	if f.project != nil {
		f.project(ctx)
	}
	return f.storeErr
}
func newGrantSettingsFixture() (*grantSettingsFixture, *PolicyGrantSettingsObserver) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := value.Policy{Revision: value.Revision{UID: "identity-settings", Generation: 1, Digest: [32]byte{1}}, Issuer: "https://id.example.test", ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Clients: []value.Client{{ID: "console", Kind: value.Human, ClassQualified: true}}, EligibleGroups: []string{"team"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute}
	f := &grantSettingsFixture{now: now, policy: p}
	o := &PolicyGrantSettingsObserver{Issuer: p.Issuer, Source: f, Projection: f, Now: func() time.Time { return f.now }}
	return f, o
}
func TestPolicyGrantSettingsObserverPreservesCachedOriginalTimesAndDefaults(t *testing.T) {
	f, o := newGrantSettingsFixture()
	if err := o.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.writes != 1 || f.seen[0].Values != value.DefaultPolicyGrantApproval() || f.seen[0].ObservedAt != f.policy.ObservedAt || f.seen[0].FreshUntil != f.policy.FreshUntil {
		t.Fatal("default settings or original observation changed", f.seen)
	}
	f.now = f.now.Add(10 * time.Second)
	if err := o.Reconcile(context.Background()); err != nil || f.writes != 1 {
		t.Fatal("cached snapshot rewrote/refreshed projection", err, f.writes)
	}
	f.policy.ObservedAt, f.policy.FreshUntil = f.now, f.now.Add(30*time.Second)
	periods := value.PolicyGrantApproval{DefaultAge: time.Hour, MaxAge: 2 * time.Hour, RenewalNotice: time.Minute}
	f.policy.PolicyGrants = &periods
	f.policy.Revision.Generation++
	f.policy.Revision.Digest[0]++
	if err := o.Reconcile(context.Background()); err != nil || f.writes != 2 || f.seen[1].Values != periods {
		t.Fatal("new accepted candidate lost", err, f.seen)
	}
}
func TestPolicyGrantSettingsObserverRetriesUnknownProjectionWithoutRenewal(t *testing.T) {
	f, o := newGrantSettingsFixture()
	f.storeErr = errors.New("uncertain SQL reply")
	if err := o.Reconcile(context.Background()); err == nil || f.writes != 1 {
		t.Fatal("failure hidden", err)
	}
	first := f.seen[0]
	f.now = f.now.Add(time.Second)
	f.storeErr = nil
	if err := o.Reconcile(context.Background()); err != nil || f.writes != 2 || f.seen[1] != first {
		t.Fatal("unknown reply reset source times", err, f.seen)
	}
	if err := o.Reconcile(context.Background()); err != nil || f.writes != 2 {
		t.Fatal("acknowledged observation repeated SQL", err)
	}
}
func TestPolicyGrantSettingsObserverRejectsInvalidSourceAndPostBlockingExpiry(t *testing.T) {
	for _, name := range []string{"source-failure", "wrong-issuer", "invalid-period", "expired-source", "clock-rollback", "expires-during-write", "canceled"} {
		t.Run(name, func(t *testing.T) {
			f, o := newGrantSettingsFixture()
			call, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "source-failure":
				f.sourceErr = value.ErrUnavailable
			case "wrong-issuer":
				f.policy.Issuer = "https://other.example.test"
			case "invalid-period":
				p := value.DefaultPolicyGrantApproval()
				p.MaxAge = 0
				f.policy.PolicyGrants = &p
			case "expired-source":
				f.policy.FreshUntil = f.now
			case "clock-rollback":
				f.source = func(context.Context) { f.now = f.now.Add(-time.Second) }
			case "expires-during-write":
				f.project = func(context.Context) { f.now = f.policy.FreshUntil }
			case "canceled":
				cancel()
			}
			if err := o.Reconcile(call); err == nil {
				t.Fatal("unavailable setting supplied")
			}
			if name != "expires-during-write" && f.writes != 0 {
				t.Fatal("invalid source reached projection")
			}
			if o.accepted != (value.PolicyGrantSettingsObservation{}) {
				t.Fatal("unacknowledged/expired observation cached")
			}
		})
	}
}
func TestPolicyGrantSettingsObserverJoinsCancellationAndKeepsFailuresLocal(t *testing.T) {
	f, o := newGrantSettingsFixture()
	started := make(chan struct{})
	f.source = func(ctx context.Context) { close(started); <-ctx.Done() }
	call, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); o.Run(call, nil) }()
	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("observer retained source read after lease cancellation")
	}
	if f.writes != 0 {
		t.Fatal("canceled source reached SQL")
	}
	f, o = newGrantSettingsFixture()
	f.sourceErr = value.ErrUnavailable
	call, cancel = context.WithCancel(context.Background())
	defer cancel()
	reported := make(chan error, 1)
	done = make(chan struct{})
	go func() { defer close(done); o.Run(call, func(err error) { reported <- err }) }()
	if err := <-reported; err == nil {
		t.Fatal("local failure not reported")
	}
	select {
	case <-done:
		t.Fatal("source failure terminated supervised observer")
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("observer did not join")
	}
}
