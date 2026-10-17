package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The provider, encrypted SQL credential store, existing one-use SQL claim and
// C02 ownership loop are real. This fixture-only scheduling journal stands in
// for already accepted C14 demand/process authority; the SQL43 test separately
// qualifies durable owner/consumer admission against actual accepted downloads.
type providerOwnerJournal struct {
	mu                     sync.Mutex
	store                  *postgres.BrowserSessions
	owner                  identity.RefreshOwnerObservation
	demand                 identity.RefreshDemand
	joined                 chan struct{}
	closed                 chan struct{}
	joinedOnce, closedOnce sync.Once
	claims                 int
}

func (j *providerOwnerJournal) AdmitBrowserRefresh(ctx context.Context, c app.CurrentIdentity, p identity.RefreshSessionPin, r identity.RefreshOwnerRef, d string) (identity.RefreshOwnerObservation, error) {
	i, e := c.ResolveIdentity(ctx)
	if e != nil || i.Principal != p.Principal {
		return identity.RefreshOwnerObservation{}, identity.ErrDenied
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	n := time.Now()
	j.owner = identity.RefreshOwnerObservation{Owner: r, SessionEnd: p.ExpiresAt, LeaseUntil: n.Add(15 * time.Second), ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}
	j.demand = identity.RefreshDemand{Owner: j.owner, DownloadID: d, HardUntil: identity.Earlier(n.Add(30*time.Second), p.ExpiresAt), GraceUntil: identity.Earlier(n.Add(30*time.Second), p.ExpiresAt)}
	return j.owner, nil
}
func (j *providerOwnerJournal) ObserveBrowserRefresh(_ context.Context, r identity.RefreshOwnerRef) (identity.RefreshDemand, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	select {
	case <-j.joined:
		return identity.RefreshDemand{}, identity.ErrDenied
	default:
	}
	if r != j.owner.Owner {
		return identity.RefreshDemand{}, identity.ErrDenied
	}
	n := time.Now()
	out := j.demand
	out.Owner.ObservedAt = n
	out.Owner.ValidUntil = n.Add(5 * time.Second)
	out.Owner.LeaseUntil = n.Add(15 * time.Second)
	return out, nil
}
func (j *providerOwnerJournal) ClaimBrowserOwnedRefresh(ctx context.Context, c app.CurrentIdentity, d identity.RefreshDemand, v int64, k [32]byte) error {
	if _, e := c.ResolveIdentity(ctx); e != nil {
		return e
	}
	j.mu.Lock()
	j.claims++
	j.mu.Unlock()
	return j.store.ClaimRefresh(ctx, d.Owner.Owner.SessionID, v, k)
}
func (j *providerOwnerJournal) JoinBrowserRefreshClaim(context.Context, identity.RefreshOwnerRef, int64, [32]byte) error {
	j.joinedOnce.Do(func() { close(j.joined) })
	return nil
}
func (j *providerOwnerJournal) CloseBrowserRefreshOwner(context.Context, identity.RefreshOwnerRef) error {
	j.closedOnce.Do(func() { close(j.closed) })
	return nil
}
func qualifyBrowserRefreshProvider(t *testing.T, admin *pgxpool.Pool, sessions app.BrowserSessions, store *postgres.BrowserSessions, root, origin, cookie, csrf string) {
	t.Helper()
	ctx := t.Context()
	key := sha256.Sum256([]byte(cookie))
	before, e := store.ReadSession(ctx, key)
	if e != nil {
		t.Fatal(e)
	}
	provider := &browserRefreshObserver{BrowserProvider: sessions.Provider}
	sessions.Provider = provider
	j := &providerOwnerJournal{store: store, joined: make(chan struct{}), closed: make(chan struct{})}
	b := identity.RefreshProcessBinding{RootID: root, Epoch: sessions.Epoch, InstallationID: custodyID(), ClusterID: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID()}
	owners, e := app.NewBrowserRefreshOwners(ctx, sessions, j, b, origin, custodyID)
	if e != nil {
		t.Fatal(e)
	}
	defer owners.Close()
	// Fixture makes the real current credential due. Only this explicit consent
	// call creates a continuation; there is no tab timer or GET refresh thereafter.
	if _, e = admin.Exec(ctx, "UPDATE browser_session SET refresh_at=created_at+interval '1 microsecond' WHERE root_id=$1 AND id=$2", root, key[:]); e != nil {
		t.Fatal(e)
	}
	if _, e = owners.Admit(ctx, origin, cookie, csrf, custodyID()); e != nil {
		t.Fatal("explicit POST owner", e)
	}
	select {
	case <-j.joined:
	case <-time.After(10 * time.Second):
		t.Fatal("actual provider refresh did not join without browser polling")
	}
	if e = owners.Close(); e != nil {
		t.Fatal(e)
	}
	after, e := store.ReadSession(ctx, key)
	if e != nil || after.Version != before.Version+1 || !after.ExpiresAt.Equal(before.ExpiresAt) || after.Principal != before.Principal || provider.refreshes.Load() != 1 {
		t.Fatal("automatic refresh changed identity/deadline or repeated token", e)
	}
	j.mu.Lock()
	claims := j.claims
	j.mu.Unlock()
	if claims != 1 {
		t.Fatal("owned SQL credential claim count", claims)
	}
	view, e := sessions.Resolve(ctx, cookie, false)
	if e != nil || view.Identity.Principal != before.Principal || provider.refreshes.Load() != 1 {
		t.Fatal("read-only identity did not use new current credential", e)
	}
	if e = store.RevokeSession(ctx, key); e != nil {
		t.Fatal(e)
	}
	if _, e = sessions.Resolve(ctx, cookie, false); !errors.Is(e, identity.ErrDenied) {
		t.Fatal("joined owner revived logout", e)
	}
	t.Log("actual Keycloak/SQL/OpenBao one-use refresh continues after explicit POST without tab polling; fixed session and read-only GET preserved; accepted download/process journal is synthetic and no native bytes transferred")
}

func (j *providerOwnerJournal) AbandonBrowserRefreshAdmission(context.Context, identity.RefreshOwnerRef) error {
	return nil
}
