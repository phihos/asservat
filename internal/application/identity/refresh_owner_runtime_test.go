package identity

import (
	value "asservat.local/asservat/internal/domain/identity"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

type ownerTestStore struct {
	BrowserSessionStore
	mu      sync.Mutex
	row     value.BrowserSession
	claim   [32]byte
	revoked bool
}

func (s *ownerTestStore) ReadSession(_ context.Context, key [32]byte) (value.BrowserSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || key != s.row.ID {
		return value.BrowserSession{}, value.ErrDenied
	}
	if s.claim != ([32]byte{}) {
		return value.BrowserSession{}, value.ErrSessionBusy
	}
	r := s.row
	n := time.Now()
	r.Observation.ObservedAt = n
	r.Observation.FreshUntil = n.Add(5 * time.Second)
	return r, nil
}
func (s *ownerTestStore) ReadSessionForCSRF(_ context.Context, key [32]byte) (value.BrowserSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || key != s.row.ID {
		return value.BrowserSession{}, value.ErrDenied
	}
	return s.row, nil
}
func (s *ownerTestStore) FinishRefresh(_ context.Context, key [32]byte, version int64, claim [32]byte, blob []byte, due time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || s.row.ID != key || s.row.Version != version || s.claim != claim {
		return value.ErrDenied
	}
	s.row.Version++
	s.claim = [32]byte{}
	s.row.Ciphertext = blob
	s.row.RefreshAt = due
	return nil
}

type ownerTestCipher struct{}

func (ownerTestCipher) Encrypt(_ context.Context, b, _ []byte) ([]byte, error) {
	return append([]byte{}, b...), nil
}
func (ownerTestCipher) Decrypt(_ context.Context, b, _ []byte) ([]byte, error) {
	return append([]byte{}, b...), nil
}

type ownerTestIdentity struct{ principal value.Principal }

func (s ownerTestIdentity) Resolve(ctx context.Context, token string) (value.Identity, error) {
	o, e := s.ObserveCredential(ctx, token)
	return o.Identity, e
}
func (s ownerTestIdentity) ObserveCredential(_ context.Context, _ string) (CredentialObservation, error) {
	n := time.Now()
	i := requestIdentity(n)
	i.Principal = s.principal
	return CredentialObservation{Identity: i, Window: CredentialWindow{IssuedAt: n, TokenExpiresAt: n.Add(time.Minute), GroupsExpireAt: n.Add(time.Minute), Policy: i.Policy, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}}, nil
}

type ownerTestProvider struct {
	BrowserProvider
	entered, release chan struct{}
	row              value.BrowserSession
}

func (p ownerTestProvider) Refresh(_ context.Context, _ string, subject, sid, _ string) (BrowserTokens, error) {
	close(p.entered)
	<-p.release
	n := time.Now()
	return BrowserTokens{Access: "new", Refresh: "new-refresh", Subject: subject, SessionID: sid, IssuedAt: n, ExpiresAt: n.Add(time.Minute), AuthenticatedAt: p.row.AuthenticatedAt}, nil
}

type ownerTestJournal struct {
	RefreshOwnerJournal
	mu                    sync.Mutex
	store                 *ownerTestStore
	view                  value.RefreshOwnerObservation
	claims, joins, closes int
	joinedBeforeProvider  bool
	providerDone          <-chan struct{}
	observeErr            error
	closeErr              error
	admitErr, abandonErr  error
	admissions, abandons  int
	lastAbandon           value.RefreshOwnerRef
}

func (j *ownerTestJournal) AdmitBrowserRefresh(_ context.Context, current CurrentIdentity, pin value.RefreshSessionPin, r value.RefreshOwnerRef, download string) (value.RefreshOwnerObservation, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	n := time.Now()
	j.view = value.RefreshOwnerObservation{Owner: r, SessionEnd: pin.ExpiresAt, LeaseUntil: n.Add(15 * time.Second), ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}
	j.admissions++
	return j.view, j.admitErr
}
func (j *ownerTestJournal) ObserveBrowserRefresh(_ context.Context, ref value.RefreshOwnerRef) (value.RefreshDemand, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.observeErr != nil {
		return value.RefreshDemand{}, j.observeErr
	}
	n := time.Now()
	j.view.ObservedAt = n
	j.view.ValidUntil = n.Add(5 * time.Second)
	j.view.LeaseUntil = n.Add(15 * time.Second)
	return value.RefreshDemand{Owner: j.view, DownloadID: refreshUUID(), HardUntil: j.view.SessionEnd, GraceUntil: n.Add(30 * time.Second)}, nil
}
func (j *ownerTestJournal) ClaimBrowserOwnedRefresh(ctx context.Context, current CurrentIdentity, d value.RefreshDemand, version int64, claim [32]byte) error {
	if _, e := current.ResolveIdentity(ctx); e != nil {
		return e
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.store.mu.Lock()
	defer j.store.mu.Unlock()
	if j.store.revoked || j.store.row.Version != version || j.store.claim != ([32]byte{}) {
		return value.ErrDenied
	}
	j.store.claim = claim
	j.claims++
	return nil
}
func (j *ownerTestJournal) JoinBrowserRefreshClaim(context.Context, value.RefreshOwnerRef, int64, [32]byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	select {
	case <-j.providerDone:
	default:
		j.joinedBeforeProvider = true
	}
	j.joins++
	return nil
}
func (j *ownerTestJournal) CloseBrowserRefreshOwner(context.Context, value.RefreshOwnerRef) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.closes++
	return j.closeErr
}
func ownerFixture(t *testing.T) (*BrowserRefreshOwners, *ownerTestStore, *ownerTestJournal, ownerTestProvider, string, string) {
	t.Helper()
	n := time.Now()
	cookie, csrf := randomSessionSecret(), randomSessionSecret()
	key, _ := sessionKey(cookie)
	p := requestIdentity(n).Principal
	blob, _ := json.Marshal(sessionSecrets{Access: "old", Refresh: "old-refresh", CSRF: csrf, Nonce: "nonce"})
	store := &ownerTestStore{row: value.BrowserSession{ID: key, Principal: p, ProviderSession: "provider", Ciphertext: blob, CreatedAt: n.Add(-time.Minute), AuthenticatedAt: n.Add(-time.Minute), ExpiresAt: n.Add(time.Hour), RefreshAt: n.Add(-time.Second), Version: 1, Observation: value.SessionObservation{Settings: value.Revision{UID: "settings", Generation: 1, Digest: [32]byte{1}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}}}
	provider := ownerTestProvider{entered: make(chan struct{}), release: make(chan struct{}), row: store.row}
	journal := &ownerTestJournal{store: store, providerDone: provider.release}
	sessions := BrowserSessions{Store: store, Cipher: ownerTestCipher{}, Provider: provider, Identities: ownerTestIdentity{p}, Issuer: p.Issuer, ClientID: p.ClientID, Epoch: refreshUUID(), Lifetime: time.Hour, Now: time.Now}
	b := value.RefreshProcessBinding{RootID: refreshUUID(), Epoch: refreshUUID(), InstallationID: refreshUUID(), ClusterID: refreshUUID(), PodUID: refreshUUID(), ProcessEpoch: refreshUUID()}
	owners, e := NewBrowserRefreshOwners(t.Context(), sessions, journal, b, "https://console.invalid", refreshUUID)
	if e != nil {
		t.Fatal(e)
	}
	return owners, store, journal, provider, cookie, csrf
}
func TestRefreshOwnerShutdownJoinsActualProviderAndNeverAdoptsLogout(t *testing.T) {
	owners, store, journal, provider, cookie, csrf := ownerFixture(t)
	if _, e := owners.Admit(t.Context(), "https://console.invalid", cookie, csrf, refreshUUID()); e != nil {
		t.Fatal(e)
	}
	select {
	case <-provider.entered:
	case <-time.After(time.Second):
		t.Fatal("POST owner never called provider")
	}
	store.mu.Lock()
	store.revoked = true
	store.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- owners.Close() }()
	select {
	case e := <-done:
		t.Fatal("shutdown refunded blocked refresh", e)
	case <-time.After(20 * time.Millisecond):
	}
	close(provider.release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.claims != 1 || journal.joins != 1 || journal.closes != 1 || journal.joinedBeforeProvider {
		t.Fatal("provider work/spend incorrectly joined", journal.claims, journal.joins, journal.closes, journal.joinedBeforeProvider)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.row.Version != 1 || store.claim == ([32]byte{}) {
		t.Fatal("logout allowed replacement or claim reuse")
	}
}
func TestRefreshOwnerAdmissionRequiresExactPOSTConsent(t *testing.T) {
	owners, _, journal, _, cookie, csrf := ownerFixture(t)
	defer owners.Close()
	for _, v := range [][3]string{{"https://other.invalid", cookie, csrf}, {"https://console.invalid", cookie, randomSessionSecret()}} {
		if _, e := owners.Admit(t.Context(), v[0], v[1], v[2], refreshUUID()); e == nil {
			t.Fatal("invalid POST consent admitted")
		}
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.view.Owner.Valid() {
		t.Fatal("invalid consent reached durable admission")
	}
}
func TestRefreshOwnerFailedClosureStaysCounted(t *testing.T) {
	owners, _, journal, provider, cookie, csrf := ownerFixture(t)
	journal.observeErr = value.ErrDenied
	journal.closeErr = errors.New("synthetic unknown close")
	if _, e := owners.Admit(t.Context(), "https://console.invalid", cookie, csrf, refreshUUID()); e != nil {
		t.Fatal(e)
	}
	key, _ := sessionKey(cookie)
	owners.mu.Lock()
	owner := owners.owners[key]
	owners.mu.Unlock()
	<-owner.done
	if e := owners.Close(); e == nil {
		t.Fatal("unknown close hidden")
	}
	owners.mu.Lock()
	defer owners.mu.Unlock()
	if len(owners.owners) != 1 {
		t.Fatal("unknown closure refunded local owner")
	}
	select {
	case <-provider.entered:
		t.Fatal("denied demand refreshed")
	default:
	}
}

// A stricter accepted group-age policy must wake the already admitted owner
// without depending on a browser tab, provider refresh, or byte-chunk polling.
type shortenedOwnerIdentity struct {
	ownerTestIdentity
	mu        sync.Mutex
	shortened bool
}

func (s *shortenedOwnerIdentity) ObserveCredential(ctx context.Context, token string) (CredentialObservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, e := s.ownerTestIdentity.ObserveCredential(ctx, token)
	v.Window.IssuedAt = v.Window.IssuedAt.Add(-10 * time.Second)
	if s.shortened {
		v.Window.GroupsExpireAt = v.Window.IssuedAt.Add(15 * time.Second)
	}
	return v, e
}
func (s *shortenedOwnerIdentity) ShortenCredentialWindow(_ context.Context, p value.Principal, w CredentialWindow) (CredentialWindow, error) {
	s.mu.Lock()
	s.shortened = true
	s.mu.Unlock()
	n := time.Now()
	w.GroupsExpireAt = value.Earlier(w.GroupsExpireAt, w.IssuedAt.Add(15*time.Second))
	w.ObservedAt = n
	w.FreshUntil = n.Add(5 * time.Second)
	return w, nil
}
func TestRefreshOwnerCurrentPolicyShortensScheduleWithoutAnotherPOST(t *testing.T) {
	owners, store, _, provider, cookie, csrf := ownerFixture(t)
	store.row.RefreshAt = time.Now().Add(45 * time.Second)
	owners.sessions.Identities = &shortenedOwnerIdentity{ownerTestIdentity: ownerTestIdentity{store.row.Principal}}
	defer func() { close(provider.release); _ = owners.Close() }()
	if _, e := owners.Admit(t.Context(), "https://console.invalid", cookie, csrf, refreshUUID()); e != nil {
		t.Fatal(e)
	}
	select {
	case <-provider.entered:
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("current group deadline waited for another POST or persisted due time")
	}
}

func (s ownerTestIdentity) ShortenCredentialWindow(_ context.Context, _ value.Principal, w CredentialWindow) (CredentialWindow, error) {
	n := time.Now()
	w.ObservedAt = n
	w.FreshUntil = n.Add(5 * time.Second)
	return w, nil
}

func (j *ownerTestJournal) AbandonBrowserRefreshAdmission(_ context.Context, r value.RefreshOwnerRef) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.abandons++
	j.lastAbandon = r
	return j.abandonErr
}
func TestRefreshOwnerUnknownAdmissionKeepsExactClosingProposalUntilAcknowledged(t *testing.T) {
	owners, _, journal, provider, cookie, csrf := ownerFixture(t)
	journal.admitErr = value.ErrUnavailable
	journal.abandonErr = value.ErrUnavailable
	if _, e := owners.Admit(t.Context(), "https://console.invalid", cookie, csrf, refreshUUID()); e == nil {
		t.Fatal("unknown admission hidden")
	}
	journal.mu.Lock()
	first := journal.lastAbandon
	admissions := journal.admissions
	journal.mu.Unlock()
	key, _ := sessionKey(cookie)
	owners.mu.Lock()
	retained := owners.owners[key]
	reserved := owners.reserved
	owners.mu.Unlock()
	if retained == nil || !retained.unstarted || retained.ref != first || reserved != 0 {
		t.Fatal("unknown closing proposal lost bounded ownership")
	}
	if _, e := owners.Admit(t.Context(), "https://console.invalid", cookie, csrf, refreshUUID()); e == nil {
		t.Fatal("unknown closure permitted another proposal")
	}
	journal.mu.Lock()
	if journal.admissions != admissions || journal.lastAbandon != first {
		t.Fatal("old admission retried with new identity")
	}
	journal.abandonErr = nil
	journal.admitErr = nil
	journal.observeErr = value.ErrDenied
	journal.mu.Unlock()
	if _, e := owners.Admit(t.Context(), "https://console.invalid", cookie, csrf, refreshUUID()); e != nil {
		t.Fatal("acknowledged closure did not permit explicit fresh POST", e)
	}
	if e := owners.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-provider.entered:
		t.Fatal("unknown admission started provider")
	default:
	}
}
