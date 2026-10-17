package identity

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

// These local safety bounds are additional ceilings, not installation backing.
// SQL43's union with accepted browser sessions supplies the global bound.
const maxLocalRefreshOwners = 128
const maxLocalRefreshAdmissions = 16
const refreshPoll = time.Second

type BrowserRefreshOwners struct {
	ctx            context.Context
	cancel         context.CancelFunc
	sessions       BrowserSessions
	journal        RefreshOwnerJournal
	binding        value.RefreshProcessBinding
	origin         string
	now            func() time.Time
	newID          func() string
	mu             sync.Mutex
	closed         bool
	reserved       int
	owners         map[[32]byte]*browserRefreshOwner
	admissions     chan struct{}
	admissionLocks map[[32]byte]*refreshAdmissionLock
	work           sync.WaitGroup
}
type refreshAdmissionLock struct {
	token chan struct{}
	users int
}
type browserRefreshOwner struct {
	historical sync.Mutex
	ref        value.RefreshOwnerRef
	pin        value.RefreshSessionPin
	stop       context.CancelFunc
	done       chan struct{}
	// These fields are touched only by the owning loop until done closes. They
	// retain exact possible spend when closure acknowledgement is unavailable.
	pendingClaim   [32]byte
	pendingVersion int64
	closureError   error
	unstarted      bool
}

func NewBrowserRefreshOwners(ctx context.Context, sessions BrowserSessions, journal RefreshOwnerJournal, binding value.RefreshProcessBinding, origin string, newID func() string) (*BrowserRefreshOwners, error) {
	if ctx == nil || ctx.Err() != nil || !sessions.configured() || journal == nil || !binding.Valid() || binding.Epoch != sessions.Epoch || !value.Text(origin, 2048) || newID == nil {
		return nil, value.ErrUnavailable
	}
	parsed, e := url.Parse(origin)
	if e != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, value.ErrInvalid
	}
	if _, ok := sessions.Identities.(CredentialSchedulePolicy); !ok {
		return nil, value.ErrUnavailable
	}
	if _, ok := sessions.Identities.(CredentialObserver); !ok {
		return nil, value.ErrUnavailable
	}
	c, cancel := context.WithCancel(ctx)
	return &BrowserRefreshOwners{ctx: c, cancel: cancel, sessions: sessions, journal: journal, binding: binding, origin: origin, now: sessions.Now, newID: newID, owners: make(map[[32]byte]*browserRefreshOwner), admissions: make(chan struct{}, maxLocalRefreshAdmissions), admissionLocks: make(map[[32]byte]*refreshAdmissionLock)}, nil
}

// Admit belongs exclusively to an actual exact-origin, CSRF-protected explicit
// prepare/download POST. The current SQL journal independently checks the same
// accepted download and principal. A public GET cannot call this path.
func (s *BrowserRefreshOwners) Admit(ctx context.Context, origin, cookie, csrf, downloadID string) (value.RefreshOwnerObservation, error) {
	var zero value.RefreshOwnerObservation
	if s == nil || ctx == nil || ctx.Err() != nil || origin != s.origin || s.ctx.Err() != nil {
		return zero, value.ErrDenied
	}
	select {
	case s.admissions <- struct{}{}:
		defer func() { <-s.admissions }()
	default:
		return zero, value.ErrSessionCapacity
	}
	// Joining shutdown includes pre-admission work; no detached provider request
	// can disappear from process accounting while an authenticated POST blocks.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return zero, value.ErrDenied
	}
	s.work.Add(1)
	s.mu.Unlock()
	defer s.work.Done()
	operation, stop := context.WithCancel(ctx)
	defer stop()
	unlink := context.AfterFunc(s.ctx, stop)
	defer unlink()
	if err := s.sessions.CheckCSRF(operation, cookie, csrf); err != nil {
		return zero, err
	}
	current, view, err := NewBrowserRequest(operation, s.sessions, cookie, false, s.now)
	if err != nil {
		return zero, err
	}
	key, err := sessionKey(cookie)
	if err != nil {
		return zero, err
	}
	release, err := s.lockAdmission(operation, key)
	if err != nil {
		return zero, err
	}
	defer release()
	record, err := s.sessions.Store.ReadSession(operation, key)
	if err != nil || !record.Current(s.now()) || record.Principal != view.Identity.Principal || record.ExpiresAt.After(view.ExpiresAt) {
		return zero, value.ErrDenied
	}
	pin := value.RefreshSessionPin{ID: key, Principal: record.Principal, ProviderSession: record.ProviderSession, CreatedAt: record.CreatedAt, AuthenticatedAt: record.AuthenticatedAt, ExpiresAt: record.ExpiresAt}
	s.mu.Lock()
	existing := s.owners[key]
	full := len(s.owners) >= maxLocalRefreshOwners
	s.mu.Unlock()
	if existing != nil {
		select {
		case <-existing.done:
			if err = s.closeHistorical(existing); err != nil {
				return zero, err
			}
			s.mu.Lock()
			if s.owners[key] == existing {
				delete(s.owners, key)
			}
			s.mu.Unlock()
			existing = nil
			full = false // We just released this owner's existing local slot.
		default:
		}
	}
	if existing == nil && full {
		return zero, value.ErrSessionCapacity
	}
	if existing == nil {
		s.mu.Lock()
		if len(s.owners)+s.reserved >= maxLocalRefreshOwners {
			s.mu.Unlock()
			return zero, value.ErrSessionCapacity
		}
		s.reserved++
		s.mu.Unlock()
		defer func() { s.mu.Lock(); s.reserved--; s.mu.Unlock() }()
	}
	proposed := value.RefreshOwnerRef{RootID: s.binding.RootID, Epoch: s.binding.Epoch, OwnerID: s.newID(), InstallationID: s.binding.InstallationID, ClusterID: s.binding.ClusterID, PodUID: s.binding.PodUID, ProcessEpoch: s.binding.ProcessEpoch, SessionID: key, Generation: 1}
	if !proposed.Valid() {
		return zero, value.ErrUnavailable
	}
	abandon := func() {
		if existing != nil {
			return
		}
		temporary := &browserRefreshOwner{ref: proposed, pin: pin, done: make(chan struct{}), unstarted: true}
		temporary.closureError = s.closeHistorical(temporary)
		close(temporary.done)
		if temporary.closureError != nil {
			s.mu.Lock()
			s.owners[key] = temporary
			s.mu.Unlock()
		}
	}
	admitted, err := s.journal.AdmitBrowserRefresh(operation, current, pin, proposed, downloadID)
	if err != nil {
		// The synchronous SQL callback has joined. Abandon takes the same root
		// lock, so an already-sent mutation/COMMIT must settle before absence
		// or exact unstarted closure can be acknowledged.
		abandon()
		return zero, err
	} // Unknown admission never launches work.
	if !admitted.Valid(s.now()) || !s.binding.Owns(admitted.Owner) || admitted.Owner.SessionID != key || admitted.SessionEnd.After(pin.ExpiresAt) {
		abandon()
		return zero, value.ErrDenied
	}
	if _, err = current.ResolveIdentity(operation); err != nil || operation.Err() != nil {
		abandon()
		return zero, value.ErrDenied
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || operation.Err() != nil {
		s.mu.Unlock()
		abandon()
		return zero, value.ErrDenied
	}
	if owner := s.owners[key]; owner != nil {
		same := owner.ref == admitted.Owner
		s.mu.Unlock()
		if !same {
			return zero, value.ErrSessionBusy
		}
		select {
		case <-owner.done:
			return zero, value.ErrSessionBusy
		default:
		}
		return admitted, nil
	}
	if len(s.owners) >= maxLocalRefreshOwners {
		s.mu.Unlock()
		abandon()
		return zero, value.ErrSessionCapacity
	}
	owned, cancel := context.WithCancel(s.ctx)
	owner := &browserRefreshOwner{ref: admitted.Owner, pin: pin, stop: cancel, done: make(chan struct{})}
	s.owners[key] = owner
	s.work.Add(1)
	s.mu.Unlock()
	go s.run(owned, owner)
	return admitted, nil
}

func (s *BrowserRefreshOwners) run(ctx context.Context, owner *browserRefreshOwner) {
	defer s.work.Done()
	defer func() {
		owner.closureError = s.closeHistorical(owner)
		close(owner.done)
		if owner.closureError == nil {
			s.mu.Lock()
			if s.owners[owner.pin.ID] == owner {
				delete(s.owners, owner.pin.ID)
			}
			s.mu.Unlock()
		}
	}()
	nextAttempt := time.Time{}
	var schedule refreshSessionSchedule
	for {
		if ctx.Err() != nil || !s.now().Before(owner.pin.ExpiresAt) {
			return
		}
		observe, cancel := context.WithTimeout(ctx, 5*time.Second)
		demand, err := s.journal.ObserveBrowserRefresh(observe, owner.ref)
		if err == nil && (!demand.Valid(s.now()) || demand.Owner.Owner != owner.ref) {
			err = value.ErrDenied
		}
		var record value.BrowserSession
		if err == nil {
			record, err = s.sessions.Store.ReadSession(observe, owner.pin.ID)
		}
		if err == nil && !owner.pin.Matches(record, s.now()) {
			err = value.ErrDenied
		}
		if err == nil && schedule.Version != record.Version {
			_, err = s.sessions.resolveKey(observe, owner.pin.ID, false, &schedule)
		}
		if err == nil {
			schedule.Window, err = s.sessions.Identities.(CredentialSchedulePolicy).ShortenCredentialWindow(observe, owner.pin.Principal, schedule.Window)
			if err == nil {
				schedule.RefreshAt = value.Earlier(record.RefreshAt, schedule.Window.RefreshAt(record.ExpiresAt))
			}
		}
		cancel()
		if err != nil {
			return
		}
		if record.ExpiresAt.Before(owner.pin.ExpiresAt) {
			owner.pin.ExpiresAt = record.ExpiresAt
		}
		if !s.now().Before(schedule.RefreshAt) {
			// Unsupported cadence stops; it never becomes a tight provider loop or an
			// artificial extension of token/group/session freshness.
			if s.now().Before(nextAttempt) {
				return
			}
			until := value.Earlier(demand.HardUntil, value.Earlier(demand.Owner.LeaseUntil, s.now().Add(value.RefreshClaimWindow)))
			call, stop := context.WithDeadline(ctx, until)
			store := &ownedRefreshStore{BrowserSessionStore: s.sessions.Store, journal: s.journal, owner: owner, demand: demand, now: s.now, sessions: s.sessions}
			sessions := s.sessions
			sessions.Store = store
			_, err = sessions.resolveKey(call, owner.pin.ID, true, &schedule)
			stop()
			if owner.pendingClaim != ([32]byte{}) {
				if joined := s.joinClaim(owner); joined != nil {
					return
				}
			}
			if err != nil {
				return
			}
			if schedule.Pin.Principal != owner.pin.Principal || schedule.Pin.ExpiresAt.After(owner.pin.ExpiresAt) {
				return
			}
			nextAttempt = s.now().Add(time.Second)
			if !schedule.RefreshAt.After(nextAttempt) {
				return
			}
		}
		timer := time.NewTimer(refreshPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

type ownedRefreshStore struct {
	sessions BrowserSessions
	BrowserSessionStore
	journal RefreshOwnerJournal
	owner   *browserRefreshOwner
	demand  value.RefreshDemand
	now     func() time.Time
}

func (s *ownedRefreshStore) ReadSession(ctx context.Context, key [32]byte) (value.BrowserSession, error) {
	r, err := s.BrowserSessionStore.ReadSession(ctx, key)
	if err != nil {
		return value.BrowserSession{}, err
	}
	if key != s.owner.pin.ID || !s.owner.pin.Matches(r, s.now()) {
		return value.BrowserSession{}, value.ErrDenied
	}
	return r, nil
}
func (s *ownedRefreshStore) ClaimRefresh(ctx context.Context, key [32]byte, version int64, claim [32]byte) error {
	if key != s.owner.pin.ID || claim == ([32]byte{}) || version < 1 || !s.demand.Valid(s.now()) {
		return value.ErrDenied
	}
	s.owner.pendingClaim, s.owner.pendingVersion = claim, version
	return value.ErrDenied // Owned callers must supply the just-verified identity.
}
func (s *ownedRefreshStore) ClaimCurrentRefresh(ctx context.Context, key [32]byte, version int64, claim [32]byte, initial value.Identity) error {
	if key != s.owner.pin.ID || initial.Principal != s.owner.pin.Principal || !initial.Valid(s.now()) || claim == ([32]byte{}) || !s.demand.Valid(s.now()) {
		return value.ErrDenied
	}
	resolve := func(c context.Context) (value.Identity, error) {
		view, err := s.sessions.resolveKey(c, key, false, nil)
		return view.Identity, err
	}
	current, _, err := bindCurrentRequest(ctx, s.now(), initial, resolve, s.now)
	if err != nil {
		return err
	}
	s.owner.pendingClaim, s.owner.pendingVersion = claim, version
	return s.journal.ClaimBrowserOwnedRefresh(ctx, current, s.demand, version, claim)
}

func (s *BrowserRefreshOwners) joinClaim(owner *browserRefreshOwner) error {
	owner.historical.Lock()
	defer owner.historical.Unlock()
	return s.joinClaimLocked(owner)
}
func (s *BrowserRefreshOwners) joinClaimLocked(owner *browserRefreshOwner) error {
	if owner.pendingClaim == ([32]byte{}) {
		return nil
	}
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := s.journal.JoinBrowserRefreshClaim(cleanup, owner.ref, owner.pendingVersion, owner.pendingClaim); err != nil {
		return err
	}
	owner.pendingClaim = [32]byte{}
	owner.pendingVersion = 0
	return nil
}
func (s *BrowserRefreshOwners) closeHistorical(owner *browserRefreshOwner) error {
	owner.historical.Lock()
	defer owner.historical.Unlock()
	if owner.unstarted {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		return s.journal.AbandonBrowserRefreshAdmission(cleanup, owner.ref)
	}
	if err := s.joinClaimLocked(owner); err != nil {
		return err
	}
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	return s.journal.CloseBrowserRefreshOwner(cleanup, owner.ref)
}

// Close cancels and joins every admitted/closing observer and provider call.
// A failed SQL acknowledgement remains charged. Neither caller cancellation nor
// a timeout reports joined success while an adapter is still running.
func (s *BrowserRefreshOwners) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.work.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	var result error
	for _, owner := range s.owners {
		if err := s.closeHistorical(owner); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

// Only admitted HTTP calls create these short in-memory locks. Their total is
// bounded by maxLocalRefreshAdmissions; no user-controlled permanent key map.
func (s *BrowserRefreshOwners) lockAdmission(ctx context.Context, key [32]byte) (func(), error) {
	s.mu.Lock()
	l := s.admissionLocks[key]
	if l == nil {
		l = &refreshAdmissionLock{token: make(chan struct{}, 1)}
		l.token <- struct{}{}
		s.admissionLocks[key] = l
	}
	l.users++
	s.mu.Unlock()
	drop := func() {
		s.mu.Lock()
		l.users--
		if l.users == 0 {
			delete(s.admissionLocks, key)
		}
		s.mu.Unlock()
	}
	select {
	case <-ctx.Done():
		drop()
		return nil, value.ErrDenied
	case <-s.ctx.Done():
		drop()
		return nil, value.ErrDenied
	case <-l.token:
	}
	return func() { l.token <- struct{}{}; drop() }, nil
}
