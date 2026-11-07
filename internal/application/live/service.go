// Package live owns finite viewer sessions. It has no acquisition, snapshot,
// recording mutation, object-store payload or raw-content port.
package live

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
)

type CurrentIdentity = identities.CurrentIdentity

// Sources checks current viewer maintainer/read rights and original audience, source executor,
// live feature/region/current source lease independently. It must never use an
// evidence share as source authority, start a collector or select replacements.
type Sources interface {
	// Resolve is reached only after the reference MAC has passed. The source
	// adapter checks current rights before its full protected source lookup.
	Resolve(context.Context, CurrentIdentity, string, string, string) (v.Source, time.Time, error)
	Inventory(context.Context, CurrentIdentity, targets.WorkloadRequest, string, int) ([]v.Source, string, error)
	Check(context.Context, CurrentIdentity, v.Source, string) (v.Source, time.Time, error)
}

// ProjectionReader is the existing-source nonblocking projection boundary.
// Read receives only fixed source epochs and original remaining read authority.
// It cannot pin the ring. A failed/unknown connection returns no cached payload.
type ProjectionReader interface {
	Head(context.Context, []v.Source, string) ([]v.Position, error)
	Read(context.Context, []v.Source, string, []v.Position, int, int, int) (Projection, error)
}
type Projection struct {
	Rows      []v.Row
	Positions []v.Position
	Sources   []v.SourceStatus
	Gaps      []v.Gap
	Examined  int
	Bytes     int64
}

// Control is minimized durable state. No source identity, filter, row, handle,
// cursor, principal text or payload may be added to this storage record.
type Control struct {
	ID                                       string
	OwnerID                                  string
	PrincipalKey, WorkloadKey, RequestDigest [32]byte
	Revision                                 int64
	State                                    string
	AcceptedAt, ExpiresAt, IdleUntil         time.Time
	OutputLimit, Spent                       int64
	BytesPerSecond                           int64
	Fence                                    string
}
type Ledger interface {
	// CurrentLive checks the original current owner/fence and reservation before
	// private data dispatch. It cannot refill spend or renew idle/hard deadlines.
	CurrentLive(context.Context, Control) error
	// Create applies installation/principal/workload slots and aggregate rolling
	// output reservations atomically; retries return the original ID, never refill.
	Create(context.Context, Control, string) (Control, bool, error)
	// Change compares original revision/fence, checks current DB time and charges
	// every delivered/replayed byte before returning. Closed/expired stays spent.
	Change(context.Context, Control, int64, int64) (Control, error)
}
type Config struct {
	RootID      string
	OwnerID     string
	Keys        Keys
	Now         func() time.Time
	NewID       func() string
	Limits      v.Limits
	MaxWatches  int
	MaxControls int
}
type replay struct {
	batch v.Batch
	next  string
	until time.Time
}
type session struct {
	lastCheck  time.Duration // diagnostics only: duration of the latest current() check
	cancelRead context.CancelFunc
	readJoined chan struct{}
	timer      *time.Timer
	ownerEnd   time.Time
	mu         sync.Mutex
	watch      v.Watch
	control    Control
	actor      identity.Principal
	selected   []v.Source
	filter     v.Filter
	positions  []v.Position
	position   uint64
	replay     map[string]replay
	gap        []v.Gap
	reading    bool
	updates    map[string]updateReceipt
}
type updateReceipt struct {
	digest [32]byte
	watch  v.Watch
}
type Service struct {
	closed   bool
	active   atomic.Int64
	starting int
	cfg      Config
	sources  Sources
	reader   ProjectionReader
	ledger   Ledger
	mu       sync.Mutex
	sessions map[string]*session
	opens    map[[32]byte]string
}

func New(c Config, s Sources, r ProjectionReader, l Ledger) (*Service, error) {
	if !authorization.UUID(c.RootID) || !authorization.UUID(c.OwnerID) || c.Keys == nil || c.Now == nil || c.NewID == nil || !c.Limits.Valid() || c.MaxWatches < 1 || c.MaxWatches > 4096 || c.MaxControls < c.MaxWatches || c.MaxControls > 1048576 || s == nil || r == nil || l == nil {
		return nil, fmt.Errorf("%w: service:127", v.ErrInvalid)
	}
	return &Service{cfg: c, sources: s, reader: r, ledger: l, sessions: map[string]*session{}, opens: map[[32]byte]string{}}, nil
}
func hash(value any) [32]byte { b, _ := json.Marshal(value); return sha256.Sum256(b) }
func (s *Service) actor(ctx context.Context, current CurrentIdentity) (identity.Identity, error) {
	if ctx == nil || ctx.Err() != nil || current == nil {
		return identity.Identity{}, fmt.Errorf("%w: service:134", v.ErrDenied)
	}
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.cfg.Now()) || !slices.Contains(i.Scopes, "evidence:read") {
		return identity.Identity{}, fmt.Errorf("%w: service:138", v.ErrDenied)
	}
	i.Groups = slices.Clone(i.Groups)
	i.Scopes = slices.Clone(i.Scopes)
	slices.Sort(i.Groups)
	slices.Sort(i.Scopes)
	return i, nil
}
func (s *Service) List(ctx context.Context, current CurrentIdentity, target targets.WorkloadRequest, cursor string, limit int) (v.SourcePage, string, error) {
	var zero v.SourcePage
	i, err := s.actor(ctx, current)
	if err != nil {
		return zero, "", err
	}
	if limit == 0 {
		limit = 20
	}
	if limit < 1 || limit > 100 || !target.Valid() {
		return zero, "", fmt.Errorf("%w: service:156", v.ErrInvalid)
	}
	// Requested limit is an upper bound. Existing source rows have longer
	// identities/handles than event rows; use the existing backend continuation
	// with a bounded page rather than generate an oversized public result.
	limit = min(limit, 20)
	sources, next, err := s.sources.Inventory(ctx, current, target, cursor, limit)
	if err != nil && !errors.Is(err, v.ErrDenied) && errors.Is(err, v.ErrUnavailable) {
		// An unavailable catalog/status read is not an access decision.
		return zero, "", fmt.Errorf("%w: %w: service:164: %v", v.ErrUnavailable, v.ErrTransient, err)
	}
	if err != nil || len(sources) > limit {
		return zero, "", fmt.Errorf("%w: service:164", v.ErrDenied)
	}
	final, err := s.actor(ctx, current)
	if err != nil || !sameLiveIdentity(i, final) {
		return zero, "", fmt.Errorf("%w: service:168", v.ErrDenied)
	}
	out := v.SourcePage{Sources: make([]v.SourceRow, 0, len(sources))}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()

	if s.closed {
		return zero, "", fmt.Errorf("%w: service:176", v.ErrUnavailable)
	}
	for _, source := range sources {
		if !source.ReferenceValid() {
			continue
		}
		until := minTime(now.Add(time.Minute), source.HardUntil, source.PrivacyUntil)
		eligible := source.Valid(now) && slices.Contains([]string{"Warming", "Ready", "Degraded"}, source.State) && len(source.Projections) > 0
		blockers := append([]string{}, source.Blockers...)
		if !eligible && len(blockers) == 0 {
			blockers = append(blockers, "ProjectionUnavailable")
		}
		if eligible {
			until = minTime(until, source.HardUntil, source.PrivacyUntil)
		}
		id, until, e := s.encodeSourceHandle(i.Principal, source, until)
		if e != nil {
			return zero, "", e
		}
		out.Sources = append(out.Sources, v.SourceRow{Handle: id, HandleExpires: until, ID: source.ID(), WorkloadUID: source.Target.WorkloadUID, PodUID: source.Target.PodUID, ActionID: source.Action(), OwnerKind: source.OwnerKind, OwnerID: source.OwnerID, State: source.State, Projections: append([]string{}, source.Projections...), Eligible: eligible, Blockers: blockers, SaveVia: source.SaveVia, LeaseUntil: source.LeaseUntil})
	}
	return out, next, nil
}
func minTime(t time.Time, rest ...time.Time) time.Time {
	for _, v := range rest {
		if v.Before(t) {
			t = v
		}
	}
	return t
}

func (s *Service) Open(ctx context.Context, current CurrentIdentity, r v.Open) (v.Watch, error) {
	var zero v.Watch
	if !r.Valid() {
		return zero, fmt.Errorf("%w: service:211", v.ErrInvalid)
	}
	if r.Duration == 0 {
		r.Duration = v.DefaultLimits().Duration
	}
	if r.Output == 0 {
		r.Output = v.DefaultLimits().Output
	}
	if r.Filter.All == nil {
		r.Filter.All = []v.Predicate{}
	}
	i, err := s.actor(ctx, current)
	if err != nil {
		return zero, err
	}
	keyDigest, keyErr := s.account("open-key", struct {
		Principal identity.Principal
		Key       string
	}{i.Principal, r.Key})
	if keyErr != nil {
		return zero, fmt.Errorf("%w: service:231", v.ErrUnavailable)
	}
	requestDigest, digestErr := s.account("selection", r)
	if digestErr != nil {
		return zero, fmt.Errorf("%w: service:235", v.ErrUnavailable)
	}
	s.mu.Lock()
	prior := s.sessions[s.opens[keyDigest]]
	s.mu.Unlock()
	if prior != nil {
		prior.mu.Lock()
		defer prior.mu.Unlock()
		if prior.control.RequestDigest != requestDigest {
			return zero, fmt.Errorf("%w: service:244", v.ErrConflict)
		}
		if _, e := s.current(ctx, current, prior, i); e != nil {
			s.clear(prior, "AccessLost")
			return zero, e
		}
		return cloneWatch(prior.watch), nil
	}
	s.mu.Lock()
	if s.closed || s.active.Load()+int64(s.starting) >= int64(s.cfg.MaxWatches) || len(s.sessions)+s.starting >= s.cfg.MaxControls {
		s.mu.Unlock()
		return zero, fmt.Errorf("%w: service:255", v.ErrCapacity)
	}
	s.starting++
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.starting--; s.mu.Unlock() }()
	selected := make([]v.Source, len(r.Handles))
	s.mu.Lock()
	now := s.cfg.Now()

	if s.closed {
		s.mu.Unlock()
		return zero, fmt.Errorf("%w: service:266", v.ErrUnavailable)
	}

	s.mu.Unlock()
	proofUntil := i.ValidUntil
	if batch, ok := s.sources.(interface {
		ResolveSources(context.Context, CurrentIdentity, []v.SourceReference, string) ([]v.Source, time.Time, error)
	}); ok {
		refs := make([]v.SourceReference, len(r.Handles))
		handles := make([]sourceHandle, len(r.Handles))
		for n, encoded := range r.Handles {
			h, e := s.decodeSourceHandle(i.Principal, encoded)
			if e != nil {
				return zero, e
			}
			handles[n] = h
			refs[n] = v.SourceReference{ID: h.ID, Kind: h.Kind}
		}
		var e error
		selected, proofUntil, e = batch.ResolveSources(ctx, current, refs, r.Projection)
		if e != nil || len(selected) != len(handles) {
			return zero, fmt.Errorf("%w: service:287", v.ErrDenied)
		}
		for n, h := range handles {
			source := selected[n]
			if source.Root() != s.cfg.RootID || source.ID() != h.ID || source.OwnerKind != h.Kind || sourceVersion(source) != h.Version {
				return zero, fmt.Errorf("%w: service:292", v.ErrDenied)
			}
		}
	} else {
		for n, encoded := range r.Handles {
			h, e := s.decodeSourceHandle(i.Principal, encoded)
			if e != nil {
				return zero, e
			}
			source, until, e := s.sources.Resolve(ctx, current, h.ID, h.Kind, r.Projection)
			if e != nil || source.Root() != s.cfg.RootID || source.ID() != h.ID || source.OwnerKind != h.Kind || sourceVersion(source) != h.Version {
				return zero, fmt.Errorf("%w: service:303", v.ErrDenied)
			}
			selected[n] = source.Clone()
			proofUntil = minTime(proofUntil, until)
		}

	}
	first := selected[0]
	seen := map[string]bool{}
	for _, source := range selected {
		if seen[source.ID()] || source.Target.ClusterID != first.Target.ClusterID || source.Target.NamespaceUID != first.Target.NamespaceUID || source.Target.WorkloadUID != first.Target.WorkloadUID || !slices.Contains(source.Projections, r.Projection) {
			return zero, fmt.Errorf("%w: service:314", v.ErrInvalid)
		}
		seen[source.ID()] = true

		if !source.Valid(s.cfg.Now()) || !s.cfg.Now().Before(proofUntil) || !slices.Contains([]string{"Warming", "Ready", "Degraded"}, source.State) {
			return zero, fmt.Errorf("%w: service:319", v.ErrDenied)
		}
	}

	headCall, headCancel := context.WithDeadline(ctx, proofUntil)
	positions, err := s.reader.Head(headCall, selected, r.Projection)
	headCancel()
	if err != nil || len(positions) != len(selected) || !s.cfg.Now().Before(proofUntil) {
		// Nothing was created yet; the same idempotent open can be retried.
		return zero, fmt.Errorf("%w: %w: service:327", v.ErrUnavailable, v.ErrTransient)
	}
	final, err := s.actor(ctx, current)
	if err != nil || !sameLiveIdentity(i, final) {
		return zero, fmt.Errorf("%w: service:331", v.ErrDenied)
	}
	now = s.cfg.Now()
	limits := s.cfg.Limits
	for _, source := range selected {
		if source.ViewLimits.Valid() {
			limits = limits.Tighten(source.ViewLimits)
		}
	}
	if r.Duration != 0 {
		limits.Duration = min(limits.Duration, r.Duration)
	}
	if r.Output != 0 {
		limits.Output = min(limits.Output, r.Output)
	}
	end := now.Add(time.Duration(limits.Duration) * time.Second)
	for _, source := range selected {
		end = minTime(end, source.HardUntil, source.PrivacyUntil)
	}
	if !now.Before(end) {
		return zero, fmt.Errorf("%w: service:351", v.ErrDenied)
	}
	principalKey, keyErr := s.account("principal", struct {
		Issuer, Subject string
		Kind            identity.Kind
	}{i.Principal.Issuer, i.Principal.Subject, i.Principal.Kind})
	if keyErr != nil {
		return zero, fmt.Errorf("%w: service:358", v.ErrUnavailable)
	}
	workloadKey, keyErr := s.account("workload", []string{first.Target.ClusterID, first.Target.NamespaceUID, first.Target.WorkloadUID})
	if keyErr != nil {
		return zero, fmt.Errorf("%w: service:362", v.ErrUnavailable)
	}
	c := Control{OwnerID: s.cfg.OwnerID, ID: s.cfg.NewID(), Fence: s.cfg.NewID(), PrincipalKey: principalKey, WorkloadKey: workloadKey, RequestDigest: requestDigest, Revision: 1, State: "Active", AcceptedAt: now, ExpiresAt: end, IdleUntil: minTime(now.Add(v.IdleAge), end), OutputLimit: limits.Output, BytesPerSecond: limits.Rate}
	stored, reused, err := s.ledger.Create(ctx, c, hex.EncodeToString(keyDigest[:]))
	if err != nil {
		return zero, err
	}
	if !s.cfg.Now().Before(proofUntil) || ctx.Err() != nil {
		return zero, fmt.Errorf("%w: service:370", v.ErrDenied)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return zero, fmt.Errorf("%w: service:375", v.ErrUnavailable)
	}
	if reused {
		old := s.sessions[stored.ID]
		if old == nil {
			return zero, fmt.Errorf("%w: service:380", v.ErrUnavailable)
		}
		old.mu.Lock()
		receipt := cloneWatch(old.watch)
		old.mu.Unlock()
		return receipt, nil
	}
	if s.active.Load() >= int64(s.cfg.MaxWatches) {
		return zero, fmt.Errorf("%w: service:388", v.ErrCapacity)
	}
	ids := make([]string, len(selected))
	for n, source := range selected {
		ids[n] = source.ID()
	}
	w := v.Watch{ID: stored.ID, Revision: 1, State: "Active", SourceIDs: ids, Projection: r.Projection, AcceptedAt: stored.AcceptedAt, ExpiresAt: stored.ExpiresAt, IdleUntil: stored.IdleUntil, Limits: limits, Handling: v.Notices()}
	st := &session{watch: w, control: stored, actor: i.Principal, selected: selected, filter: v.CloneFilter(r.Filter), positions: positions, replay: map[string]replay{}, updates: map[string]updateReceipt{}}
	cursor := s.cursor(st)
	st.watch.Cursor = &cursor
	st.ownerEnd = w.ExpiresAt
	s.sessions[w.ID] = st
	s.active.Add(1)
	s.opens[keyDigest] = w.ID
	s.armLocked(st)
	return cloneWatch(st.watch), nil
}
func cloneWatch(w v.Watch) v.Watch {
	w.SourceIDs = append([]string(nil), w.SourceIDs...)
	if w.Cursor != nil {
		c := *w.Cursor
		w.Cursor = &c
	}
	return w
}
func (s *Service) get(ctx context.Context, current CurrentIdentity, id string) (*session, identity.Identity, error) {
	i, e := s.actor(ctx, current)
	if e != nil {
		return nil, i, e
	}
	s.mu.Lock()
	st := s.sessions[id]
	s.mu.Unlock()
	if st == nil || st.actor != i.Principal {
		return nil, i, fmt.Errorf("%w: service:422", v.ErrDenied)
	}
	return st, i, nil
}
func (s *Service) current(ctx context.Context, current CurrentIdentity, st *session, i identity.Identity) (time.Time, error) {
	now := s.cfg.Now()
	defer func() { st.lastCheck = s.cfg.Now().Sub(now) }()
	end := minTime(i.ValidUntil, st.watch.ExpiresAt, st.watch.IdleUntil)
	if !now.Before(st.watch.ExpiresAt) || !now.Before(st.watch.IdleUntil) {
		s.clear(st, "Expired")
		return end, fmt.Errorf("%w: service:431", v.ErrUnavailable)
	}
	stopped := false
	checks := make([]v.Source, len(st.selected))
	phaseUntil := end
	if batch, ok := s.sources.(interface {
		CheckSources(context.Context, CurrentIdentity, []v.Source, string) ([]v.Source, time.Time, error)
	}); ok {
		var e error
		checks, phaseUntil, e = batch.CheckSources(ctx, current, st.selected, st.watch.Projection)
		if errors.Is(e, v.ErrEnded) {
			// A finite source ended: end the view normally, as a stopped source.
			s.clear(st, "SourceEnded")
			st.gap = []v.Gap{{Reason: "sourceEnded", From: s.cfg.Now(), Until: s.cfg.Now()}}
			return end, nil
		}
		if e != nil || len(checks) != len(st.selected) {
			// A transient source/status miss fails only this read; it is not
			// an access decision and must not end the view.
			if e != nil && !errors.Is(e, v.ErrDenied) && errors.Is(e, v.ErrUnavailable) {
				return end, fmt.Errorf("%w: %w: service:442: %v", v.ErrUnavailable, v.ErrTransient, e)
			}
			return end, fmt.Errorf("%w: service:442: %v", v.ErrDenied, e)
		}
	} else {
		for n, source := range st.selected {
			var until time.Time
			var e error
			checks[n], until, e = s.sources.Check(ctx, current, source, st.watch.Projection)
			if errors.Is(e, v.ErrEnded) {
				s.clear(st, "SourceEnded")
				st.gap = []v.Gap{{Reason: "sourceEnded", From: s.cfg.Now(), Until: s.cfg.Now()}}
				return end, nil
			}
			if e != nil {
				if !errors.Is(e, v.ErrDenied) && errors.Is(e, v.ErrUnavailable) {
					return end, fmt.Errorf("%w: %w: service:450: %v", v.ErrUnavailable, v.ErrTransient, e)
				}
				return end, fmt.Errorf("%w: service:450: %v", v.ErrDenied, e)
			}
			phaseUntil = minTime(phaseUntil, until)
		}
	}
	for n, source := range st.selected {
		checked, until := checks[n], phaseUntil
		if !source.Same(checked) || !checked.Valid(s.cfg.Now()) || checked.ViewLimits.Valid() && st.watch.Limits.Tighten(checked.ViewLimits) != st.watch.Limits {
			return end, fmt.Errorf("%w: service:458", v.ErrDenied)
		}
		if checked.State == "Stopped" {
			stopped = true
		}
		if !slices.Contains(checked.Projections, st.watch.Projection) || !slices.Contains([]string{"Warming", "Ready", "Degraded", "Stopped"}, checked.State) {
			return end, fmt.Errorf("%w: service:464", v.ErrDenied)
		}
		st.selected[n] = checked.Clone()
		end = minTime(end, until, checked.LeaseUntil, checked.PrivacyUntil)
	}
	if e := s.ledger.CurrentLive(ctx, st.control); e != nil {
		// Ledger unavailability is not an access decision; a refused or
		// changed control is.
		if !errors.Is(e, v.ErrDenied) && errors.Is(e, v.ErrUnavailable) && ctx.Err() == nil {
			return end, fmt.Errorf("%w: %w: service:470: %v", v.ErrUnavailable, v.ErrTransient, e)
		}
		return end, fmt.Errorf("%w: service:470", v.ErrDenied)
	}
	final, e := s.actor(ctx, current)
	if e != nil || !sameLiveIdentity(i, final) || ctx.Err() != nil {
		return end, fmt.Errorf("%w: service:474", v.ErrDenied)
	}
	if !s.cfg.Now().Before(end) {
		// The checked bounds (for example a lease awaiting renewal) lapsed
		// during this check; refuse this call only and re-check next time.
		return end, fmt.Errorf("%w: %w: service:474", v.ErrUnavailable, v.ErrTransient)
	}
	if stopped {
		s.clear(st, "SourceEnded")
		st.gap = []v.Gap{{Reason: "sourceEnded", From: s.cfg.Now(), Until: s.cfg.Now()}}
	}
	return end, nil
}
func (s *Service) Read(ctx context.Context, current CurrentIdentity, r v.Read) (v.Batch, error) {
	var zero v.Batch
	var previous []v.Position // positions to restore if delivery is refused transiently
	if !r.Valid() {
		return zero, fmt.Errorf("%w: service:485", v.ErrInvalid)
	}
	st, i, err := s.get(ctx, current, r.ID)
	if err != nil {
		return zero, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.reading {
		return zero, fmt.Errorf("%w: service:494", v.ErrConflict)
	}
	end, err := s.current(ctx, current, st, i)
	if err != nil {
		if !errors.Is(err, v.ErrTransient) {
			s.clear(st, "AccessLost")
		}
		return zero, err
	}
	now := s.cfg.Now()
	for c, p := range st.replay {
		if !now.Before(p.until) {
			delete(st.replay, c)
		}
	}
	if p, ok := st.replay[r.Cursor]; ok {
		batch := v.CloneBatch(p.batch)
		batch.DisclosureUntil = minTime(batch.DisclosureUntil, end)
		batch.Cursor = p.next
		for _, row := range batch.Rows {
			if !row.Valid(now) {
				return zero, fmt.Errorf("%w: service:513", v.ErrConflict)
			}
		}
		return s.charge(ctx, st, batch)
	}
	position, validCursor := s.cursorPosition(st, r.Cursor)
	if !validCursor || position > st.position {
		return zero, fmt.Errorf("%w: service:520", v.ErrConflict)
	}
	lagging := position < st.position
	if !lagging && (st.watch.Cursor == nil || r.Cursor != *st.watch.Cursor) {
		return zero, fmt.Errorf("%w: service:524", v.ErrConflict)
	}
	batch := v.Batch{DisclosureUntil: end, WatchID: st.watch.ID, Revision: st.watch.Revision, ID: s.cfg.NewID(), State: st.watch.State, Rows: []v.Row{}, Sources: []v.SourceStatus{}, Gaps: append([]v.Gap{}, st.gap...), From: now, Until: now, ReceivedAt: now, RetryAfter: 1000, Handling: v.Notices()}
	st.gap = nil
	if lagging && !v.Terminal(st.watch.State) {
		if st.watch.State == "Active" {
			headCall, headCancel := context.WithDeadline(ctx, end)
			head, e := s.reader.Head(headCall, st.selected, st.watch.Projection)
			headCancel()
			if e != nil || len(head) != len(st.positions) {
				return zero, fmt.Errorf("%w: service:534", v.ErrUnavailable)
			}
			finalEnd, e := s.current(ctx, current, st, i)
			if e != nil {
				return zero, e
			}
			end = finalEnd // fresh check after the head read; see the Active branch
			batch.DisclosureUntil = end
			if v.Terminal(st.watch.State) {
				batch.State = st.watch.State
				batch.Gaps = append(batch.Gaps, st.gap...)
				st.gap = nil
			} else {
				st.positions = append(st.positions[:0], head...)
			}
		}
		now = s.cfg.Now()
		if !v.Terminal(batch.State) {
			batch.Gaps = appendLiveGap(batch.Gaps, v.Gap{Reason: "bufferExpired", From: st.watch.AcceptedAt, Until: now})
		}
		batch.Until = now
		batch.ReceivedAt = now
	} else if st.watch.State == "Active" {
		// The private call shares original authority and finite wait. Its fixed
		// examined-event cap applies before filtering, including discarded rows.
		call, cancel := context.WithDeadline(ctx, end)
		st.reading = true
		st.cancelRead = cancel
		st.readJoined = make(chan struct{})
		selected := append([]v.Source(nil), st.selected...)
		positions := append([]v.Position(nil), st.positions...)
		projection := st.watch.Projection
		rowLimit := min(defaultLimit(r.Limit), st.watch.Limits.Rows)
		st.mu.Unlock()
		projected, e := s.reader.Read(call, selected, projection, positions, rowLimit, 4096, r.WaitMS)
		cancel()
		st.mu.Lock()
		st.reading = false
		st.cancelRead = nil
		close(st.readJoined)
		if e != nil {
			s.clear(st, "Disconnected")
			return zero, fmt.Errorf("%w: service:576", v.ErrUnavailable)
		}
		if len(projected.Rows) > min(defaultLimit(r.Limit), st.watch.Limits.Rows) || projected.Examined < 0 || projected.Examined > 4096 || projected.Bytes < 0 || projected.Bytes > 1<<20 || len(projected.Positions) != len(st.selected) || len(projected.Gaps) > 32 || len(projected.Sources) > v.MaxSources {
			s.clear(st, "Disconnected")
			return zero, fmt.Errorf("%w: service:580", v.ErrUnavailable)
		}
		finalEnd, e := s.current(ctx, current, st, i)
		if e != nil {
			if !errors.Is(e, v.ErrTransient) {
				s.clear(st, "AccessLost")
			}
			return zero, e
		}
		// The node read stayed inside the first check's window; disclosure is
		// authorized by this fresh check, which carries every current bound.
		end = finalEnd
		batch.DisclosureUntil = end
		now = s.cfg.Now()
		batch.Until = now
		batch.ReceivedAt = now
		if v.Terminal(st.watch.State) {
			// A source can end while the node read is in flight. current()
			// has already erased its references; never index them or disclose
			// the batch selected before that terminal observation.
			batch.State = st.watch.State
			for _, gap := range st.gap {
				batch.Gaps = appendLiveGap(batch.Gaps, gap)
			}
			st.gap = nil
			clear(projected.Rows)
		} else {
			seenSources := map[string]bool{}
			for _, source := range projected.Sources {
				if !source.Valid(now) || !slices.Contains(st.watch.SourceIDs, source.ID) || seenSources[source.ID] {
					s.clear(st, "Disconnected")
					return zero, fmt.Errorf("%w: service:607", v.ErrUnavailable)
				}
				seenSources[source.ID] = true
			}
			for _, gap := range projected.Gaps {
				if !gap.Valid(now) || gap.SourceID != nil && !slices.Contains(st.watch.SourceIDs, *gap.SourceID) {
					s.clear(st, "Disconnected")
					return zero, fmt.Errorf("%w: service:614", v.ErrUnavailable)
				}
			}
			batch.Sources = projected.Sources
			for _, gap := range projected.Gaps {
				batch.Gaps = appendLiveGap(batch.Gaps, gap)
			}
			lastSequence := append([]v.Position(nil), st.positions...)
			for _, row := range projected.Rows {
				idx := slices.Index(st.watch.SourceIDs, row.SourceID)
				if idx < 0 || row.PodUID != st.selected[idx].Target.PodUID || row.Projection != st.watch.Projection || row.Sequence <= lastSequence[idx].Sequence || row.Sequence > projected.Positions[idx].Sequence {
					s.clear(st, "Disconnected")
					return zero, fmt.Errorf("%w: service:626", v.ErrUnavailable)
				}
				lastSequence[idx].Sequence = row.Sequence
				if row.ObservedAt.Before(st.watch.AcceptedAt) {
					continue
				}
				if !row.Valid(now) {
					reason := "clockUncertain"
					if !now.Before(row.ExpiresAt) {
						reason = "bufferExpired"
					}
					id := row.SourceID
					batch.Gaps = appendLiveGap(batch.Gaps, v.Gap{Reason: reason, SourceID: &id, From: batch.From, Until: now})
					continue
				}
				// Read authority is re-checked by every read and a denial ends the
				// view; it bounds each read, not how long a disclosed row displays.
				row.ExpiresAt = minTime(row.ExpiresAt, st.watch.ExpiresAt, st.selected[idx].PrivacyUntil, row.ObservedAt.Add(time.Duration(st.watch.Limits.RowAge)*time.Second-time.Duration(row.ClockUncertainty)*time.Millisecond))
				if !row.Valid(now) {
					continue
				}
				if !st.filter.Match(row) {
					count := 1
					id := row.SourceID
					batch.Gaps = appendLiveGap(batch.Gaps, v.Gap{Reason: "filteredOut", SourceID: &id, Count: &count, From: batch.From, Until: now})
					continue
				}
				batch.Rows = append(batch.Rows, row.Clone())
				b, _ := json.Marshal(batch)
				if len(b) > v.MaxBatchBytes-512 {
					batch.Rows = batch.Rows[:len(batch.Rows)-1]
					batch.Gaps = appendLiveGap(batch.Gaps, v.Gap{Reason: "subscriberOverflow", From: batch.From, Until: now})
					break
				}
			}
			for n, pos := range projected.Positions {
				if !pos.Follows(st.positions[n]) {
					s.clear(st, "Disconnected")
					return zero, fmt.Errorf("%w: service:662", v.ErrUnavailable)
				}
			}
			previous = append([]v.Position(nil), st.positions...)
			st.positions = append(st.positions[:0], projected.Positions...)
		}
	}
	charged, err := s.charge(ctx, st, batch)
	if err != nil {
		if previous != nil && errors.Is(err, v.ErrTransient) {
			// Nothing was disclosed; the next read returns the same rows.
			st.positions = append(st.positions[:0], previous...)
		}
		return zero, err
	}
	st.position++
	next := s.cursor(st)
	st.watch.Cursor = &next
	charged.Cursor = next
	if st.watch.Limits.Replay > 0 && !v.Terminal(st.watch.State) {
		expiry := s.cfg.Now().Add(time.Duration(st.watch.Limits.Replay) * time.Second)
		for _, row := range charged.Rows {
			expiry = minTime(expiry, row.ExpiresAt)
		}
		used := 0
		for _, previous := range st.replay {
			raw, _ := json.Marshal(previous.batch)
			used += len(raw)
		}
		raw, _ := json.Marshal(charged)
		if used+len(raw) > st.watch.Limits.Buffer {
			clear(st.replay)
		}
		// A valid delivered batch may exceed a smaller accepted replay
		// buffer. Retain none rather than exceeding it or trimming paid rows.
		if len(raw) <= st.watch.Limits.Buffer {
			st.replay[r.Cursor] = replay{v.CloneBatch(charged), next, expiry}
		}
		s.armLocked(st)
	}
	s.armLocked(st)
	return charged, nil
}
func defaultLimit(n int) int {
	if n == 0 {
		return 20
	}
	return n
}
func (s *Service) charge(ctx context.Context, st *session, b v.Batch) (v.Batch, error) {
	if b.DisclosureUntil.IsZero() {
		return v.Batch{}, fmt.Errorf("%w: service:708", v.ErrDenied)
	}
	if !s.cfg.Now().Before(b.DisclosureUntil) {
		// The current bounds (for example a source lease about to renew)
		// ended before delivery; refuse this read only.
		return v.Batch{}, fmt.Errorf("%w: %w: service:708 (late %s, last check %s)", v.ErrUnavailable, v.ErrTransient, s.cfg.Now().Sub(b.DisclosureUntil).Round(time.Millisecond), st.lastCheck.Round(time.Millisecond))
	}
	call, stop := context.WithDeadline(ctx, b.DisclosureUntil)
	defer stop()
	raw, _ := json.Marshal(b)
	cost := int64(len(raw) + 4096)
	if cost > 24<<10 {
		return v.Batch{}, fmt.Errorf("%w: service:715", v.ErrCapacity)
	}
	if cost > st.control.OutputLimit-st.control.Spent {
		s.clear(st, "Exhausted")
		return v.Batch{}, fmt.Errorf("%w: service:719", v.ErrCapacity)
	}
	// Durable/account-wide rate enforcement is inside the ledger transaction.
	next := st.control
	next.Spent += cost
	next.State = st.watch.State
	next.IdleUntil = minTime(s.cfg.Now().Add(v.IdleAge), next.ExpiresAt)
	saved, err := s.ledger.Change(call, next, st.control.Revision, cost)
	if err != nil {
		return v.Batch{}, transientLedger(err)
	}
	st.control = saved
	st.watch.IdleUntil = saved.IdleUntil
	b.Spent = saved.Spent
	if call.Err() != nil || !s.cfg.Now().Before(b.DisclosureUntil) {
		if ctx.Err() == nil {
			// The charge committed but the current bounds lapsed before
			// delivery: refuse this read only. The spend stays charged
			// (conservative) and the next read re-delivers the same rows.
			return v.Batch{}, fmt.Errorf("%w: %w: service:735", v.ErrUnavailable, v.ErrTransient)
		}
		s.clear(st, "Disconnected")
		return v.Batch{}, fmt.Errorf("%w: service:735", v.ErrDenied)
	}
	return b, nil
}
func (s *Service) clear(st *session, state string) {
	before := st.watch.State
	if v.Terminal(before) {
		state = before
	}
	st.watch.State = state
	if !v.Terminal(before) && v.Terminal(state) {
		s.active.Add(-1)
	}
	clear(st.replay)
	st.gap = nil
	if v.Terminal(state) && !st.reading {
		s.eraseDetails(st)
	}
}
func (s *Service) Update(ctx context.Context, current CurrentIdentity, r v.Update, close bool) (v.Watch, error) {
	var zero v.Watch
	if !r.Valid() || !close && r.Mode == "" && r.Filter == nil {
		return zero, fmt.Errorf("%w: service:757", v.ErrInvalid)
	}
	st, i, err := s.get(ctx, current, r.ID)
	if err != nil {
		return zero, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.reading {
		return zero, fmt.Errorf("%w: service:766", v.ErrConflict)
	}
	digest := hash(struct {
		R     v.Update
		Close bool
	}{r, close})
	if old, ok := st.updates[r.Key]; ok {
		if old.digest != digest {
			return zero, fmt.Errorf("%w: service:774", v.ErrConflict)
		}
		if close && old.watch.State == "Closed" && st.watch.State == "Closed" {
			// A Close receipt discloses no rows and cannot reacquire the source
			// scope already erased by Close. Keep its original actor/control and
			// hard/idle bounds current without rebuilding that erased authority.
			if e := s.currentClosedReceipt(ctx, current, st, i); e != nil {
				return zero, e
			}
		} else if _, e := s.current(ctx, current, st, i); e != nil {
			return zero, e
		}
		return cloneWatch(old.watch), nil
	}
	if len(st.updates) >= 128 {
		return zero, fmt.Errorf("%w: service:789", v.ErrCapacity)
	}
	if r.Revision != st.watch.Revision {
		return zero, fmt.Errorf("%w: service:792", v.ErrConflict)
	}
	if r.Filter != nil && !r.Filter.Valid(st.watch.Projection) {
		return zero, fmt.Errorf("%w: service:795", v.ErrInvalid)
	}
	currentEnd, currentErr := s.current(ctx, current, st, i)
	err = currentErr
	if err != nil && !close {
		if !errors.Is(err, v.ErrTransient) {
			s.clear(st, "AccessLost")
		}
		return zero, err
	}
	if v.Terminal(st.watch.State) && !close {
		return zero, fmt.Errorf("%w: service:804", v.ErrConflict)
	}
	positions := st.positions
	if !close {
		var headErr error
		headCall, headCancel := context.WithDeadline(ctx, currentEnd)
		positions, headErr = s.reader.Head(headCall, st.selected, st.watch.Projection)
		headCancel()
		if headErr != nil || len(positions) != len(st.positions) {
			return zero, fmt.Errorf("%w: %w: service:813", v.ErrUnavailable, v.ErrTransient)
		}
	}
	before := st.control.Revision
	next := st.control
	next.Revision++
	if close {
		next.State = "Closed"
	} else if r.Mode != "" {
		next.State = r.Mode
	}
	if !close {
		next.IdleUntil = minTime(s.cfg.Now().Add(v.IdleAge), next.ExpiresAt)
	}
	saved, err := s.ledger.Change(ctx, next, before, 0)
	if err != nil {
		return zero, transientLedger(err)
	}
	st.control = saved
	st.positions = append(st.positions[:0], positions...)
	priorState := st.watch.State
	st.watch.State = saved.State
	if !v.Terminal(priorState) && v.Terminal(saved.State) {
		s.active.Add(-1)
	}
	st.watch.Revision = saved.Revision
	st.watch.IdleUntil = saved.IdleUntil
	clear(st.replay)
	if r.Filter != nil {
		st.filter = v.CloneFilter(*r.Filter)
	}
	st.position++
	cursor := s.cursor(st)
	st.watch.Cursor = &cursor
	reason := "filterChanged"
	if priorState == "Disconnected" && r.Mode == "Active" {
		reason = "reconnect"
	}
	if r.Mode == "Paused" {
		reason = "paused"
	}
	st.gap = []v.Gap{{Reason: reason, From: s.cfg.Now(), Until: s.cfg.Now()}}
	if close {
		s.clear(st, "Closed")
		st.watch.Cursor = nil
	}
	st.updates[r.Key] = updateReceipt{digest, cloneWatch(st.watch)}
	s.armLocked(st)
	return cloneWatch(st.watch), nil
}

// currentClosedReceipt validates only the original minimized terminal control.
// It returns no rows, reads no source, performs no charge and renews no date.
func (s *Service) currentClosedReceipt(ctx context.Context, current CurrentIdentity, st *session, i identity.Identity) error {
	if st.control.State != "Closed" || st.control.ID != st.watch.ID || st.actor != i.Principal || !st.control.ExpiresAt.Equal(st.watch.ExpiresAt) || !st.control.IdleUntil.Equal(st.watch.IdleUntil) {
		return fmt.Errorf("%w: service:868", v.ErrDenied)
	}
	end := minTime(i.ValidUntil, st.control.ExpiresAt, st.control.IdleUntil, st.ownerEnd)
	if !s.cfg.Now().Before(end) {
		return fmt.Errorf("%w: service:872", v.ErrDenied)
	}
	call, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	if err := s.ledger.CurrentLive(call, st.control); err != nil {
		return err
	}
	final, err := s.actor(call, current)
	if err != nil || !sameLiveIdentity(i, final) || call.Err() != nil || !s.cfg.Now().Before(end) {
		return fmt.Errorf("%w: service:881", v.ErrDenied)
	}
	return nil
}

// ReferenceKey is an opaque stable operation key, never source/filter text.
func ReferenceKey(p identity.Principal, key string) string {
	h := hash(struct {
		P identity.Principal
		K string
	}{p, key})
	return hex.EncodeToString(h[:])
}

func sameLiveIdentity(a, b identity.Identity) bool {
	return a.Principal == b.Principal && a.Policy == b.Policy && slices.Equal(a.Groups, b.Groups) && slices.Equal(a.Scopes, b.Scopes)
}

// transientLedger marks an unavailable ledger write as retryable: nothing was
// disclosed, and a retry re-checks current authority and may charge again.
func transientLedger(err error) error {
	if errors.Is(err, v.ErrUnavailable) && !errors.Is(err, v.ErrDenied) && !errors.Is(err, v.ErrTransient) {
		return fmt.Errorf("%w: %w: ledger change", err, v.ErrTransient)
	}
	return err
}
