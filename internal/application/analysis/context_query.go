package analysis

import (
	"context"
	"slices"
	"sync"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextProjectionResults deliberately has no worker admission capability.
// Looking up a pending handle can only observe/read its original exact worker.
// All ports are mandatory protected composition; this component enables no tool.
type ContextProjectionResults struct {
	RootID, InstallationID, HubProcessEpoch string
	Authority                               CurrentContextProjectionAuthority
	Ledger                                  ContextQueryLedger
	Reader                                  ContextProjectionReader
	Now                                     func() time.Time
	NewID                                   func() string
}

type ContextProjectionService struct {
	Results  ContextProjectionResults
	Recovery ContextProjectionRecovery
	Routes   ContextProjectionRoutes
	Plans    ContextQueryPlans
	Workers  ContextProjectionWorkerAdmission
}

func (s ContextProjectionResults) valid() bool {
	return authorization.UUID(s.RootID) && authorization.UUID(s.InstallationID) && authorization.UUID(s.HubProcessEpoch) &&
		s.Authority != nil && s.Ledger != nil && s.Reader != nil && s.Now != nil && s.NewID != nil
}

// These dispositions describe acknowledged internal effects for the existing
// C-20/C-08 outcome mapping. An error after dispatch may still have an unknown
// effect; absence of a successful delivery never proves an effect-free call.
type ContextQueryEffect string

const (
	ContextQueryAdmitted    ContextQueryEffect = "query_admitted"
	ContextQueryPollCharged ContextQueryEffect = "query_poll_charged"
	ContextQueryReadCharged ContextQueryEffect = "query_read_charged"
)

type ContextProjectionAssociation struct {
	ID, QueryID, OperationID, BatchID string
	Generation                        int64
	Selection                         value.LineSelection
}

// ContextProjectionDelivery owns both the prepared result and its live request.
// C-20 must serialize a bounded copy once, bind that exact body to this pointer,
// acknowledge its existing outcome and retain the guard through write/flush.
// Its own audit slot/cancel must also transfer to transport-owned cleanup.
type ContextProjectionDelivery struct {
	owner                                   *projectionRequest
	association                             ContextProjectionAssociation
	effect                                  ContextQueryEffect
	excerpt                                 value.ContextExcerpt
	pending                                 bool
	batch                                   *value.ContextReadBatch
	read                                    ContextProjectionRead
	observedAt, queryDeadline, cleanupUntil time.Time
	once                                    sync.Once
	closeErr                                error
}

func (d *ContextProjectionDelivery) Association() ContextProjectionAssociation { return d.association }
func (d *ContextProjectionDelivery) Effect() ContextQueryEffect                { return d.effect }
func (d *ContextProjectionDelivery) Pending() bool                             { return d.pending }

// These are frozen for this exact prepared association. QueryDeadline is the
// original total query/evidence cutoff, never the private five-second lease;
// ObservedAt is this response's preparation observation, not query creation.
func (d *ContextProjectionDelivery) ObservedAt() time.Time    { return d.observedAt }
func (d *ContextProjectionDelivery) QueryDeadline() time.Time { return d.queryDeadline }
func (d *ContextProjectionDelivery) CleanupUntil() time.Time  { return d.cleanupUntil }

// Done exposes only loss of the existing request owner. Transport links it to
// final writes; it conveys neither authority nor a new request lifetime.
func (d *ContextProjectionDelivery) Done() <-chan struct{} {
	if d != nil && d.owner != nil {
		return d.owner.ctx.Done()
	}
	closed := make(chan struct{})
	close(closed)
	return closed
}
func (d *ContextProjectionDelivery) Excerpt() (value.ContextExcerpt, bool) {
	if d == nil || d.pending {
		return value.ContextExcerpt{}, false
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.closed {
		return value.ContextExcerpt{}, false
	}
	x := d.excerpt
	x.Lines = slices.Clone(x.Lines)
	return x, true
}

func (d *ContextProjectionDelivery) ValidUntil() time.Time {
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	return d.owner.until
}

// CheckDisclosure fails before this exact result's outcome acknowledgement.
// Each check retains every original interval and rechecks after blocking ports.
func (d *ContextProjectionDelivery) CheckDisclosure(ctx context.Context) error {
	if d == nil || d.owner == nil {
		return value.ErrUnavailable
	}
	o := d.owner
	checked, cancel, err := o.context(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err := o.invocation.CheckOutcome(checked, d); err != nil {
		return value.ErrUnavailable
	}
	a, err := o.CheckCurrent(checked)
	if err != nil {
		return err
	}
	if a.AccessUntil.Before(d.queryDeadline) {
		return value.ErrUnavailable
	}
	if d.batch == nil {
		err = o.service.Ledger.PermitQuery(checked, o.query, o.request, a)
	} else {
		err = o.service.Ledger.PermitReadBatch(checked, *d.batch, a)
		if err == nil {
			err = d.read.CheckCurrent(checked)
		}
	}
	if err != nil {
		return value.ErrUnavailable
	}
	a, err = o.CheckCurrent(checked)
	if err == nil && a.AccessUntil.Before(d.queryDeadline) {
		return value.ErrUnavailable
	}
	return err
}

// Close is called only after the transport has joined all writes and discarded
// every copy it owns. The original prepaid cleanup horizon permits restrictive
// completion after request cancellation; it cannot renew normal-work authority.
// A failed/unknown private close leaves SQL active and every charge intact.
func (d *ContextProjectionDelivery) Close(ctx context.Context) error {
	if d == nil || d.owner == nil {
		return value.ErrUnavailable
	}
	d.once.Do(func() {
		o := d.owner
		o.cancel()
		o.mu.Lock()
		o.closed = true
		clear(d.excerpt.Lines)
		d.excerpt = value.ContextExcerpt{}
		o.mu.Unlock()
		if d.read == nil {
			return
		}
		if ctx == nil {
			d.closeErr = value.ErrUnavailable
			return
		}
		until := d.cleanupUntil
		if deadline, ok := ctx.Deadline(); ok {
			until = identity.Earlier(until, deadline)
		}
		cleanup, cancel := context.WithDeadline(context.WithoutCancel(ctx), until)
		defer cancel()
		if err := d.read.Close(cleanup); err != nil {
			d.closeErr = value.ErrUnavailable
			return
		}
		if d.batch == nil {
			d.closeErr = value.ErrUnavailable
			return
		}
		// The adapter consumes the opaque C-14 guarded closure; C-18 never
		// creates a Joined receipt or infers retirement from a clock.
		d.closeErr = o.service.Ledger.CompleteReadBatch(cleanup, *d.batch, d.read)
	})
	return d.closeErr
}

type projectionRequest struct {
	service    ContextProjectionResults
	ctx        context.Context
	cancel     context.CancelFunc
	current    identities.CurrentIdentity
	initial    identity.Identity
	invocation ContextQueryInvocation
	request    value.ContextQueryRequest
	query      value.ContextQuery
	mu         sync.Mutex
	until      time.Time
	closed     bool
	timer      *time.Timer
}

// Every port sees the same monotonically shortened deadline. The underlying
// context is also cancelled at that bound, including ports that wait only on
// Done rather than deriving a deadline of their own. The context is installed
// once before exposure and is never replaced while a worker may retain it.
type projectionContext struct {
	context.Context
	owner *projectionRequest
}

func (c projectionContext) Deadline() (time.Time, bool) {
	c.owner.mu.Lock()
	defer c.owner.mu.Unlock()
	return c.owner.until, true
}

func sameProjectionIdentity(a, b identity.Identity, now time.Time) bool {
	if !a.Valid(now) || !b.Valid(now) || a.Principal != b.Principal || a.Policy != b.Policy {
		return false
	}
	for _, pair := range [][2][]string{{a.Groups, b.Groups}, {a.Scopes, b.Scopes}} {
		x, y := slices.Clone(pair[0]), slices.Clone(pair[1])
		slices.Sort(x)
		slices.Sort(y)
		if !slices.Equal(x, y) {
			return false
		}
	}
	return true
}

func (s ContextProjectionResults) request(ctx context.Context, current identities.CurrentIdentity, invocation ContextQueryInvocation, tool string) (*projectionRequest, error) {
	if !s.valid() || ctx == nil || ctx.Err() != nil || current == nil || invocation == nil {
		return nil, value.ErrUnavailable
	}
	started := s.Now()
	until := started.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	initialCtx, initialCancel := context.WithDeadline(ctx, until)
	transferred := false
	defer func() {
		if !transferred {
			initialCancel()
		}
	}()
	i, err := current.ResolveIdentity(initialCtx)
	if err != nil || initialCtx.Err() != nil || !i.Valid(s.Now()) || !slices.Contains(i.Scopes, "evidence:read") {
		return nil, value.ErrUnavailable
	}
	i.Scopes, i.Groups = slices.Clone(i.Scopes), slices.Clone(i.Groups)
	until = identity.Earlier(until, i.ValidUntil)
	callCtx, callCancel := context.WithDeadline(initialCtx, until)
	defer func() {
		if !transferred {
			callCancel()
		}
	}()
	call, err := invocation.Invocation(callCtx)
	if err != nil || callCtx.Err() != nil || !call.Valid(s.Now()) || call.Tool != tool || call.RootID != s.RootID || call.Principal != i.Principal {
		return nil, value.ErrUnavailable
	}
	until = identity.Earlier(until, call.Until)
	request := value.ContextQueryRequest{Call: call, OwnerID: s.NewID(), HubProcessEpoch: s.HubProcessEpoch}
	if !request.Valid(s.Now()) || !s.Now().Before(until) {
		return nil, value.ErrUnavailable
	}
	owned, cancel := context.WithCancel(callCtx)
	o := &projectionRequest{service: s, current: current, initial: i, invocation: invocation, request: request, until: until}
	o.ctx = projectionContext{Context: owned, owner: o}
	o.cancel = func() {
		cancel()
		callCancel()
		initialCancel()
		o.mu.Lock()
		if o.timer != nil {
			o.timer.Stop()
		}
		o.mu.Unlock()
	}
	transferred = true
	if !o.shorten(until) || invocation.CheckIntent(o.ctx, call) != nil {
		o.cancel()
		return nil, value.ErrUnavailable
	}
	if _, err = o.checkIdentity(o.ctx); err != nil {
		o.cancel()
		return nil, err
	}
	return o, nil
}

func (o *projectionRequest) Request() value.ContextQueryRequest { return o.request }

func (o *projectionRequest) context(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil || ctx.Err() != nil || o.ctx.Err() != nil {
		return nil, nil, value.ErrUnavailable
	}
	o.mu.Lock()
	until, closed := o.until, o.closed
	o.mu.Unlock()
	if closed || !o.service.Now().Before(until) {
		return nil, nil, value.ErrExpired
	}
	checked, cancel := context.WithDeadline(ctx, until)
	stop := context.AfterFunc(o.ctx, cancel)
	return checked, func() { stop(); cancel() }, nil
}

func (o *projectionRequest) checkIdentity(ctx context.Context) (identity.Identity, error) {
	if ctx == nil || ctx.Err() != nil || o.ctx.Err() != nil {
		return identity.Identity{}, value.ErrUnavailable
	}
	o.mu.Lock()
	until, closed := o.until, o.closed
	o.mu.Unlock()
	if closed || !o.service.Now().Before(until) {
		return identity.Identity{}, value.ErrExpired
	}
	checked, cancel := context.WithDeadline(ctx, until)
	stop := context.AfterFunc(o.ctx, cancel)
	defer func() { stop(); cancel() }()
	i, err := o.current.ResolveIdentity(checked)
	if err != nil || checked.Err() != nil || o.ctx.Err() != nil || !sameProjectionIdentity(o.initial, i, o.service.Now()) {
		return identity.Identity{}, value.ErrUnavailable
	}
	if !o.shorten(i.ValidUntil) {
		return identity.Identity{}, value.ErrExpired
	}
	return i, nil
}

func (o *projectionRequest) shorten(until time.Time) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	earliest := identity.Earlier(o.until, until)
	if o.timer == nil || earliest.Before(o.until) {
		o.until = earliest
		if o.timer != nil {
			o.timer.Stop()
		}
		o.timer = time.AfterFunc(time.Until(earliest), o.cancel)
	}
	return !o.closed && o.ctx.Err() == nil && o.service.Now().Before(o.until)
}

func (o *projectionRequest) CheckCurrent(ctx context.Context) (value.ContextProjectionAuthority, error) {
	checked, cancel, err := o.context(ctx)
	if err != nil {
		return value.ContextProjectionAuthority{}, err
	}
	defer cancel()
	if _, err := o.checkIdentity(checked); err != nil {
		return value.ContextProjectionAuthority{}, err
	}
	a, err := o.service.Authority.CheckProjectionCurrent(checked, o.current, o.query.Scope)
	if err != nil || !o.query.Current(a, o.service.Now()) || a.Environment.InstallationID != o.service.InstallationID ||
		a.IdentityRevision != o.initial.Policy || !o.shorten(identity.Earlier(o.query.Deadline, a.ValidUntil)) {
		return value.ContextProjectionAuthority{}, value.ErrUnavailable
	}
	if _, err = o.checkIdentity(checked); err != nil {
		return value.ContextProjectionAuthority{}, err
	}
	o.mu.Lock()
	a.ValidUntil = identity.Earlier(a.ValidUntil, o.until)
	o.mu.Unlock()
	if !a.Valid(o.service.Now()) {
		return value.ContextProjectionAuthority{}, value.ErrUnavailable
	}
	return a, nil
}

func (s ContextProjectionService) BeginExcerpt(ctx context.Context, current identities.CurrentIdentity, invocation ContextQueryInvocation, selection value.ContextExcerptSelection) (*ContextProjectionDelivery, error) {
	if !selection.Valid() || s.Recovery == nil || s.Routes == nil || s.Plans == nil || s.Workers == nil {
		return nil, value.ErrUnavailable
	}
	o, err := s.Results.request(ctx, current, invocation, "get_file_excerpt")
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			o.cancel()
		}
	}()
	if err = invocation.CheckInput(o.ctx, ContextQueryInput{Selection: selection}); err != nil {
		return nil, value.ErrUnavailable
	}
	recovery, err := s.Recovery.RecoveryState(o.ctx)
	if err != nil || !recovery.Valid(s.Results.Now()) || recovery.InstallationID != s.Results.InstallationID || !o.shorten(recovery.FreshUntil) {
		return nil, value.ErrUnavailable
	}
	candidate, err := s.Routes.ResolveContextProjection(o.ctx, selection, o.initial, recovery)
	if err != nil || !candidate.Valid() || candidate.RootID != s.Results.RootID || candidate.CaseID != selection.CaseID ||
		candidate.ArtifactID != selection.ArtifactID || candidate.Selection != selection.Selection || candidate.Principal != o.initial.Principal {
		return nil, value.ErrUnavailable
	}
	a, err := s.Results.Authority.ResolveProjectionCurrent(o.ctx, current, candidate)
	if err != nil || !a.Valid(s.Results.Now()) || a.Scope.Candidate() != candidate || a.Environment.InstallationID != s.Results.InstallationID ||
		a.Environment.Recovery.IssuerEpoch != recovery.IssuerEpoch || a.Environment.Recovery.Revision != recovery.Revision || a.IdentityRevision != o.initial.Policy || !o.shorten(a.ValidUntil) {
		return nil, value.ErrUnavailable
	}
	p, err := s.Plans.ContextQueryPlan(o.ctx, a)
	if err != nil || !p.Valid(a.Scope, s.Results.Now()) || !o.shorten(p.ValidUntil) {
		return nil, value.ErrUnavailable
	}
	q, err := value.NewContextQuery(s.Results.NewID(), o.request.Call.ID, s.Results.NewID(), a, p, s.Results.Now())
	if err != nil {
		return nil, err
	}
	o.query = q
	a, err = o.CheckCurrent(o.ctx)
	if err != nil {
		return nil, err
	}
	admitted, err := s.Results.Ledger.AdmitQuery(o.ctx, q, o.request, a)
	if err != nil || !admitted.Fresh || !admitted.Query.Equal(q) {
		return nil, value.ErrUnavailable
	}
	if _, err = o.CheckCurrent(o.ctx); err != nil {
		return nil, err
	}
	if err = s.Workers.AdmitProjectionWorker(o.ctx, q, o); err != nil {
		return nil, value.ErrUnavailable
	}
	d, err := s.Results.prepare(o, ContextQueryAdmitted)
	if err != nil {
		return nil, err
	}
	owned = true
	return d, nil
}

// GetQueryResult has no reference to ContextProjectionWorkerAdmission.
// A paid poll and fresh authorization precede status as well as evidence output.
func (s ContextProjectionResults) GetQueryResult(ctx context.Context, current identities.CurrentIdentity, invocation ContextQueryInvocation, queryID string) (*ContextProjectionDelivery, error) {
	if !authorization.UUID(queryID) {
		return nil, value.ErrInvalid
	}
	o, err := s.request(ctx, current, invocation, "get_query_result")
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			o.cancel()
		}
	}()
	if err = invocation.CheckInput(o.ctx, ContextQueryInput{QueryID: queryID}); err != nil {
		return nil, value.ErrUnavailable
	}
	q, err := s.Ledger.LookupQuery(o.ctx, o.initial.Principal, queryID)
	if err != nil || !q.Valid() || q.ID != queryID || q.Scope.RootID != s.RootID || q.Scope.Principal != o.initial.Principal {
		return nil, value.ErrUnavailable
	}
	o.query = q
	a, err := o.CheckCurrent(o.ctx)
	if err != nil {
		return nil, err
	}
	if err = s.Ledger.AdmitQueryPoll(o.ctx, q, o.request, a); err != nil {
		return nil, value.ErrUnavailable
	}
	d, err := s.prepare(o, ContextQueryPollCharged)
	if err != nil {
		return nil, err
	}
	owned = true
	return d, nil
}

func (s ContextProjectionResults) prepare(o *projectionRequest, effect ContextQueryEffect) (*ContextProjectionDelivery, error) {
	if _, err := o.CheckCurrent(o.ctx); err != nil {
		return nil, err
	}
	worker, err := s.Reader.ObserveProjectionWorker(o.ctx, o.query, o)
	if err != nil || !identity.Fresh(worker.ObservedAt, worker.ValidUntil, s.Now(), 5*time.Second) || !o.shorten(worker.ValidUntil) {
		return nil, value.ErrUnavailable
	}
	a, err := o.CheckCurrent(o.ctx)
	if err != nil {
		return nil, err
	}
	if err = s.Ledger.PermitQuery(o.ctx, o.query, o.request, a); err != nil {
		return nil, value.ErrUnavailable
	}
	a, err = o.CheckCurrent(o.ctx)
	if err != nil {
		return nil, err
	}
	d := &ContextProjectionDelivery{owner: o, pending: !worker.Ready, effect: effect,
		observedAt: s.Now(), queryDeadline: identity.Earlier(o.query.Deadline, a.AccessUntil),
		cleanupUntil: identity.Earlier(o.query.CleanupUntil, o.request.Call.WriteUntil),
		association:  ContextProjectionAssociation{ID: s.NewID(), QueryID: o.query.ID, OperationID: o.request.Call.ID, Selection: o.query.Scope.Selection}}
	if !authorization.UUID(d.association.ID) {
		return nil, value.ErrUnavailable
	}
	if !worker.Ready {
		if worker.Worker != (value.ContextQueryWorker{}) {
			return nil, value.ErrUnavailable
		}
		if _, err = o.CheckCurrent(o.ctx); err != nil {
			return nil, err
		}
		return d, nil
	}
	if !worker.Worker.Matches(o.query) {
		return nil, value.ErrUnavailable
	}
	batchID := s.NewID()
	if !authorization.UUID(batchID) {
		return nil, value.ErrUnavailable
	}
	admitted, err := s.Ledger.BeginReadBatch(o.ctx, o.query, o.request, worker.Worker, batchID, a)
	b := admitted.Batch
	if err != nil || !admitted.Fresh || !b.Current(o.query, a, s.Now()) || b.Until.After(a.ValidUntil) || b.ID != batchID || b.Worker != worker.Worker || b.Request != o.request {
		return nil, value.ErrUnavailable
	}
	a, err = o.CheckCurrent(o.ctx)
	if err != nil {
		return nil, err
	}
	if !o.shorten(b.Until) {
		return nil, value.ErrExpired
	}
	start, err := s.Ledger.ClaimReadBatch(o.ctx, b, a)
	if err != nil || !start.Fresh || !start.Batch.Equal(b) || !authorization.UUID(start.ClaimID) {
		return nil, value.ErrUnavailable
	}
	if _, err = o.CheckCurrent(o.ctx); err != nil {
		return nil, err
	}
	d.batch = &b
	d.effect = ContextQueryReadCharged
	d.association.BatchID, d.association.Generation = b.ID, b.Generation
	// No retry is possible after this one-use claim. A missing handle on an
	// uncertain reply remains charged for independently protected cleanup.
	d.read, err = s.Reader.ReadProjection(o.ctx, start, o)
	if err != nil || d.read == nil {
		if d.read != nil {
			_ = d.Close(context.WithoutCancel(o.ctx))
		}
		return nil, value.ErrUnavailable
	}
	if _, err = o.CheckCurrent(o.ctx); err != nil {
		_ = d.Close(context.WithoutCancel(o.ctx))
		return nil, err
	}
	projection, err := d.read.Projection(o.ctx)
	if err == nil && projection.NamespaceUID == o.query.Scope.NamespaceUID && projection.PodUID == o.query.Scope.PodUID {
		d.excerpt, err = FormatContextExcerpt(projection, o.query.Scope.Selection)
	} else {
		err = value.ErrUnavailable
	}
	projection = value.PodStatusProjection{}
	if err == nil {
		_, err = o.CheckCurrent(o.ctx)
	}
	if err == nil {
		err = d.read.CheckCurrent(o.ctx)
	}
	if err == nil {
		_, err = o.CheckCurrent(o.ctx)
	}
	if err != nil {
		_ = d.Close(context.WithoutCancel(o.ctx))
		return nil, value.ErrUnavailable
	}
	return d, nil
}
