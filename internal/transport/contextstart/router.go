package contextstart

import (
	"context"
	"errors"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
)

// ClusterLimit is an installed finite reservation, not a request parameter.
// Reservations cannot overcommit the whole-process caps, so one cluster cannot
// take the standby or active capacity reserved for another cluster.
type ClusterLimit struct {
	ClusterID         string
	Standby, Captures int
}
type RouterLimits struct {
	Standby, Captures int
	Clusters          []ClusterLimit
}
type clusterCount struct {
	limit             ClusterLimit
	standby, captures int
}
type Router struct {
	mu       sync.Mutex
	closed   bool
	limits   RouterLimits
	clusters map[string]*clusterCount
	standby  map[string]*Standby
	captures map[string]*Attachment
	serial   uint64
	// registered is closed and replaced when a standby registers or a query
	// releases it, so a waiting query can retry within its original reserve.
	registered chan struct{}
}

// queryReserve is the part of a query's original deadline kept for the query
// itself and the caller's later checks when waiting for a standby to register.
const queryReserve = 2500 * time.Millisecond

// standbyMargin is the residency a selected standby must keep beyond the work's
// own deadline. The region's exchange began, and ends, its opening's setup
// (about a second) before this registration; near that end the region cuts its
// observations to it and the exchange closes mid-work (installed native:
// headroom refusals with seconds left, stream loss before preparation).
const standbyMargin = 3 * time.Second

// standbyWork is the longest work or query deadline Attach and Query accept.
// An idle standby that can no longer cover it is retired, so the region opens
// its replacement at once instead of at the end of the full residency.
const standbyWork = 5 * time.Second

// selectLocked returns the idle live standby of cluster with the latest
// residency end still covering until plus standbyMargin, or nil. The newest
// standby is preferred: the oldest is the one about to end. It only reads.
func (r *Router) selectLocked(cluster string, until time.Time, eligible func(*Standby) bool) *Standby {
	var selected *Standby
	var end time.Time
	for _, s := range r.standby {
		d, ok := s.ctx.Deadline()
		if !ok || s.channel.Connector.Binding.ClusterID != cluster || s.attached || s.queryBusy || !eligible(s) || !s.liveLocked() || d.Before(until.Add(standbyMargin)) {
			continue
		}
		if selected == nil || d.After(end) || d.Equal(end) && s.order > selected.order {
			selected, end = s, d
		}
	}
	return selected
}

// pruneLocked retires the idle standbys of cluster that can no longer cover
// any work, so the region opens their replacements at once. Attach and Query
// call it before selecting; each standby's own timer does the same.
func (r *Router) pruneLocked(cluster string) {
	for _, s := range r.standby {
		if s.channel.Connector.Binding.ClusterID == cluster {
			s.retireIdleLocked()
		}
	}
}

// ReceiverCheck rechecks the same actual TLS peer and accepted local process.
// A successful fresh check may authorize attachment, never restore a lost human
// owner. The channel identity must remain exactly the original registered one.
type ReceiverCheck = app.APIContextReceiverCheck
type Standby struct {
	router    *Router
	channel   fleet.APIContextChannel
	check     ReceiverCheck
	order     uint64
	ctx       context.Context
	cancel    context.CancelFunc
	job       chan *captureJob
	query     chan *queryJob
	done      chan struct{}
	attached  bool
	queryBusy bool
	queries   int
	retire    *time.Timer
	once      sync.Once
	// Protected by router.mu. Selection observes stream cancellation directly,
	// including the interval before its cancellation callback runs.
	streamDone <-chan struct{}
}
type queryJob struct {
	ctx     context.Context
	method  string
	in, out any
	result  chan queryResult
}
type queryResult struct {
	until time.Time
	err   error
}
type captureJob struct {
	ctx    context.Context
	work   fleet.APIContextWork
	signed []byte
	// run is the ADR-171 hub-run execution over this exchange's operations.
	run    func(context.Context, *HubOperations) (string, error)
	result chan jobResult
}
type jobResult struct {
	state string
	err   error
}
type Attachment struct {
	router             *Router
	standby            *Standby
	capture            string
	ctx                context.Context
	cancel             context.CancelFunc
	mu                 sync.Mutex
	dispatched, closed bool
	work               sync.WaitGroup
	once               sync.Once
}

func NewRouter(l RouterLimits) (*Router, error) {
	if l.Standby < 1 || l.Standby > 64 || l.Captures < 1 || l.Captures > 16 || len(l.Clusters) > 16 {
		return nil, fleet.ErrInvalid
	}
	clusters := make(map[string]*clusterCount, len(l.Clusters))
	standby, captures := 0, 0
	for _, c := range l.Clusters {
		if !authorization.UUID(c.ClusterID) || c.Standby < 1 || c.Standby > 16 || c.Captures < 1 || c.Captures > 16 || clusters[c.ClusterID] != nil {
			return nil, fleet.ErrInvalid
		}
		standby += c.Standby
		captures += c.Captures
		clusters[c.ClusterID] = &clusterCount{limit: c}
	}
	if standby > l.Standby || captures > l.Captures {
		return nil, fleet.ErrInvalid
	}
	l.Clusters = append([]ClusterLimit(nil), l.Clusters...)
	return &Router{limits: l, clusters: clusters, standby: make(map[string]*Standby), captures: make(map[string]*Attachment), registered: make(chan struct{})}, nil
}

// RegisterStandby runs only after actual TLS authentication, before any human
// request attaches. The handler must call Finish only after its stream joins.
func (r *Router) RegisterStandby(ctx context.Context, receiver fleet.APIContextReceiver, check ReceiverCheck) (*Standby, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || check == nil || !receiver.Valid(time.Now()) {
		return nil, fleet.ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cluster := r.clusters[receiver.Channel.Connector.Binding.ClusterID]
	if r.closed || cluster == nil || len(r.standby) >= r.limits.Standby || cluster.standby >= cluster.limit.Standby || r.standby[receiver.Channel.ExchangeID] != nil {
		return nil, fleet.ErrCapacity
	}
	// This bounds passive socket residency, not an authority interval. Attachment
	// below always independently rechecks current peer/route/process facts.
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	r.serial++
	s := &Standby{router: r, channel: receiver.Channel, check: check, order: r.serial, ctx: call, cancel: cancel, job: make(chan *captureJob, 1), query: make(chan *queryJob), done: make(chan struct{})}
	if end, ok := call.Deadline(); ok {
		if usable := time.Until(end.Add(-(standbyWork + standbyMargin))); usable > 0 {
			s.retire = time.AfterFunc(usable, func() {
				r.mu.Lock()
				defer r.mu.Unlock()
				s.retireIdleLocked()
			})
		}
	}
	r.standby[s.channel.ExchangeID] = s
	cluster.standby++
	close(r.registered)
	r.registered = make(chan struct{})
	return s, nil
}
func (s *Standby) Context() context.Context { return s.ctx }

// retireIdleLocked ends an idle standby that can no longer cover any work, so
// its handler returns and the region opens a replacement. Attached or querying
// standbys are left to their own work.
func (s *Standby) retireIdleLocked() {
	end, ok := s.ctx.Deadline()
	if ok && !s.attached && !s.queryBusy && end.Before(time.Now().Add(standbyWork+standbyMargin)) {
		s.cancel()
	}
}
func (s *Standby) liveLocked() bool {
	if s.ctx.Err() != nil {
		return false
	}
	select {
	case <-s.streamDone:
		return false
	default:
		return true
	}
}
func (s *Standby) Finish() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		s.cancel()
		if s.retire != nil {
			s.retire.Stop()
		}
		s.router.mu.Lock()
		if s.router.standby[s.channel.ExchangeID] == s {
			delete(s.router.standby, s.channel.ExchangeID)
			s.router.clusters[s.channel.Connector.Binding.ClusterID].standby--
		}
		s.check = nil
		select {
		case pending := <-s.job:
			clear(pending.signed)
			pending.run = nil
			pending.result <- jobResult{err: fleet.ErrUnavailable}
		default:
		}
		s.router.mu.Unlock()
		close(s.done)
	})
}
func (s *Standby) Serve(stream Stream, now func() time.Time) error {
	if s == nil || stream == nil || now == nil {
		return fleet.ErrInvalid
	}
	streamCtx := stream.Context()
	if streamCtx == nil {
		return fleet.ErrInvalid
	}
	s.router.mu.Lock()
	s.streamDone = streamCtx.Done()
	s.router.mu.Unlock()
	// A stream can die before the surrounding HTTP request is cancelled.
	// Withdraw it immediately, but keep both reservations until the handler
	// joins stream.Close and calls Finish. Active work also sees this cancellation.
	ended := make(chan struct{})
	stopStream := context.AfterFunc(streamCtx, func() { s.cancel(); close(ended) })
	defer func() {
		if !stopStream() {
			<-ended
		}
	}()
	for {
		select {
		case job := <-s.job:
			// Parent cancellation remains linked for the full conversation; completion
			// waits for this handler and its socket owner before the capture slot frees.
			call, cancel := context.WithCancel(job.ctx)
			stop := context.AfterFunc(s.ctx, cancel)
			state, e := ServeHubOperations(call, stream, job.work, job.signed, job.run, now)
			stop()
			cancel()
			clear(job.signed)
			job.run = nil
			job.result <- jobResult{state, e}
			return e
		case q := <-s.query:
			// ADR-179: a pre-work query leaves the standby waiting for work
			// unless it broke the stream.
			fs, ok := stream.(*frameStream)
			if !ok {
				s.cancel()
				q.result <- queryResult{err: fleet.ErrUnavailable}
				return fleet.ErrUnavailable
			}
			call, cancel := context.WithCancel(q.ctx)
			stop := context.AfterFunc(s.ctx, cancel)
			until, e := fs.query(call, q.method, q.in, q.out)
			stop()
			cancel()
			var answer errQueryAnswer
			if e != nil && !errors.As(e, &answer) {
				recordStreamDiagnostic(q.ctx, fs, e, streamHubQuery)
				// Withdraw before result publication releases query ownership.
				// The handler still owns joined socket cleanup and Finish.
				s.cancel()
			}
			q.result <- queryResult{until, e}
			if e != nil && !errors.As(e, &answer) {
				return e
			}
		case <-s.ctx.Done():
			return fleet.ErrUnavailable
		}
	}
}

// Query asks one idle standby of the cluster a pre-work target question
// (ADR-179). It returns the region receiver's checked validity, which bounds
// the use of the answer.
func (r *Router) Query(ctx context.Context, cluster, method string, in, out any) (time.Time, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(cluster) {
		return time.Time{}, fleet.ErrInvalid
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) || deadline.After(time.Now().Add(5*time.Second)) {
		return time.Time{}, fleet.ErrInvalid
	}
	// Between a standby's bounded residency and the region's next opening no
	// standby may be idle. Wait for a registration within this query's original
	// deadline, keeping queryReserve for the query and the caller (native 66).
	var selected *Standby
	for {
		r.mu.Lock()
		r.pruneLocked(cluster)
		selected = r.selectLocked(cluster, deadline, func(s *Standby) bool { return s.queries < contracts.APIContextMaximumQueries })
		if r.closed {
			r.mu.Unlock()
			return time.Time{}, fleet.ErrUnavailable
		}
		if selected != nil {
			selected.queries++
			selected.queryBusy = true
			r.mu.Unlock()
			break
		}
		registered := r.registered
		r.mu.Unlock()
		wait := time.Until(deadline.Add(-queryReserve))
		if wait <= 0 {
			return time.Time{}, fleet.ErrUnavailable
		}
		timer := time.NewTimer(wait)
		select {
		case <-registered:
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			return time.Time{}, fleet.ErrUnavailable
		case <-timer.C:
			return time.Time{}, fleet.ErrUnavailable
		}
	}
	defer func() {
		r.mu.Lock()
		selected.queryBusy = false
		selected.retireIdleLocked()
		if !r.closed && selected.liveLocked() {
			close(r.registered)
			r.registered = make(chan struct{})
		}
		r.mu.Unlock()
	}()
	job := &queryJob{ctx: ctx, method: method, in: in, out: out, result: make(chan queryResult, 1)}
	select {
	case selected.query <- job:
	case <-ctx.Done():
		return time.Time{}, fleet.ErrUnavailable
	case <-selected.ctx.Done():
		return time.Time{}, fleet.ErrUnavailable
	}
	// After handoff, cancellation cannot release ownership before the actual
	// query and its finite I/O callbacks have joined.
	result := <-job.result
	return result.until, result.err
}
func (r *Router) Attach(ctx context.Context, cluster, capture string) (*Attachment, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(cluster) || !authorization.UUID(capture) {
		return nil, fleet.ErrInvalid
	}
	// Even a miscomposed caller cannot hold a live capture slot indefinitely.
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) || deadline.After(time.Now().Add(5*time.Second)) {
		return nil, fleet.ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.clusters[cluster]
	if r.closed || c == nil || len(r.captures) >= r.limits.Captures || c.captures >= c.limit.Captures || r.captures[capture] != nil {
		return nil, fleet.ErrCapacity
	}
	r.pruneLocked(cluster)
	selected := r.selectLocked(cluster, deadline, func(*Standby) bool { return true })
	if selected == nil {
		return nil, fleet.ErrUnavailable
	}
	selected.attached = true
	call, cancel := context.WithDeadline(ctx, deadline)
	a := &Attachment{router: r, standby: selected, capture: capture, ctx: call, cancel: cancel}
	r.captures[capture] = a
	c.captures++
	return a, nil
}
func (a *Attachment) Receiver(ctx context.Context) (fleet.APIContextReceiver, error) {
	if a == nil || ctx == nil || ctx.Err() != nil {
		return fleet.APIContextReceiver{}, fleet.ErrInvalid
	}
	a.mu.Lock()
	closed := a.closed
	if !closed {
		a.work.Add(1)
	}
	a.mu.Unlock()
	if !closed {
		defer a.work.Done()
	}
	a.router.mu.Lock()
	check := a.standby.check
	live := a.standby.liveLocked()
	a.router.mu.Unlock()
	if closed || check == nil || a.ctx.Err() != nil || !live {
		return fleet.APIContextReceiver{}, fleet.ErrUnavailable
	}
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(a.ctx, cancel)
	defer func() { stop(); cancel() }()
	receiver, e := check(call)
	a.router.mu.Lock()
	live = a.standby.liveLocked()
	a.router.mu.Unlock()
	if e != nil || call.Err() != nil || a.ctx.Err() != nil || !live || !receiver.Valid(time.Now()) || receiver.Channel != a.standby.channel {
		return fleet.APIContextReceiver{}, fleet.ErrUnavailable
	}
	if d, ok := a.ctx.Deadline(); ok && d.Before(receiver.ValidUntil) {
		receiver.ValidUntil = d
	}
	if !receiver.Valid(time.Now()) {
		return fleet.APIContextReceiver{}, fleet.ErrUnavailable
	}
	return receiver, nil
}

// Run sends the signed work and runs run on the hub with this exchange's
// regional operations (ADR-171). The region asks no identity questions.
func (a *Attachment) Run(w fleet.APIContextWork, signed []byte, run func(context.Context, *HubOperations) (string, error)) (string, error) {
	if run == nil {
		return "", fleet.ErrInvalid
	}
	return a.dispatch(w, signed, run)
}

func (a *Attachment) dispatch(w fleet.APIContextWork, signed []byte, run func(context.Context, *HubOperations) (string, error)) (string, error) {
	if a == nil || !w.Valid(time.Now()) || w.Channel != a.standby.channel || w.CaptureID != a.capture || len(signed) == 0 {
		return "", fleet.ErrInvalid
	}
	a.mu.Lock()
	if a.closed || a.dispatched || a.ctx.Err() != nil || a.standby.ctx.Err() != nil {
		a.mu.Unlock()
		return "", fleet.ErrUnavailable
	}
	a.router.mu.Lock()
	if a.router.standby[a.standby.channel.ExchangeID] != a.standby || !a.standby.liveLocked() {
		a.router.mu.Unlock()
		a.mu.Unlock()
		return "", fleet.ErrUnavailable
	}
	a.dispatched = true
	a.work.Add(1)
	defer a.work.Done()
	job := &captureJob{ctx: a.ctx, work: w, signed: append([]byte(nil), signed...), run: run, result: make(chan jobResult, 1)}
	a.standby.job <- job
	a.router.mu.Unlock()
	a.mu.Unlock()
	select {
	case result := <-job.result:
		return result.state, result.err
	case <-a.ctx.Done():
		return "", fleet.ErrUnavailable
	case <-a.standby.ctx.Done():
		return "", fleet.ErrUnavailable
	}
}

// Close does not release a slot until the actual handler/socket finishes. It
// also covers a signed work whose delivery/result became uncertain.
func (a *Attachment) Close() {
	if a == nil {
		return
	}
	a.once.Do(func() {
		a.mu.Lock()
		a.closed = true
		a.cancel()
		a.standby.cancel()
		a.mu.Unlock()
		a.work.Wait()
		<-a.standby.done
		a.router.mu.Lock()
		if a.router.captures[a.capture] == a {
			delete(a.router.captures, a.capture)
			a.router.clusters[a.standby.channel.Connector.Binding.ClusterID].captures--
		}
		a.router.mu.Unlock()
	})
}
func (r *Router) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	connections := make([]*Standby, 0, len(r.standby))
	for _, s := range r.standby {
		connections = append(connections, s)
		s.cancel()
	}
	active := make([]*Attachment, 0, len(r.captures))
	for _, a := range r.captures {
		active = append(active, a)
	}
	r.mu.Unlock()
	for _, s := range connections {
		<-s.done
	}
	for _, a := range active {
		a.Close()
	}
}
