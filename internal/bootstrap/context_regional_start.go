package bootstrap

import (
	"asservat.local/asservat/internal/transport/connectorlifecycle"
	"context"
	"errors"
	"math/rand/v2"
	"sync"

	auditapp "asservat.local/asservat/internal/application/audit"

	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	captureapp "asservat.local/asservat/internal/application/capture"
	executionapp "asservat.local/asservat/internal/application/execution"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	execution "asservat.local/asservat/internal/domain/execution"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/contextstart"
)

// RegionalAPIContextStart is the hub half of the synchronous Start port. It
// runs the API context runner with the hub's own SQL/authority ports
// (ADR-171); the attached regional exchange supplies only cluster-local
// operations. It holds no collector, wrapper, evidence reader or provider key.
// Historical Request replay never calls this port; explicit fresh-current
// Continue remains a caller decision.
type RegionalAPIContextStart struct {
	Runner executionapp.APIContextRunner // hub ports; cluster-local ports are per exchange
	Router *contextstart.Router
	Now    func() time.Time
	// Report receives a failed run's fixed step and error class; diagnostics
	// only, nil leaves it silent.
	Report func(string)
}

var _ captureapp.ContextAcceptedStart = RegionalAPIContextStart{}

// startRetryLeft is the least remaining start interval for which a not-started
// attempt is repeated: an attach wait, the receiver check, signing and the
// ADR-212 one-second floor before the first preparation insert.
const startRetryLeft = 2 * time.Second

// startRetryPause spaces repeated attempts; startAttempts bounds them.
const (
	startRetryPause = 250 * time.Millisecond
	startAttempts   = 3
)

// StartContext repeats an attempt that ended not started (only reads
// happened, no SQL preparation was entered and the attachment joined) while
// the first attempt's interval keeps startRetryLeft. A standby exchange lost
// mid-run otherwise left an admitted Save Pending until its caller continued.
// Every attempt runs inside that one interval and the caller's context: no
// deadline is renewed, and a prepared, denied, expired or uncertain run is
// never repeated (ADR-250).
func (s RegionalAPIContextStart) StartContext(ctx context.Context, current identities.CurrentIdentity, id string) error {
	if ctx == nil || ctx.Err() != nil || current == nil || !authorization.UUID(id) || s.Runner.Read == nil || s.Runner.Capabilities == nil || s.Router == nil || s.Now == nil {
		return execution.ErrInvalid
	}
	window, cancel := context.WithDeadline(ctx, s.Now().UTC().Truncate(time.Microsecond).Add(identity.AuthorityRecheckInterval)) // ADR-311
	defer cancel()
	until, _ := window.Deadline()
	for attempt := 1; ; attempt++ {
		err := s.startOnce(window, current, id)
		if !errors.Is(err, capturevalue.ErrAcquisitionNotStarted) || attempt == startAttempts || until.Sub(s.Now()) < startRetryLeft+startRetryPause {
			return err
		}
		if s.Report != nil {
			s.Report("retry not-started start-left" + fleetapp.RemainingBucket(window, s.Now()))
		}
		pause := time.NewTimer(startRetryPause)
		select {
		case <-window.Done():
			pause.Stop()
			return err
		case <-pause.C:
		}
	}
}

func (s RegionalAPIContextStart) startOnce(ctx context.Context, current identities.CurrentIdentity, id string) error {
	// Diagnostics only: the joined conversation's first stream interruption.
	ctx, diagnostics := contextstart.NewStreamDiagnosticContext(ctx)
	// A temporary unavailability before the run, or a run that failed as
	// temporarily unavailable without entering the one-use SQL preparation
	// (or whose preparation rolled back before its insert, ADR-212), leaves
	// the admitted capture unstarted: only reads happened, so an explicit
	// continuation may start it (ADR-134/250). A denial, expiry or any other
	// run failure keeps its own class.
	notStarted := errors.Join(execution.ErrUnavailable, capturevalue.ErrAcquisitionNotStarted)
	// Dispatch can return early, without joining the run, when its exchange
	// or attachment ends; the gate then refuses any later preparation.
	gate := &preparationGate{}
	started := s.Now().UTC().Truncate(time.Microsecond)
	call, cancel := context.WithDeadline(ctx, started.Add(identity.AuthorityRecheckInterval)) // ADR-311
	defer cancel()
	until, _ := call.Deadline()
	var cancels []context.CancelFunc
	defer func() {
		for i := len(cancels) - 1; i >= 0; i-- {
			cancels[i]()
		}
	}()
	// The initial context may already be shorter than this start's interval.
	// Later names identify only an input that actually shortens that bound.
	bound := regionalStartInitialBound(ctx, started)
	narrow := func(name string, d time.Time) {
		if d.Before(until) {
			bound = name
		}
		until = identity.Earlier(until, d)
		var stop context.CancelFunc
		call, stop = context.WithDeadline(call, until)
		cancels = append(cancels, stop)
	}
	// Fixed step durations for the operation's timing line; diagnostics only.
	var mark time.Time
	caller, e := current.ResolveIdentity(call)
	if e != nil || !caller.Valid(s.Now()) {
		return execution.ErrDenied
	}
	narrow("identity", caller.ValidUntil)
	mark = time.Now()
	accepted, e := s.Runner.Read.ReadAPIContextWork(call, id, caller)
	auditapp.MarkStep(ctx, "st-read", mark)
	if e != nil {
		return e
	}
	a := accepted.Accepted
	if accepted.Actor != caller.Principal || a.CaptureID != id || accepted.Target.ClusterID != a.Expectation.Registration.Location.ClusterID {
		return execution.ErrDenied
	}
	narrow("deadline", a.Deadline)
	narrow("write-until", a.Expectation.Registration.WriteUntil)
	target := authorization.Target{ClusterID: accepted.Target.ClusterID, NamespaceUID: accepted.Target.Namespace.UID, WorkloadUID: accepted.Target.Workload.UID, PodUID: accepted.Target.PodUID}
	mark = time.Now()
	capability, e := s.Runner.Capabilities.ContextCapability(call, target)
	auditapp.MarkStep(ctx, "st-capability", mark)
	if e != nil || !capability.Valid(s.Now()) {
		return notStarted
	}
	narrow("capability", capability.FreshUntil)
	// Reservation happens before signing/attachment. A closing old exchange stays
	// charged until its original socket and human owner have actually joined.
	mark = time.Now()
	attachment, e := s.Router.Attach(call, target.ClusterID, id)
	auditapp.MarkStep(ctx, "st-attach", mark)
	if e != nil {
		if s.Report != nil {
			reason := "unavailable"
			if errors.Is(e, fleetvalue.ErrCapacity) {
				reason = "capacity"
			} else if errors.Is(e, fleetvalue.ErrInvalid) {
				reason = "invalid"
			}
			s.Report("attach (" + reason + ") start-left" + fleetapp.RemainingBucket(call, s.Now()) + " bound=" + bound + " " + s.Router.AttachState(target.ClusterID))
		}
		return notStarted
	}
	defer attachment.Close()
	mark = time.Now()
	receiver, e := attachment.Receiver(call)
	auditapp.MarkStep(ctx, "st-receiver", mark)
	if e != nil {
		return notStarted
	}
	narrow("receiver", receiver.Window.Until())
	work, e := executionapp.NewAPIContextWork(accepted, receiver.Channel, capability, started, until, s.Now())
	if e != nil {
		return e
	}
	// Every prior blocking read retains its original bounds. The same
	// retained CurrentIdentity answers regional requests on this attachment.
	if call.Err() != nil || !s.Now().Before(until) {
		return execution.ErrUnavailable // the original interval ended: not retryable as not-started
	}
	mark = time.Now()
	outer := ctx
	state, e := attachment.Run(work, func(ctx context.Context, ops *contextstart.HubOperations) (string, error) {
		ops.Timing = func(method string, d time.Duration) { auditapp.MarkDuration(outer, "op-"+method, d) }
		r := s.Runner
		r.Process, r.Targets, r.Output, r.Collector = ops, ops, ops, ops
		r.Prepare = gatedPreparer{r.Prepare, gate}
		result, err := r.ExecuteObserved(ctx, current, caller, accepted, capability)
		gate.finish(err)
		if err != nil && s.Report != nil {
			step := "execute"
			var fixed interface{ FixedStep() string }
			if errors.As(err, &fixed) {
				step += "/" + fixed.FixedStep()
			}
			s.Report(step + " (" + regionalOutcome(err) + ") left" + fleetapp.RemainingBucket(ctx, s.Now()) + " start-left" + fleetapp.RemainingBucket(call, s.Now()) + " bound=" + bound)
		}
		switch {
		case err == nil && (result.State == "Published" || result.State == "AlreadyStarted" || result.State == "Recording"):
			return result.State, nil
		case errors.Is(err, execution.ErrPreparationUncertain):
			return "PreparationUncertain", err
		}
		return "Unavailable", err
	})
	auditapp.MarkStep(ctx, "st-run", mark)
	gate.close()
	if e != nil && state == "" {
		if s.Report != nil {
			// Join the conversation first so its stream stage is recorded;
			// the deferred Close is then a no-op.
			left := fleetapp.RemainingBucket(call, s.Now())
			attachment.Close()
			s.Report("dispatch (" + regionalOutcome(e) + ") start-left" + left + " bound=" + bound + streamInterruptionLabel(diagnostics))
		}
		if gate.notStarted() {
			return notStarted
		}
		return execution.ErrUnavailable
	}
	switch state {
	case "Published", "AlreadyStarted", "Recording":
		// ADR-248: a recording continues on the node; RegionalRecordingCollect
		// records its outcome after a later collect exchange.
		return nil
	case "PreparationUncertain":
		return capturevalue.ErrPreparationUncertain
	}
	if gate.notStarted() {
		return notStarted
	}
	return execution.ErrUnavailable
}

// streamInterruptionLabel names a recorded first stream interruption by its
// fixed stage and reason codes only.
func streamInterruptionLabel(d *contextstart.StreamDiagnostics) string {
	if v := d.Interruption(); v.Present() {
		return " stream=" + v.Stage() + "/" + v.Reason()
	}
	return ""
}

// preparationGate records whether a run entered the one-use SQL preparation
// and how the run ended. A preparation refused before its insert (ADR-212
// headroom) does not count. After close no preparation begins.
type preparationGate struct {
	mu                       sync.Mutex
	closed, active, finished bool
	runErr                   error
}

func (g *preparationGate) finish(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.finished, g.runErr = true, err
}

// notStarted is true after close for a run that never entered preparation
// and either failed as temporarily unavailable or was abandoned when its
// exchange ended. A denied, expired or otherwise definite run never is.
func (g *preparationGate) notStarted() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed && !g.active && (!g.finished || executionapp.TemporarilyUnavailable(g.runErr))
}

func (g *preparationGate) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.active = true
	return true
}

func (g *preparationGate) rolledBack() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed {
		g.active = false
	}
}

func (g *preparationGate) close() (entered bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return g.active
}

type gatedPreparer struct {
	executionapp.APIExecutionPreparer
	gate *preparationGate
}

func (p gatedPreparer) PrepareAPIExecution(ctx context.Context, c executionapp.APIExecutionCheck) (execution.APIExecution, bool, error) {
	if !p.gate.enter() {
		return execution.APIExecution{}, false, errors.Join(execution.ErrUnavailable, execution.ErrNotStarted)
	}
	r, first, err := p.APIExecutionPreparer.PrepareAPIExecution(ctx, c)
	if err != nil && errors.Is(err, execution.ErrNotStarted) {
		p.gate.rolledBack()
	}
	return r, first, err
}

func (p gatedPreparer) PreparePolicyRecording(ctx context.Context, c executionapp.APIExecutionCheck, source targets.PacketSourceObservation) (execution.APIExecution, bool, collector.ObservationPermit, error) {
	preparer, ok := p.APIExecutionPreparer.(executionapp.PolicyRecordingPreparer)
	if !ok || !p.gate.enter() {
		return execution.APIExecution{}, false, collector.ObservationPermit{}, errors.Join(execution.ErrUnavailable, execution.ErrNotStarted)
	}
	r, first, permit, err := preparer.PreparePolicyRecording(ctx, c, source)
	if err != nil && errors.Is(err, execution.ErrNotStarted) {
		p.gate.rolledBack()
	}
	return r, first, permit, err
}

func (p gatedPreparer) PrepareArgumentRecording(ctx context.Context, c executionapp.APIExecutionCheck, source targets.PacketSourceObservation) (execution.APIExecution, bool, collector.ArgumentObservationPermit, error) {
	preparer, ok := p.APIExecutionPreparer.(executionapp.ArgumentRecordingPreparer)
	if !ok || !p.gate.enter() {
		return execution.APIExecution{}, false, collector.ArgumentObservationPermit{}, errors.Join(execution.ErrUnavailable, execution.ErrNotStarted)
	}
	r, first, permit, err := preparer.PrepareArgumentRecording(ctx, c, source)
	if err != nil && errors.Is(err, execution.ErrNotStarted) {
		p.gate.rolledBack()
	}
	return r, first, permit, err
}

// Diagnostic only: a retained caller deadline is not a fresh start interval.
func regionalStartInitialBound(ctx context.Context, started time.Time) string {
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(started.Add(identity.AuthorityRecheckInterval)) {
		return "parent"
	}
	return "start"
}

// ServeRegionalAPIContextExchange owns one outbound exchange until all regional
// operations and stream I/O join. It does not reconnect or retry uncertain
// work. It answers only cluster-local operations for the received work.
func ServeRegionalAPIContextExchange(exchange *mtls.ContextStartExchange, local contextstart.RegionalLocal) error {
	if exchange == nil || local.Now == nil {
		return execution.ErrInvalid
	}
	defer exchange.Close()
	response, writer, connection, e := exchange.IO()
	if e != nil {
		return e
	}
	receiver := exchange.Receiver()
	stream, e := contextstart.NewOutboundStream(exchange.Context(), receiver.Channel, exchange.Check, local.Targets, local.Sources, response, writer, connection, exchange.Close)
	if e != nil {
		return e
	}
	defer stream.Close()
	ctx, diagnostics := contextstart.NewStreamDiagnosticContext(exchange.Context())
	if e = contextstart.ServeRegionalOperations(ctx, stream, receiver, local, local.Now); e != nil {
		if v := diagnostics.Interruption(); v.Present() {
			return exchangeStepError{e, v.Stage() + "/" + v.Reason()}
		}
	}
	return e
}

// exchangeStepError carries only the stream's fixed stage/reason codes.
type exchangeStepError struct {
	error
	step string
}

func (e exchangeStepError) Unwrap() error        { return e.error }
func (e exchangeStepError) ExchangeStep() string { return e.step }

type regionalWorkWatch func(context.Context, func(connectorlifecycle.WorkHint)) (bool, error)

// RegionalContextStartConnections opens work exchanges only when a hub owner
// has a waiting request. The connector never replays a capture on reconnect.
type RegionalContextStartConnections struct {
	Watch  regionalWorkWatch
	Client interface {
		OpenRequested(context.Context, fleetvalue.OwnerBinding, time.Time) (*mtls.ContextStartExchange, error)
		Close()
	}
	Local         contextstart.RegionalLocal
	Concurrency   int
	Report        func(string)
	ReportOpening func(string, time.Duration, time.Duration, string)
}

func (s RegionalContextStartConnections) Run(ctx context.Context) error {
	if ctx == nil || s.Watch == nil || s.Client == nil || s.Local.Now == nil || s.Concurrency < 1 {
		return execution.ErrInvalid
	}
	defer s.Client.Close()
	var tasks sync.WaitGroup
	defer tasks.Wait()
	slots := make(chan struct{}, s.Concurrency)
	receive := func(hint connectorlifecycle.WorkHint) {
		timer := time.NewTimer(time.Until(hint.Until))
		defer timer.Stop()
		select {
		case slots <- struct{}{}:
		case <-timer.C:
			return
		case <-ctx.Done():
			return
		}
		tasks.Go(func() {
			defer func() { <-slots }()
			call, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			exchange, err := s.Client.OpenRequested(call, hint.Owner, hint.Until)
			if err != nil {
				s.reportFailure("open", err)
				return
			}
			if err := ServeRegionalAPIContextExchange(exchange, s.Local); err != nil {
				s.reportFailure("exchange", err)
			}
		})
	}
	return reconnectRegional(ctx, func() (bool, error) { return s.Watch(ctx, receive) }, func(err error) { s.reportFailure("work-stream", err) })
}

func reconnectRegional(ctx context.Context, subscribe func() (bool, error), report func(error)) error {
	backoff := time.Second
	for ctx.Err() == nil {
		connected, err := subscribe()
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			report(err)
		}
		if connected {
			backoff = time.Second
		}
		// Jitter each reconnect, including at the ceiling, to spread a fleet
		// returning after the same hub outage. Attached work continues meanwhile.
		timer := time.NewTimer(backoff + rand.N(backoff))
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		backoff = min(30*time.Second, backoff*2)
	}
	return ctx.Err()
}
