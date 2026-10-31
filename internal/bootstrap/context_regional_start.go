package bootstrap

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"context"
	"errors"
	"sync"

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
	Signer fleetapp.APIContextWorkSigner
	Router *contextstart.Router
	Now    func() time.Time
	// Report receives a failed run's fixed step and error class; diagnostics
	// only, nil leaves it silent.
	Report func(string)
}

var _ captureapp.ContextAcceptedStart = RegionalAPIContextStart{}

func (s RegionalAPIContextStart) StartContext(ctx context.Context, current identities.CurrentIdentity, id string) error {
	if ctx == nil || ctx.Err() != nil || current == nil || !authorization.UUID(id) || s.Runner.Read == nil || s.Runner.Capabilities == nil || s.Runner.Recovery == nil || s.Signer == nil || s.Router == nil || s.Now == nil {
		return execution.ErrInvalid
	}
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
	call, cancel := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer cancel()
	until, _ := call.Deadline()
	var cancels []context.CancelFunc
	defer func() {
		for i := len(cancels) - 1; i >= 0; i-- {
			cancels[i]()
		}
	}()
	// The initial context may already be shorter than this start's five seconds.
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
	recovery, e := s.Runner.Recovery.RecoveryState(call)
	if e != nil || !recovery.Valid(s.Now()) {
		return notStarted
	}
	narrow("recovery", recovery.FreshUntil)
	mark = time.Now()
	accepted, e := s.Runner.Read.ReadAPIContextWork(call, id, caller, recovery)
	auditapp.MarkStep(ctx, "st-read", mark)
	if e != nil {
		return e
	}
	a := accepted.Accepted
	if accepted.Actor != caller.Principal || a.CaptureID != id || a.State != capturevalue.IntentAudited || accepted.Target.ClusterID != a.Expectation.Registration.Location.ClusterID {
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
	narrow("receiver", receiver.ValidUntil)
	if receiver.Channel.Connector.Binding.InstallationID != recovery.InstallationID || receiver.Channel.Connector.Binding.IssuerEpoch != recovery.IssuerEpoch {
		return execution.ErrDenied
	}
	work, e := executionapp.NewAPIContextWork(accepted, receiver.Channel, capability, started, until, s.Now())
	if e != nil {
		return e
	}
	mark = time.Now()
	signed, e := s.Signer.SignAPIContextWork(call, work)
	auditapp.MarkStep(ctx, "st-sign", mark)
	if e != nil {
		return e
	}
	defer clear(signed)
	// Signing and every prior blocking read retain their original bounds. The
	// same retained CurrentIdentity answers regional requests on this attachment.
	if call.Err() != nil || !s.Now().Before(until) {
		return execution.ErrUnavailable // the original interval ended: not retryable as not-started
	}
	mark = time.Now()
	state, e := attachment.Run(work, signed, func(ctx context.Context, ops *contextstart.HubOperations) (string, error) {
		r := s.Runner
		r.Process, r.Targets, r.Local, r.Starts, r.Output, r.Collector = ops, ops, ops, ops, ops, ops
		r.Prepare = gatedPreparer{r.Prepare, gate}
		result, err := r.ExecuteObserved(ctx, current, caller, accepted, capability, recovery)
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
		case err == nil && (result.State == "StoredPendingVerification" || result.State == "AlreadyStarted" || result.State == "Recording"):
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
			s.Report("dispatch (" + regionalOutcome(e) + ") start-left" + fleetapp.RemainingBucket(call, s.Now()) + " bound=" + bound)
		}
		if gate.notStarted() {
			return notStarted
		}
		return execution.ErrUnavailable
	}
	switch state {
	case "StoredPendingVerification", "AlreadyStarted", "Recording":
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

// Diagnostic only: a retained caller deadline is not a fresh start interval.
func regionalStartInitialBound(ctx context.Context, started time.Time) string {
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(started.Add(5*time.Second)) {
		return "parent"
	}
	return "start"
}

// ServeRegionalAPIContextExchange owns one outbound exchange until all regional
// operations and stream I/O join. It does not reconnect or retry uncertain
// work. It answers only cluster-local operations for the verified work.
func ServeRegionalAPIContextExchange(exchange *mtls.ContextStartExchange, verifier fleetapp.APIContextWorkVerifier, local contextstart.RegionalLocal) error {
	if exchange == nil || verifier == nil || local.Now == nil {
		return execution.ErrInvalid
	}
	defer exchange.Close()
	response, writer, connection, e := exchange.IO()
	if e != nil {
		return e
	}
	receiver := exchange.Receiver()
	stream, e := contextstart.NewOutboundStream(exchange.Context(), receiver.Channel, exchange.Check, local.Source, local.Targets, local.Sources, response, writer, connection, exchange.Close)
	if e != nil {
		return e
	}
	defer stream.Close()
	ctx, diagnostics := contextstart.NewStreamDiagnosticContext(exchange.Context())
	if e = contextstart.ServeRegionalOperations(ctx, stream, receiver, verifier, local, local.Now); e != nil {
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

// RegionalContextStartConnections supervises only outbound standby exchanges.
// Each new conversation starts empty under fresh route/peer checks. It cannot
// retain or resubmit a capture ID, signed work or human CurrentIdentity. An
// uncertain attached conversation therefore never becomes an automatic retry.
type RegionalContextStartConnections struct {
	Candidates fleetapp.APIContextOwnerCandidatesReader
	Client     *mtls.ContextStartClient
	Verifier   fleetapp.APIContextWorkVerifier
	Local      contextstart.RegionalLocal
	// Report receives closed diagnostic labels only and must not block.
	Report func(string)
	// ReportOpening keeps numeric timing outside the finite event-count key.
	// It observes a joined refusal, never changes the opening's authority.
	ReportOpening func(string, time.Duration, time.Duration, string)
}

func (s RegionalContextStartConnections) Run(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || s.Candidates == nil || s.Client == nil || s.Verifier == nil || s.Local.Now == nil {
		return execution.ErrInvalid
	}
	defer s.Client.Close()
	// ADR-271: mtls.ContextStartExchangesPerOwner slots per owner. Openings
	// are staggered (one in flight per owner): concurrent setups refused each
	// other (installed native 65). Each slot is retried on its own.
	type slot struct {
		owner fleetvalue.OwnerBinding
		n     int
	}
	type connection struct{ cancel context.CancelFunc }
	active := make(map[slot]connection)
	next := make(map[slot]time.Time)
	opening := make(map[fleetvalue.OwnerBinding]bool)
	type end struct {
		key   slot
		retry time.Duration
	}
	ended := make(chan end, 2*16)
	opened := make(chan fleetvalue.OwnerBinding, 2*16)
	defer func() {
		for _, c := range active {
			c.cancel()
		}
		for len(active) > 0 {
			delete(active, (<-ended).key)
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	poll := func() {
		observed, e := s.Candidates.ReadContextStartOwners(ctx)
		if e != nil || !observed.Valid(s.Local.Now()) || ctx.Err() != nil {
			s.reportFailure("candidates", e)
			return
		}
		if len(observed.Owners) == 0 {
			s.reportFailure("candidates-empty", nil)
		}
		contains := func(b fleetvalue.OwnerBinding) bool {
			for _, candidate := range observed.Owners {
				if b == candidate {
					return true
				}
			}
			return false
		}
		for k, c := range active {
			if !contains(k.owner) {
				c.cancel()
			}
		}
		for k := range next {
			if !contains(k.owner) {
				delete(next, k)
			}
		}
		for _, owner := range observed.Owners {
			for n := range mtls.ContextStartExchangesPerOwner {
				key := slot{owner, n}
				if _, exists := active[key]; exists || opening[owner] || len(active) >= 16 || s.Local.Now().Before(next[key]) {
					continue
				}
				call, cancel := context.WithTimeout(ctx, 30*time.Second)
				active[key], opening[owner] = connection{cancel}, true
				go func() {
					defer cancel()
					retry := time.Second
					defer func() { ended <- end{key, retry} }()
					exchange, e := s.Client.OpenDiscovered(call, owner, observed)
					opened <- owner
					retry = openingRetry(e)
					if e == nil {
						// An opened exchange passed every opening check; the hub
						// ends a used standby by closing it, so its end is usually
						// a read error. Either way the slot needs its next standby.
						retry = 0
						if e = ServeRegionalAPIContextExchange(exchange, s.Verifier, s.Local); e != nil {
							s.reportFailure("exchange", e)
						}
					} else {
						s.reportFailure("open", e)
					}
				}()
			}
		}
	}
	poll()
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case owner := <-opened:
			// The owner's other slot may open now.
			delete(opening, owner)
			poll()
		case e := <-ended:
			delete(active, e.key)
			next[e.key] = s.Local.Now().Add(e.retry)
			if e.retry == 0 {
				// An ended exchange consumed one of the owner's standbys.
				// Reopen now, not on the next tick: the hub's following attach
				// (a Save's start after its history write) waits about two
				// seconds.
				poll()
			}
		case <-ticker.C:
			poll()
		}
	}
	return ctx.Err()
}

// openingRetry is one second, or thirty after a TLS refusal: a registered
// owner process the hub no longer serves (for example before a restart) is
// refused at TLS each time, and its full setup proof shares the connector's
// coalesced proof with the live owner's opening (installed native 66). The
// owner set, every check and the next opening's bounds are unchanged.
func openingRetry(err error) time.Duration {
	var fixed interface{ FixedStep() string }
	if err != nil && errors.As(err, &fixed) && fixed.FixedStep() == "tls" {
		return 30 * time.Second
	}
	return time.Second
}
