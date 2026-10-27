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
	execution "asservat.local/asservat/internal/domain/execution"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
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
	// Every refusal before the run, and a failed run that never entered the
	// one-use SQL preparation (or whose preparation rolled back before its
	// insert, ADR-212), leaves the admitted capture unstarted: only reads
	// happened, so an explicit continuation may start it (ADR-134). Any other
	// run failure stays unavailable.
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
		return notStarted
	}
	mark = time.Now()
	state, e := attachment.Run(work, signed, func(ctx context.Context, ops *contextstart.HubOperations) (string, error) {
		r := s.Runner
		r.Process, r.Targets, r.Local, r.Starts, r.Output, r.Collector = ops, ops, ops, ops, ops, ops
		r.Prepare = gatedPreparer{r.Prepare, gate}
		result, err := r.ExecuteObserved(ctx, current, caller, accepted, capability, recovery)
		if err != nil && s.Report != nil {
			step := "execute"
			var fixed interface{ FixedStep() string }
			if errors.As(err, &fixed) {
				step += "/" + fixed.FixedStep()
			}
			s.Report(step + " (" + regionalOutcome(err) + ") left" + fleetapp.RemainingBucket(ctx, s.Now()) + " start-left" + fleetapp.RemainingBucket(call, s.Now()) + " bound=" + bound)
		}
		switch {
		case err == nil && (result.State == "StoredPendingVerification" || result.State == "AlreadyStarted"):
			return result.State, nil
		case errors.Is(err, execution.ErrPreparationUncertain):
			return "PreparationUncertain", err
		}
		return "Unavailable", err
	})
	auditapp.MarkStep(ctx, "st-run", mark)
	prepared := gate.close()
	if e != nil && state == "" {
		if s.Report != nil {
			s.Report("dispatch (" + regionalOutcome(e) + ") start-left" + fleetapp.RemainingBucket(call, s.Now()) + " bound=" + bound)
		}
		if !prepared {
			return notStarted
		}
		return execution.ErrUnavailable
	}
	switch state {
	case "StoredPendingVerification", "AlreadyStarted":
		return nil
	case "PreparationUncertain":
		return capturevalue.ErrPreparationUncertain
	}
	if !prepared {
		return notStarted
	}
	return execution.ErrUnavailable
}

// preparationGate records whether a run entered the one-use SQL preparation.
// A preparation refused before its insert (ADR-212 headroom) does not count.
// After close no preparation begins, so close's answer cannot change.
type preparationGate struct {
	mu             sync.Mutex
	closed, active bool
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
	stream, e := contextstart.NewOutboundStream(exchange.Context(), receiver.Channel, exchange.Check, local.Source, local.Targets, response, writer, connection, exchange.Close)
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
	type connection struct{ cancel context.CancelFunc }
	active := make(map[fleetvalue.OwnerBinding]connection)
	next := make(map[fleetvalue.OwnerBinding]time.Time)
	type end struct {
		owner fleetvalue.OwnerBinding
		retry time.Duration
	}
	ended := make(chan end, 16)
	defer func() {
		for _, c := range active {
			c.cancel()
		}
		for len(active) > 0 {
			delete(active, (<-ended).owner)
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
		for b, c := range active {
			if !contains(b) {
				c.cancel()
			}
		}
		for b := range next {
			if !contains(b) {
				delete(next, b)
			}
		}
		for _, owner := range observed.Owners {
			if _, exists := active[owner]; exists || len(active) >= 16 || s.Local.Now().Before(next[owner]) {
				continue
			}
			call, cancel := context.WithTimeout(ctx, 30*time.Second)
			active[owner] = connection{cancel}
			owner := owner
			go func() {
				defer cancel()
				retry := time.Second
				defer func() { ended <- end{owner, retry} }()
				exchange, e := s.Client.OpenDiscovered(call, owner, observed)
				retry = openingRetry(e)
				if e == nil {
					if e = ServeRegionalAPIContextExchange(exchange, s.Verifier, s.Local); e != nil {
						s.reportFailure("exchange", e)
					}
				} else {
					s.reportFailure("open", e)
				}
			}()
		}
	}
	poll()
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-ended:
			delete(active, e.owner)
			next[e.owner] = s.Local.Now().Add(e.retry)
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
