package integration

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"sync"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgconn"
)

// Fixture-only observation of the current download gate's dependencies. The
// gate maps every failure to one unavailable result; this records which
// dependency refused, with fixed labels, counts and durations only. Results
// and errors pass through unchanged; no read, retry or deadline is added.
var journeyGateNames = [...]string{"permissions", "catalog", "retention", "environment", "publication-recovery", "publication-retained-policies", "stop-claim", "stop-object", "stop-acknowledgement"}

type journeyGateTrace struct {
	mu              sync.Mutex
	calls, refusals [len(journeyGateNames)]uint32
	slowest         [len(journeyGateNames)]time.Duration
	reasons         [len(journeyGateNames)]string
	details         [len(journeyGateNames)]string
	// Optional fixture-admin classifier of the first permission refusal.
	probe func(context.Context) string
	state string
}

func journeyGateReason(err error) string {
	var pg *pgconn.PgError
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.As(err, &pg) && len(pg.Code) == 5:
		return "sqlstate-" + pg.Code
	case errors.Is(err, pgx.ErrNoRows):
		return "no-rows"
	case errors.Is(err, fleetvalue.ErrUnavailable):
		return "fleet-trust-unavailable"
	case errors.Is(err, auditapp.ErrUnavailable):
		return "audit-unavailable"
	case errors.Is(err, privacyapp.ErrUnavailable):
		return "custody-unavailable"
	case errors.Is(err, privacyapp.ErrFence):
		return "custody-fence"
	case errors.Is(err, cfg.ErrUnavailable):
		return "configuration-unavailable"
	case errors.Is(err, cfg.ErrLimit):
		return "configuration-limit"
	case errors.Is(err, cfg.ErrInvalid):
		return "configuration-invalid"
	default:
		return journeyDownloadReasonName(journeyDownloadReason(err))
	}
}

func journeyGateRemaining(c context.Context) time.Duration {
	if deadline, ok := c.Deadline(); ok {
		return time.Until(deadline)
	}
	return -1
}

// record keeps the first refusal's elapsed time, remaining caller deadline at
// entry and caller context state afterwards (labels/durations only).
func (g *journeyGateTrace) record(i int, c context.Context, started time.Time, remaining time.Duration, err error) {
	elapsed := time.Since(started)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls[i]++
	if elapsed > g.slowest[i] {
		g.slowest[i] = elapsed
	}
	if err != nil {
		g.refusals[i]++
		if g.reasons[i] == "" {
			g.reasons[i] = journeyGateReason(err)
			after := "nil-context"
			if c != nil {
				after = journeyGateReason(c.Err())
			}
			g.details[i] = "elapsed=" + elapsed.String() + " remaining-at-entry=" + remaining.String() + " context-after=" + after
		}
	}
}

func (g *journeyGateTrace) Report(t *testing.T) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, name := range journeyGateNames {
		reason := g.reasons[i]
		if reason == "" {
			reason = "none"
		}
		t.Logf("journey gate dependency=%s calls=%d refusals=%d first-reason=%s slowest=%s %s", name, g.calls[i], g.refusals[i], reason, g.slowest[i], g.details[i])
	}
	if g.state != "" {
		t.Logf("journey gate first permission refusal stream-state=%s", g.state)
	}
}

// Wrap returns the same gate with traced dependencies.
func (g *journeyGateTrace) Wrap(in authapp.ContextDownloadAuthority) authapp.ContextDownloadAuthority {
	in.Permissions = journeyGatePermissions{in.Permissions, g}
	in.Catalog = journeyGateCatalog{in.Catalog, g}
	in.Retention = journeyGateRetention{in.Retention, g}
	in.Environment = journeyGateEnvironment{in.Environment, g}
	return in
}

type journeyGatePermissions struct {
	authapp.ProjectionReader
	trace *journeyGateTrace
}

func (d journeyGatePermissions) Permissions(c context.Context, target value.Target) (value.Projection, error) {
	started, remaining := time.Now(), journeyGateRemaining(c)
	v, e := d.ProjectionReader.Permissions(c, target)
	d.trace.record(0, c, started, remaining, e)
	if e != nil && d.trace.probe != nil {
		d.trace.mu.Lock()
		first := d.trace.state == ""
		if first {
			d.trace.state = "pending"
		}
		d.trace.mu.Unlock()
		if first {
			probe, stop := context.WithTimeout(context.WithoutCancel(c), 2*time.Second)
			state := d.trace.probe(probe)
			stop()
			d.trace.mu.Lock()
			d.trace.state = state
			d.trace.mu.Unlock()
		}
	}
	return v, e
}

type journeyGateCatalog struct {
	authapp.ContextDownloadCatalog
	trace *journeyGateTrace
}

func (d journeyGateCatalog) ContextDownloadEvidence(c context.Context, id string) (authapp.ContextDownloadEvidence, error) {
	started, remaining := time.Now(), journeyGateRemaining(c)
	v, e := d.ContextDownloadCatalog.ContextDownloadEvidence(c, id)
	d.trace.record(1, c, started, remaining, e)
	return v, e
}

type journeyGateRetention struct {
	authapp.DownloadRetentionResolver
	trace *journeyGateTrace
}

func (d journeyGateRetention) ResolveRetained(c context.Context, in privacy.Input, deadlines privacy.Deadlines, rules []artifact.RetentionRule) (privacy.RetainedResolution, error) {
	started, remaining := time.Now(), journeyGateRemaining(c)
	v, e := d.DownloadRetentionResolver.ResolveRetained(c, in, deadlines, rules)
	d.trace.record(2, c, started, remaining, e)
	return v, e
}

type journeyGateEnvironment struct {
	authapp.DownloadEnvironmentReader
	trace *journeyGateTrace
}

func (d journeyGateEnvironment) DownloadEnvironment(c context.Context, record authapp.ContextDownloadEvidence, principal identity.Principal) (artifact.DownloadEnvironment, error) {
	started, remaining := time.Now(), journeyGateRemaining(c)
	v, e := d.DownloadEnvironmentReader.DownloadEnvironment(c, record, principal)
	d.trace.record(3, c, started, remaining, e)
	return v, e
}

func TestPublicJourneyGateTraceLabelsOnly(t *testing.T) {
	g := &journeyGateTrace{}
	ctx := context.Background()
	g.record(0, ctx, time.Now(), -1, &pgconn.PgError{Code: "53300", Message: "secret"})
	g.record(0, ctx, time.Now(), -1, nil)
	g.record(1, ctx, time.Now(), -1, &journeyDownloadPrivateError{})
	g.record(2, ctx, time.Now(), -1, context.DeadlineExceeded)
	if g.calls[0] != 2 || g.refusals[0] != 1 || g.reasons[0] != "sqlstate-53300" || g.reasons[1] != "other" || g.reasons[2] != "deadline" || g.refusals[3] != 0 {
		t.Fatal("gate trace classification changed", g.reasons)
	}
}

type journeyGateRecovery struct {
	fleetapp.RecoveryReader
	trace *journeyGateTrace
}

func (d journeyGateRecovery) RecoveryState(c context.Context) (fleetvalue.RecoveryState, error) {
	started, remaining := time.Now(), journeyGateRemaining(c)
	v, e := d.RecoveryReader.RecoveryState(c)
	d.trace.record(4, c, started, remaining, e)
	return v, e
}

type journeyGateRetainedPolicies struct {
	privacyapp.RetainedPolicyReader
	trace *journeyGateTrace
}

func (d journeyGateRetainedPolicies) RetainedRetentionPolicies(c context.Context, target value.Target, rules []artifact.RetentionRule) (privacy.PolicySet, error) {
	started, remaining := time.Now(), journeyGateRemaining(c)
	v, e := d.RetainedPolicyReader.RetainedRetentionPolicies(c, target, rules)
	d.trace.record(5, c, started, remaining, e)
	return v, e
}

// Fixture-only labels for the Stop audit facets (claim, object, acknowledgement).
func (g *journeyGateTrace) WrapStop(in evidence.ContextDownloadStopCoordinator) evidence.ContextDownloadStopCoordinator {
	in.Ledger = journeyStopLedger{in.Ledger, g}
	in.Objects = journeyStopObjects{in.Objects, g}
	in.Acknowledgements = journeyStopAcks{in.Acknowledgements, g}
	return in
}

type journeyStopLedger struct {
	evidence.DownloadStopLedger
	trace *journeyGateTrace
}

func (d journeyStopLedger) ClaimDownloadStopWrite(c context.Context, x artifact.DownloadStopDecision) (bool, error) {
	started, remaining := time.Now(), journeyGateRemaining(c)
	v, e := d.DownloadStopLedger.ClaimDownloadStopWrite(c, x)
	d.trace.record(6, c, started, remaining, e)
	return v, e
}

type journeyStopObjects struct {
	evidence.DownloadStopObjects
	trace *journeyGateTrace
}

func (d journeyStopObjects) CreateDownloadStop(c context.Context, x artifact.DownloadStopDecision) (auditvalue.Receipt, error) {
	started, remaining := time.Now(), journeyGateRemaining(c)
	v, e := d.DownloadStopObjects.CreateDownloadStop(c, x)
	d.trace.record(7, c, started, remaining, e)
	return v, e
}

type journeyStopAcks struct {
	evidence.DownloadStopAcknowledgements
	trace *journeyGateTrace
}

func (d journeyStopAcks) AcknowledgeDownloadStop(c context.Context, x artifact.DownloadStopDecision, r auditvalue.Receipt) error {
	started, remaining := time.Now(), journeyGateRemaining(c)
	e := d.DownloadStopAcknowledgements.AcknowledgeDownloadStop(c, x, r)
	d.trace.record(8, c, started, remaining, e)
	return e
}
