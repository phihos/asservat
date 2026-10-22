package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The SQL read/preparation facets share the compiled installation credential.
// Current target/process/identity observations are explicit synthetic inputs;
// the composed runner's later ports record and refuse every attempted effect.
func qualifyAPIExecutionPreparationBoundaries(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T, int64) captureAdmissionScenario) {
	t.Helper()
	t.Run("api-execution-preparation-boundaries", func(t *testing.T) {
		setup := func(t *testing.T) (*postgres.APIContextExecutions, *postgres.APIContextExecutions, string, func() executionapp.APIExecutionCheck) {
			t.Helper()
			s := create(t, 1)
			in := s.a.Plan.Input
			in.CaseID = s.a.CaseID
			in.Target.ExecutionClass = artifact.ContextAPIExecution
			in.Capability.ExecutionClass = artifact.ContextAPIExecution
			in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = "", "", ""
			var err error
			s.a.Plan, err = planning.CompileContext(in, s.a.Plan.CompiledAt)
			if err != nil {
				t.Fatal(err)
			}
			accepted, err := s.s.AdmitContext(ctx, s.a)
			if err != nil {
				t.Fatal(err)
			}
			open := func(user, password string) *pgxpool.Pool {
				p := poolFor(user, password)
				t.Cleanup(p.Close)
				return p
			}
			sharedPool, role := compiledAPIExecutionPool(t, ctx, admin, poolFor)
			executionSQL, err := postgres.NewAPIContextExecutions(ctx, sharedPool, s.a.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
			if err != nil {
				t.Fatal(err)
			}
			prepare, read := executionSQL, executionSQL
			intents, err := postgres.NewCaptureIntentAudits(ctx, open("capture_audit_runtime", "synthetic-capture-audit"), s.a.RootID)
			if err != nil {
				t.Fatal(err)
			}
			if err = (auditapp.CaptureIntentPublisher{Ledger: intents, Objects: &objectstore.CaptureIntentObjects{Store: store, Seal: keys, Open: keys}}).PublishCaptureIntents(ctx); err != nil {
				t.Fatal(err)
			}
			// Fresh observations may change timestamps, never this process or the
			// original admitted capture, attempt, retention anchor and plan scope.
			process := value.APIProcessBinding{NamespaceUID: custodyID(), AccountUID: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID(), StartupDigest: artifact.Digest{1}, ImageDigest: accepted.Expectation.CollectorImageDigest}
			refresh := func() executionapp.APIExecutionCheck {
				t.Helper()
				n := time.Now().UTC().Truncate(time.Microsecond)
				s.batch.ObservedAt, s.batch.FreshUntil, s.batch.Initial = n, n.Add(5*time.Second), nil
				if err := s.p.RefreshPermissions(ctx, s.batch); err != nil {
					t.Fatal(err)
				}
				i := s.a.Eligibility.VerifiedIdentity
				i.VerifiedAt, i.ValidUntil = n, n.Add(5*time.Second)
				recovery, err := s.recovery.reader.RecoveryState(ctx)
				if err != nil {
					t.Fatal(err)
				}
				work, err := read.ReadAPIContextWork(ctx, accepted.CaptureID, i, recovery)
				if err != nil {
					t.Fatal(err)
				}
				projection, err := s.p.Permissions(ctx, s.a.Eligibility.Target)
				if err != nil {
					t.Fatal(err)
				}
				eligible := authorization.ContextEligibility(i, projection, s.a.Eligibility.Target, time.Now())
				policies, err := s.retention.policies(ctx)
				if err != nil {
					t.Fatal(err)
				}
				retention, err := privacy.Resolve(policies, privacy.Input{Target: s.a.Eligibility.Target, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: accepted.Expectation.RequestedAgeSeconds, AnchorAt: accepted.Expectation.Registration.AnchorAt}, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				input := s.a.Plan.Input
				input.Target.ObservedAt, input.Target.FreshUntil = n, n.Add(5*time.Second)
				input.Capability.ObservedAt, input.Capability.FreshUntil = n, n.Add(5*time.Second)
				input.Retention = retention
				plan, err := planning.CompileContext(input, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				process.InstallationID, process.ClusterID, process.IssuerEpoch = recovery.InstallationID, input.Target.Target().ClusterID, recovery.IssuerEpoch
				observation := value.APIProcessObservation{Binding: process, CheckedAt: n, ValidUntil: n.Add(5 * time.Second)}
				until := n.Add(5 * time.Second)
				for _, d := range []time.Time{eligible.ValidUntil, plan.ValidUntil, recovery.FreshUntil, observation.ValidUntil, accepted.Expectation.Registration.WriteUntil} {
					until = identity.Earlier(until, d)
				}
				c := executionapp.APIExecutionCheck{Work: work, Plan: plan, Eligibility: eligible, Recovery: recovery, Process: observation, CheckedAt: n, ValidUntil: until.Truncate(time.Microsecond)}
				if !c.Valid(time.Now()) {
					t.Fatal("invalid current synthetic execution facts")
				}
				return c
			}
			return prepare, read, role, refresh
		}
		counts := func(t *testing.T, c executionapp.APIExecutionCheck, executions int) {
			t.Helper()
			var rows, wraps int
			if err := admin.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM context_execution WHERE capture_id=$1),
				(SELECT count(*) FROM context_key_wrap WHERE attempt_id=$2)`,
				c.Work.Accepted.CaptureID, c.Work.Accepted.Expectation.Registration.Location.AttemptID).Scan(&rows, &wraps); err != nil {
				t.Fatal(err)
			}
			if rows != executions || wraps != 0 {
				t.Errorf("execution/key-wrap effects = %d/%d, want %d/0", rows, wraps, executions)
			}
		}
		t.Run("expired-prepared-is-passive-and-runner-uncertain", func(t *testing.T) {
			prepare, read, _, refresh := setup(t)
			c := refresh()
			c.ValidUntil = time.Now().UTC().Truncate(time.Microsecond).Add(1500 * time.Millisecond)
			original, first, err := prepare.PrepareAPIExecution(ctx, c)
			if err != nil || !first || !original.Valid() || original.Phase != "prepared" {
				t.Fatal("first preparation", first, err)
			}
			waitAPIExecutionDatabaseTime(t, ctx, admin, original.Binding.NotAfter)
			fresh := refresh()
			got, first, err := prepare.PrepareAPIExecution(ctx, fresh)
			if err != nil || first || got != original {
				t.Error("expired preparation did not return the exact passive record", first, err)
			}
			shortCurrent := fresh
			shortCurrent.ValidUntil = time.Now().UTC().Truncate(time.Microsecond).Add(750 * time.Millisecond)
			got, first, err = prepare.PrepareAPIExecution(ctx, shortCurrent)
			if err != nil || first || got != original {
				t.Error("first-insert floor blocked an existing passive preparation", first, err)
			}
			facts, effects := &apiPreparationFacts{c: fresh}, &apiPreparationNoEffects{}
			runner := apiPreparationRunner(read, prepare, facts, effects)
			result, err := runner.Execute(ctx, facts, fresh.Work.Accepted.CaptureID)
			if !errors.Is(err, value.ErrPreparationUncertain) || result.State != "Indeterminate" {
				t.Error("expired SQL preparation lost runner uncertainty classification", result.State, err)
			}
			if effects.calls != 0 {
				t.Error("prepared replay attempted another effect", effects.calls)
			}
			// Historical results remain behind current authority and exact scope.
			for _, changed := range []struct {
				name string
				edit func(*executionapp.APIExecutionCheck)
			}{
				{"process", func(v *executionapp.APIExecutionCheck) { v.Process.Binding.ProcessEpoch = custodyID() }},
				{"actor", func(v *executionapp.APIExecutionCheck) { v.Work.Actor.Subject = "another-developer" }},
				{"scope", func(v *executionapp.APIExecutionCheck) { v.Plan.ScopeDigest[0] ^= 1 }},
				{"current-expired", func(v *executionapp.APIExecutionCheck) { v.ValidUntil = c.ValidUntil }},
			} {
				other := fresh
				changed.edit(&other)
				if _, first, err := prepare.PrepareAPIExecution(ctx, other); err == nil || first {
					t.Error("historical result bypassed current/exact check", changed.name, first, err)
				}
			}
			counts(t, fresh, 1)
		})
		for _, bound := range []string{"observation", "caller"} {
			t.Run("first-preparation-lock-consumes-"+bound+"-headroom", func(t *testing.T) {
				prepare, _, role, refresh := setup(t)
				c := refresh()
				tx, err := admin.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				var blocker int32
				var now time.Time
				if err = tx.QueryRow(ctx, `SELECT pg_backend_pid(),clock_timestamp() FROM context_capture WHERE id=$1 FOR UPDATE`, c.Work.Accepted.CaptureID).Scan(&blocker, &now); err != nil {
					t.Fatal(err)
				}
				until := now.Add(1500 * time.Millisecond)
				live, stop := context.WithCancel(ctx)
				if bound == "caller" {
					stop()
					live, stop = context.WithDeadline(ctx, until)
				} else {
					c.ValidUntil = until
				}
				defer stop()
				if !c.Valid(time.Now()) || time.Until(until) <= time.Second {
					t.Fatal("preparation did not start above the proposed minimum")
				}
				type result struct {
					execution value.APIExecution
					first     bool
					err       error
				}
				done := make(chan result, 1)
				go func() {
					r, first, err := prepare.PrepareAPIExecution(live, c)
					done <- result{r, first, err}
				}()
				joined := false
				defer func() {
					stop()
					_ = tx.Rollback(ctx)
					if !joined {
						<-done
					}
				}()
				blocked := false
				for time.Until(until) > time.Second {
					if err = admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid)))`, role, blocker).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if blocked {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
				if !blocked {
					t.Fatal("did not observe actual preparation row-lock wait before the floor")
				}
				// Release while the current facts and caller are still valid, but
				// only 750ms remain. This stays below the existing 1s SQL lock timeout.
				waitAPIExecutionDatabaseTime(t, ctx, admin, until.Add(-750*time.Millisecond))
				if err = tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				got := <-done
				joined = true
				if live.Err() != nil || !time.Now().Before(until) {
					t.Fatal("fixture expired the original bound instead of consuming headroom")
				}
				counts(t, c, 0)
				if got.err == nil || got.first || got.execution != (value.APIExecution{}) {
					t.Fatal("first preparation spent a sub-second interval after the lock", got.first, got.err)
				}
				if !errors.Is(got.err, value.ErrUnavailable) && !errors.Is(got.err, privacy.ErrUnavailable) {
					t.Fatal("insufficient headroom was not unavailable", got.err)
				}
				fresh := refresh()
				winner, first, err := prepare.PrepareAPIExecution(ctx, fresh)
				if err != nil || !first || !winner.Valid() || winner.Binding.NotAfter != fresh.ValidUntil {
					t.Fatal("refused first preparation prevented a fresh first winner", first, err)
				}
				replay, first, err := prepare.PrepareAPIExecution(ctx, fresh)
				if err != nil || first || replay != winner {
					t.Fatal("fresh first winner was renewed", first, err)
				}
				counts(t, fresh, 1)
			})
		}
		t.Run("short-caller-reaches-no-runner-effects", func(t *testing.T) {
			prepare, read, _, refresh := setup(t)
			c := refresh()
			facts, effects := &apiPreparationFacts{c: c}, &apiPreparationNoEffects{}
			runner := apiPreparationRunner(read, prepare, facts, effects)
			live, stop := context.WithTimeout(ctx, 750*time.Millisecond)
			defer stop()
			_, err := runner.Execute(live, facts, c.Work.Accepted.CaptureID)
			if err == nil || (!errors.Is(err, value.ErrUnavailable) && !errors.Is(err, privacy.ErrUnavailable)) {
				t.Error("short caller was not refused as unavailable", err)
			}
			if live.Err() != nil {
				t.Fatal("fixture reached caller expiry instead of the preparation floor")
			}
			if effects.calls != 0 {
				t.Error("short caller reached key/start/acquisition effects", effects.calls)
			}
			counts(t, c, 0)
		})
	})
}

func waitAPIExecutionDatabaseTime(t *testing.T, ctx context.Context, admin *pgxpool.Pool, until time.Time) {
	t.Helper()
	for {
		var now time.Time
		if err := admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			t.Fatal(err)
		}
		if !now.Before(until) {
			return
		}
		timer := time.NewTimer(min(until.Sub(now), 20*time.Millisecond))
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
	}
}

type apiPreparationFacts struct {
	c executionapp.APIExecutionCheck
}

func (f *apiPreparationFacts) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	return f.c.Eligibility.VerifiedIdentity, ctx.Err()
}
func (f *apiPreparationFacts) ResolvePod(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	if r != f.c.Work.Target {
		return targets.PodResolution{}, value.ErrConflict
	}
	return f.c.Plan.Input.Target, ctx.Err()
}
func (f *apiPreparationFacts) ContextEligibilityCurrent(ctx context.Context, _ identities.CurrentIdentity, target authorization.Target) authorization.CaptureEligibility {
	if ctx.Err() != nil || target != f.c.Eligibility.Target {
		return authorization.CaptureEligibility{}
	}
	return f.c.Eligibility
}
func (f *apiPreparationFacts) ContextCapability(ctx context.Context, _ authorization.Target) (planvalue.ContextCapability, error) {
	return f.c.Plan.Input.Capability, ctx.Err()
}
func (f *apiPreparationFacts) Resolve(ctx context.Context, in privacy.Input) (privacy.Resolution, error) {
	if in.Target != f.c.Eligibility.Target || !in.AnchorAt.Equal(f.c.Work.Accepted.Expectation.Registration.AnchorAt) {
		return privacy.Resolution{}, value.ErrConflict
	}
	return f.c.Plan.Input.Retention, ctx.Err()
}
func (f *apiPreparationFacts) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	return f.c.Recovery, ctx.Err()
}
func (f *apiPreparationFacts) ReadAPIProcess(ctx context.Context) (value.APIProcessObservation, error) {
	return f.c.Process, ctx.Err()
}

func apiPreparationRunner(read, prepare *postgres.APIContextExecutions, facts *apiPreparationFacts, effects *apiPreparationNoEffects) executionapp.APIContextRunner {
	return executionapp.APIContextRunner{Read: read, Prepare: prepare, Record: effects, Process: facts, Local: effects, Starts: effects, Targets: facts, Eligibility: facts, Capabilities: facts, Retention: facts, Recovery: facts, Output: effects, Collector: effects, Now: time.Now}
}

type apiPreparationNoEffects struct{ calls int }

func (f *apiPreparationNoEffects) PrepareContext(context.Context, artifact.ContextExpectation) (evidence.PreparedContext, error) {
	f.calls++
	return nil, value.ErrUnavailable
}
func (f *apiPreparationNoEffects) PrepareStart(context.Context, value.PreparationCheck) (value.PreparedStart, error) {
	f.calls++
	return value.PreparedStart{}, value.ErrUnavailable
}
func (f *apiPreparationNoEffects) ReadyStart(context.Context, value.Request) (value.Disposition, error) {
	f.calls++
	return value.Disposition{}, value.ErrUnavailable
}
func (f *apiPreparationNoEffects) ConsumeStart(context.Context, value.Request) (value.Disposition, error) {
	f.calls++
	return value.Disposition{}, value.ErrUnavailable
}
func (f *apiPreparationNoEffects) LookupStart(context.Context, value.Request) (value.Disposition, error) {
	f.calls++
	return value.Disposition{}, value.ErrUnavailable
}
func (f *apiPreparationNoEffects) RecordAPIStart(context.Context, executionapp.APIExecutionCheck, value.APIExecution, value.Disposition) (value.APIExecution, error) {
	f.calls++
	return value.APIExecution{}, value.ErrUnavailable
}
func (f *apiPreparationNoEffects) RecordAPIOutcome(context.Context, value.APIExecution, value.APIProcessObservation) (value.APIExecution, error) {
	f.calls++
	return value.APIExecution{}, value.ErrUnavailable
}
func (f *apiPreparationNoEffects) RecordAPIStoredCompletion(context.Context, value.APIExecution, artifact.ContextWriterCompletion, value.APIProcessObservation, artifact.RecoveryProof) (value.APIExecution, error) {
	f.calls++
	return value.APIExecution{}, value.ErrUnavailable
}
func (f *apiPreparationNoEffects) Capture(context.Context, artifact.PinnedPod) ([]byte, error) {
	f.calls++
	return nil, value.ErrUnavailable
}
