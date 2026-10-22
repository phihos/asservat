package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A retained request observation does not bypass the SQL effect's current
// permission check. The process, target, identity and protected source inputs
// are synthetic; the compiled SQL credential, row lock and revocation are real.
func qualifyAPIExecutionRetainedObservation(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T, int64) captureAdmissionScenario) {
	t.Helper()
	t.Run("api-execution-retained-check-revoked-during-permission-lock", func(t *testing.T) {
		s := create(t, 1)
		input := s.a.Plan.Input
		input.CaseID = s.a.CaseID
		input.Target.ExecutionClass = artifact.ContextAPIExecution
		input.Capability.ExecutionClass = artifact.ContextAPIExecution
		input.Target.NodeUID, input.Target.NodeBootID, input.Target.Pin.NodeName = "", "", ""
		var err error
		s.a.Plan, err = planning.CompileContext(input, s.a.Plan.CompiledAt)
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
		const password = "synthetic-api-observation"
		newExecution := func(purpose, prefix string) (*postgres.APIContextExecutions, string) {
			role := narrowRole(t, ctx, admin, prefix, password, func(role string) []string {
				grants, ok := postgres.PublicRuntimeRoleGrantSQL(purpose, role)
				if !ok {
					t.Fatal("missing compiled execution role", purpose)
				}
				return grants
			})
			out, err := postgres.NewAPIContextExecutions(ctx, open(role, password), s.a.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
			if err != nil {
				t.Fatal(err)
			}
			return out, role
		}
		prepare, role := newExecution("api-execution-prepare", "api_observation_prepare_")
		read, _ := newExecution("api-execution-read", "api_observation_read_")
		intents, err := postgres.NewCaptureIntentAudits(ctx, open("capture_audit_runtime", "synthetic-capture-audit"), s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		if err = (auditapp.CaptureIntentPublisher{Ledger: intents, Objects: &objectstore.CaptureIntentObjects{Store: store, Seal: keys, Open: keys}}).PublishCaptureIntents(ctx); err != nil {
			t.Fatal(err)
		}
		// Observe once after fixture provisioning, then retain exactly this check
		// through successful preparation and the subsequent blocked bind effect.
		now := time.Now().UTC().Truncate(time.Microsecond)
		s.batch.ObservedAt, s.batch.FreshUntil, s.batch.Initial = now, now.Add(5*time.Second), nil
		if err = s.p.RefreshPermissions(ctx, s.batch); err != nil {
			t.Fatal(err)
		}
		actor := s.a.Eligibility.VerifiedIdentity
		actor.VerifiedAt, actor.ValidUntil = now, now.Add(5*time.Second)
		recovery, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		work, err := read.ReadAPIContextWork(ctx, accepted.CaptureID, actor, recovery)
		if err != nil {
			t.Fatal(err)
		}
		projection, err := s.p.Permissions(ctx, s.a.Eligibility.Target)
		if err != nil {
			t.Fatal(err)
		}
		eligible := authorization.ContextEligibility(actor, projection, s.a.Eligibility.Target, time.Now())
		policies, err := s.retention.policies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		input.Retention, err = privacy.Resolve(policies, privacy.Input{Target: s.a.Eligibility.Target, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: accepted.Expectation.RequestedAgeSeconds, AnchorAt: accepted.Expectation.Registration.AnchorAt}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		input.Target.ObservedAt, input.Target.FreshUntil = now, now.Add(5*time.Second)
		input.Capability.ObservedAt, input.Capability.FreshUntil = now, now.Add(5*time.Second)
		plan, err := planning.CompileContext(input, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		process := value.APIProcessObservation{Binding: value.APIProcessBinding{InstallationID: recovery.InstallationID, ClusterID: work.Target.ClusterID, IssuerEpoch: recovery.IssuerEpoch, NamespaceUID: custodyID(), AccountUID: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID(), StartupDigest: artifact.Digest{1}, ImageDigest: accepted.Expectation.CollectorImageDigest}, CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}
		until := now.Add(5 * time.Second)
		for _, d := range []time.Time{eligible.ValidUntil, plan.ValidUntil, recovery.FreshUntil, process.ValidUntil, accepted.Expectation.Registration.WriteUntil} {
			until = identity.Earlier(until, d)
		}
		check := executionapp.APIExecutionCheck{Work: work, Plan: plan, Eligibility: eligible, Recovery: recovery, Process: process, CheckedAt: now, ValidUntil: until.Truncate(time.Microsecond)}
		if !check.Valid(time.Now()) {
			t.Fatal("invalid current synthetic execution facts")
		}
		call, cancel := context.WithDeadline(ctx, check.ValidUntil)
		defer cancel()
		original, first, err := prepare.PrepareAPIExecution(call, check)
		if err != nil || !first || !original.Valid() || original.Phase != "prepared" || original.ObjectUID != "" {
			t.Fatal("positive preparation before revocation", first, err)
		}
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var blocker int32
		if err = tx.QueryRow(ctx, `SELECT pg_backend_pid() FROM permission_stream WHERE id=$1 FOR UPDATE`, s.a.RootID).Scan(&blocker); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `UPDATE permission_stream SET suspended=true WHERE id=$1`, s.a.RootID); err != nil {
			t.Fatal(err)
		}
		type result struct {
			execution value.APIExecution
			err       error
		}
		done := make(chan result, 1)
		go func() {
			r, err := prepare.BindAPIStart(call, check, original, value.PreparedStart{ObjectUID: custodyID(), ResourceVersion: "1"})
			done <- result{r, err}
		}()
		joined := false
		defer func() {
			cancel()
			_ = tx.Rollback(ctx)
			if !joined {
				<-done
			}
		}()
		// Require an actual waiter on this administrator transaction, rather
		// than treating an elapsed sleep as proof of the interleaving.
		waitUntil := identity.Earlier(check.ValidUntil, time.Now().Add(750*time.Millisecond))
		for {
			var waiting bool
			if err = admin.QueryRow(call, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid)))`, role, blocker).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			if !time.Now().Before(waitUntil) {
				t.Fatal("did not observe the retained-check permission-lock waiter")
			}
			timer := time.NewTimer(5 * time.Millisecond)
			select {
			case got := <-done:
				joined = true
				timer.Stop()
				t.Fatal("bind returned before the blocked permission check", got.err)
			case <-call.Done():
				timer.Stop()
				t.Fatal("original observation expired before the lock interleaving", call.Err())
			case <-timer.C:
			}
		}
		if err = tx.Commit(call); err != nil {
			t.Fatal(err)
		}
		got := <-done
		joined = true
		if call.Err() != nil || !check.Valid(time.Now()) {
			t.Fatal("fixture expired authority instead of testing committed revocation", call.Err())
		}
		if !errors.Is(got.err, configuration.ErrUnavailable) || got.execution != (value.APIExecution{}) {
			t.Fatal("retained observation bypassed current SQL permission revocation", got.err)
		}
		var unchanged, suspended bool
		if err = admin.QueryRow(ctx, `SELECT e.phase='prepared' AND e.object_uid IS NULL AND e.not_before=$3 AND e.not_after=$4, p.suspended FROM context_execution e JOIN permission_stream p ON p.id=e.root_id WHERE e.capture_id=$1 AND e.root_id=$2`, accepted.CaptureID, s.a.RootID, original.Binding.NotBefore, original.Binding.NotAfter).Scan(&unchanged, &suspended); err != nil {
			t.Fatal(err)
		}
		if !unchanged || !suspended {
			t.Fatal("revoked bind changed the immutable preparation", unchanged, suspended)
		}
	})
}
