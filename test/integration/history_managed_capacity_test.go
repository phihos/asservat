package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	captureapp "asservat.local/asservat/internal/application/capture"
	compiler "asservat.local/asservat/internal/application/planning"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This reproduces the history reservation's live-capacity coupling through the
// actual compiled shared hub-runtime writer role and SQL facet. It does not
// identify which missing
// or expired managed condition caused installed TRACE41901024982. Protected
// source/identity observations remain the existing fixture's synthetic inputs;
// admission, encrypted publication, custody and transaction guards are real.
func TestHistoryParametersManagedCapacityBoundaryWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		t.Run("managed-history-reservation", func(t *testing.T) {
			withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, qualifyHistoryManagedCapacity)
		})
	})
}

type historyManagedAccounting struct {
	Bytes, Objects, Attempts, Copies, Events, History, Quotas, Used int64
}

func qualifyHistoryManagedCapacity(t *testing.T, f *queryLedgerFixture) {
	b, s := f.base, f.scenario
	role := narrowRole(t, b.ctx, b.admin, "managed_history_", "synthetic-managed-history", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
		if !ok {
			t.Fatal("compiled shared hub-runtime history writer role missing")
		}
		return grants
	})
	pool := b.fixturePool(role, "synthetic-managed-history")
	defer pool.Close()
	ledger, err := postgres.NewHistoryParameters(b.ctx, pool, s.a.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
	if err != nil {
		t.Fatal(err)
	}
	material := b.root.value.State.MAC
	mac, err := auditapp.NewOperationMAC(material.InputVersion, material.InputKey, material.AccountVersion, material.AccountKey)
	if err != nil {
		t.Fatal(err)
	}
	defer mac.Close()

	// The same accepted capture and immutable parameter selection are used for
	// refusal and the subsequent fresh-binding control. Only the independent
	// fixture observations are refreshed; no capture/grant/deadline is renewed.
	q := s.a.Plan.Input.Target.Request
	p := capture.HistoryParameters{Format: capture.HistoryParametersFormat,
		Target:       targets.WorkloadRequest{ClusterID: q.ClusterID, Namespace: q.Namespace.Name, Kind: q.Workload.Kind, Name: q.Workload.Name},
		NamespaceUID: q.Namespace.UID, WorkloadUID: q.Workload.UID, Diagnostic: capture.ContextDiagnosticName,
		RecipeJSON:       json.RawMessage(compiler.ContextRecipeSpec),
		RequestedSeconds: s.a.Plan.Input.Retention.RequestedSeconds, OriginalEffectiveSeconds: int64(f.published.Expectation.Registration.ExpiresAt.Sub(f.published.Expectation.Registration.AnchorAt).Seconds()), OriginalExecutionDigest: s.a.Plan.ScopeDigest}
	var frozen struct {
		Dependencies []struct {
			Role   string `json:"role"`
			Digest string `json:"digest"`
		} `json:"dependencies"`
		Collection struct {
			Spec struct {
				Target json.RawMessage `json:"target"`
			} `json:"spec"`
		} `json:"collection"`
	}
	if json.Unmarshal(s.a.Plan.CanonicalScope, &frozen) != nil {
		t.Fatal("accepted scope cannot supply original dependency pins")
	}
	pins := frozen.Dependencies[:0]
	for _, pin := range frozen.Dependencies {
		if pin.Role == "recipe" || pin.Role == "collector" || pin.Role == "projection" {
			pins = append(pins, pin)
		}
	}
	p.DependencyJSON, _ = json.Marshal(pins)
	p.AuthoredTargetJSON = bytes.Clone(frozen.Collection.Spec.Target)
	selector, settings, err := captureapp.HistoryParameterKeys(mac, s.a.RootID, p)
	if err != nil {
		t.Fatal(err)
	}
	r := f.published.Expectation.Registration
	r.Location.ArtifactID, r.Location.AttemptID = custodyID(), custodyID()
	r.NativeLimit = capture.MaxHistoryParameters
	var originalDeadline time.Time
	var originalScope []byte
	if err := b.admin.QueryRow(b.ctx, `SELECT created_at,deadline,scope_digest FROM context_capture WHERE root_id=$1 AND id=$2`, s.a.RootID, f.published.Expectation.CaptureUID).Scan(&r.AnchorAt, &originalDeadline, &originalScope); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalScope, s.a.Plan.ScopeDigest[:]) {
		t.Fatal("accepted scope differs from original history input")
	}
	r.WriteUntil = time.Now().UTC().Truncate(time.Microsecond).Add(30 * time.Second)
	if originalDeadline.Before(r.WriteUntil) {
		r.WriteUntil = originalDeadline
	}
	e := capture.HistoryExpectation{RootID: s.a.RootID, CaptureID: f.published.Expectation.CaptureUID, Registration: r, SelectorKey: selector, SettingsKey: settings, MACVersion: mac.AccountVersion(), OriginalExecutionDigest: s.a.Plan.ScopeDigest}
	reservation := func() capture.HistoryReservation {
		b.refreshBase(t)
		if _, err := s.retention.policies(b.ctx); err != nil {
			t.Fatal(err)
		}
		accepted := privacyapp.AcceptedRetentionReader{Topology: s.retention.topology, Sources: s.retention.reader, Now: time.Now}
		now := time.Now().UTC().Truncate(time.Microsecond)
		retention, err := (privacyapp.RetentionResolver{Policies: accepted, Now: time.Now}).ResolveCaseMetadata(b.ctx, privacy.Input{ControlKind: "case-metadata", Target: s.a.Eligibility.Target, PrivacyClass: "potentialPersonalData", EvidenceType: "other", AnchorAt: r.AnchorAt})
		if err != nil {
			t.Fatal(err)
		}
		recovery, err := s.recovery.reader.RecoveryState(b.ctx)
		if err != nil {
			t.Fatal(err)
		}
		actor := s.a.Eligibility.VerifiedIdentity
		actor.VerifiedAt, actor.ValidUntil = now, now.Add(5*time.Second)
		expected := e
		expected.Registration.ExpiresAt, expected.Registration.DeleteBy = retention.ExpiresAt, retention.DeleteBy
		return capture.HistoryReservation{Expectation: expected, Identity: actor, Recovery: recovery, Limits: capture.HistoryLimits{PerSelector: 2, PerInstallation: 4}, SummaryExpiresAt: retention.ExpiresAt, Retention: retention}
	}
	accounting := func() historyManagedAccounting {
		var v historyManagedAccounting
		err := b.admin.QueryRow(b.ctx, `SELECT a.charged_bytes,a.charged_objects,
 (SELECT count(*) FROM custody_attempt WHERE allocation_id=a.id),
 (SELECT count(*) FROM custody_copy c JOIN custody_attempt x ON x.id=c.attempt_id WHERE x.allocation_id=a.id),
 (SELECT count(*) FROM custody_event c JOIN custody_attempt x ON x.id=c.attempt_id WHERE x.allocation_id=a.id),
 (SELECT count(*) FROM capture_history_parameter WHERE root_id=$2),
 (SELECT count(*) FROM capture_history_quota WHERE root_id=$2),
 (SELECT coalesce(sum(used),0) FROM capture_history_quota WHERE root_id=$2)
 FROM custody_allocation a WHERE a.id=$1`, f.enrolled.AllocationID, s.a.RootID).Scan(&v.Bytes, &v.Objects, &v.Attempts, &v.Copies, &v.Events, &v.History, &v.Quotas, &v.Used)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	f.expireWorkloadObservation(t)
	before := accounting()
	checkInput := func(in capture.HistoryReservation) {
		now := time.Now()
		if !in.Expectation.Valid() || in.Expectation.Registration.ExpiresAt.After(in.SummaryExpiresAt) || !now.Before(in.Expectation.Registration.WriteUntil) || !in.Identity.Valid(now) || !in.Recovery.Valid(now) || !in.Retention.Proof.Valid(now) {
			t.Fatal("history fixture input expired or exceeds original accepted dates", time.Until(in.Expectation.Registration.WriteUntil))
		}
	}
	in := reservation()
	checkInput(in)
	var rootLive, bindingExpired bool
	if err := b.admin.QueryRow(b.ctx, `SELECT coalesce(clock_timestamp()<capacity_managed_root_until($1,clock_timestamp()),false),clock_timestamp()>=fresh_until FROM context_storage_binding WHERE root_id=$1 AND allocation_id=$2`, s.a.RootID, f.enrolled.AllocationID).Scan(&rootLive, &bindingExpired); err != nil || !rootLive || !bindingExpired {
		t.Fatal("expired-binding reproduction did not isolate live root from stale workload", err, rootLive, bindingExpired)
	}
	// An ordinary or unassociated custody attempt must still require the live
	// workload, even for this same SQL principal, native size and allocation.
	raw, err := postgres.New(b.ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	ordinary := in.Expectation.Registration
	ordinary.Location.ArtifactID, ordinary.Location.AttemptID = custodyID(), custodyID()
	_, err = raw.Register(b.ctx, ordinary)
	var classified interface{ FixedStep() string }
	if !errors.Is(err, privacyapp.ErrUnavailable) || !errors.As(err, &classified) || classified.FixedStep() != "sql-23514" || accounting() != before {
		t.Fatal("ordinary custody bypassed live workload or changed charge", err)
	}
	var deferrable, initiallyDeferred bool
	if err := b.admin.QueryRow(b.ctx, `SELECT tgdeferrable,tginitdeferred FROM pg_trigger WHERE tgrelid='custody_attempt'::regclass AND tgname='zzz_capacity_new_admission'`).Scan(&deferrable, &initiallyDeferred); err != nil || !deferrable || initiallyDeferred {
		t.Fatal("custody admission is not immediate by default", err)
	}
	for _, mode := range []string{"no-history", "missing-json", "wrong-scope", "wrong-allocation", "late-write-bound"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := pool.Begin(b.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err = tx.Exec(b.ctx, `SET CONSTRAINTS public.zzz_capacity_new_admission DEFERRED`); err != nil {
				t.Fatal(err)
			}
			attempt := in.Expectation.Registration
			attempt.Location.ArtifactID, attempt.Location.AttemptID = custodyID(), custodyID()
			if mode == "late-write-bound" {
				attempt.WriteUntil = originalDeadline.Add(time.Millisecond)
			}
			charged, err := tx.Exec(b.ctx, `UPDATE custody_allocation SET charged_bytes=charged_bytes+$2,charged_objects=charged_objects+4 WHERE id=$1 AND $2<=byte_limit-charged_bytes AND 4<=object_limit-charged_objects`, attempt.AllocationID, attempt.ReservedBytes())
			if err != nil || charged.RowsAffected() != 1 {
				t.Fatal("adversarial fixture charge", err)
			}
			digest := privacyapp.RegistrationDigest(attempt)
			_, err = tx.Exec(b.ctx, `INSERT INTO custody_attempt(id,cluster_id,artifact_id,allocation_id,request_digest,pool_revision,allocation_revision,native_limit,reserved_bytes,anchor_at,write_until,expires_at,delete_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, attempt.Location.AttemptID, attempt.Location.ClusterID, attempt.Location.ArtifactID, attempt.AllocationID, digest[:], attempt.PoolRevision, attempt.AllocationRevision, attempt.NativeLimit, attempt.ReservedBytes(), attempt.AnchorAt, attempt.WriteUntil, attempt.ExpiresAt, attempt.DeleteBy)
			if err != nil {
				t.Fatal("deferred insert failed before association was tested", err)
			}
			if mode != "no-history" {
				claim := in.Expectation
				claim.Registration = attempt
				switch mode {
				case "wrong-scope":
					claim.OriginalExecutionDigest[0] ^= 1
				case "wrong-allocation":
					claim.Registration.AllocationID = custodyID()
				}
				encoded, _ := json.Marshal(claim)
				if mode == "missing-json" {
					encoded = []byte(`{}`)
				}
				retained, _ := json.Marshal(capture.HistoryRetention{Input: privacy.Input{ControlKind: "case-metadata", Target: in.Retention.Target, PrivacyClass: in.Retention.PrivacyClass, EvidenceType: "other", RequestedSeconds: in.Retention.RequestedSeconds, AnchorAt: attempt.AnchorAt}, Origins: in.Retention.Policies})
				_, err = tx.Exec(b.ctx, `INSERT INTO capture_history_parameter(root_id,capture_id,attempt_id,selector_key,settings_key,mac_version,expectation_json,retention_json,summary_expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, claim.RootID, claim.CaptureID, attempt.Location.AttemptID, claim.SelectorKey[:], claim.SettingsKey[:], claim.MACVersion, encoded, retained, in.SummaryExpiresAt, attempt.AnchorAt)
			}
			if err == nil {
				err = tx.Commit(b.ctx)
			}
			_ = tx.Rollback(context.Background())
			var rejected *pgconn.PgError
			if !errors.As(err, &rejected) || rejected.Code != "23514" || accounting() != before {
				t.Fatal("deferred spoof escaped exact association or changed debit", mode, err)
			}
		})
	}

	// These explicit administrative fixture mutations bypass the protected
	// producer guard only to model existing pool/allocation expiry or suspension.
	// The runtime role still executes the unchanged real admission path.
	mutateBacking := func(statement string, args ...any) {
		t.Helper()
		tx, err := b.admin.Begin(b.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(b.ctx, "SET LOCAL session_replication_role=replica"); err != nil {
			t.Fatal(err)
		}
		if changed, err := tx.Exec(b.ctx, statement, args...); err != nil || changed.RowsAffected() != 1 {
			t.Fatal("administrative backing fixture", err)
		}
		if err = tx.Commit(b.ctx); err != nil {
			t.Fatal(err)
		}
	}
	var poolUntil, allocationUntil time.Time
	if err := b.admin.QueryRow(b.ctx, `SELECT p.valid_until,a.valid_until FROM custody_pool p JOIN custody_allocation a ON a.pool_id=p.id WHERE a.id=$1`, f.enrolled.AllocationID).Scan(&poolUntil, &allocationUntil); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"expired-pool", "paused-pool", "expired-allocation"} {
		t.Run(mode, func(t *testing.T) {
			input := reservation()
			checkInput(input)
			switch mode {
			case "expired-pool":
				mutateBacking(`UPDATE custody_pool SET valid_until=statement_timestamp()-interval '1 second' WHERE id=$1`, s.poolID)
			case "paused-pool":
				mutateBacking(`UPDATE custody_pool SET paused=true WHERE id=$1`, s.poolID)
			case "expired-allocation":
				mutateBacking(`UPDATE custody_allocation SET valid_until=statement_timestamp()-interval '1 second' WHERE id=$1`, f.enrolled.AllocationID)
			}
			defer func() {
				mutateBacking(`UPDATE custody_pool SET valid_until=$2,paused=false WHERE id=$1`, s.poolID, poolUntil)
				mutateBacking(`UPDATE custody_allocation SET valid_until=$2 WHERE id=$1`, f.enrolled.AllocationID, allocationUntil)
			}()
			_, err := ledger.ReserveHistoryParameters(b.ctx, input)
			if !errors.Is(err, privacyapp.ErrExpired) || accounting() != before {
				t.Fatal("invalid physical backing admitted history or changed charge", mode, err)
			}
		})
	}

	// Test-induced saturated quota counters exercise conservative refusal and
	// rollback. No production corruption or genuine capture storm is claimed.
	for _, key := range [][]byte{make([]byte, 32), in.Expectation.SelectorKey[:]} {
		if _, err := b.admin.Exec(b.ctx, `INSERT INTO capture_history_quota(root_id,selector_key,used) VALUES($1,$2,4)`, s.a.RootID, key); err != nil {
			t.Fatal(err)
		}
	}
	quotaBefore := accounting()
	_, quotaErr := ledger.ReserveHistoryParameters(b.ctx, reservation())
	if !errors.Is(quotaErr, capture.ErrCapacity) || accounting() != quotaBefore {
		t.Fatal("exhausted quota did not preserve all charges/state", quotaErr)
	}
	if _, err := b.admin.Exec(b.ctx, `DELETE FROM capture_history_quota WHERE root_id=$1`, s.a.RootID); err != nil {
		t.Fatal(err)
	}
	if accounting() != before {
		t.Fatal("fixture quota reset changed original accounting")
	}

	control := reservation()
	checkInput(control)
	storage, err := ledger.ReserveHistoryParameters(b.ctx, control)
	if err != nil || storage.State != "reserved" || !storage.Expectation.Registration.Equal(control.Expectation.Registration) {
		t.Fatal("accepted history requires current workload observation", err)
	}
	after := accounting()
	if after.Bytes-before.Bytes != r.ReservedBytes() || after.Objects-before.Objects != int64(len(r.Limits())) || after.Attempts-before.Attempts != 1 || after.Copies-before.Copies != int64(len(r.Limits())) || after.Events-before.Events != 1 || after.History-before.History != 1 || after.Quotas-before.Quotas != 2 || after.Used-before.Used != 2 {
		t.Fatal("history did not debit exactly one bounded snapshot", before, after)
	}
	var stillStale bool
	if err := b.admin.QueryRow(b.ctx, `SELECT clock_timestamp()>=fresh_until FROM context_storage_binding WHERE root_id=$1 AND allocation_id=$2`, s.a.RootID, f.enrolled.AllocationID).Scan(&stillStale); err != nil || !stillStale {
		t.Fatal("metadata persistence refreshed the workload", err)
	}
	// A later fresh observation permits ordinary work again, but replaying the
	// same committed history keeps its original identity and one charge.
	f.workloadGone = false
	f.refresh(t)
	if _, err = ledger.ReserveHistoryParameters(b.ctx, reservation()); err != nil || accounting() != after {
		t.Fatal("fresh control replayed history charge", err)
	}
	t.Logf("accepted history succeeded with stale workload, exact unchanged dates and one %d-byte/four-object charge; ordinary/deferred/spoof/quota/pool failures retained rollback", r.ReservedBytes())
}
