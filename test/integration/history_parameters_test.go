package integration

import (
	"bytes"
	"context"
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
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	privacy "asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real SQL/S3/AEAD custody with explicit fixture source/process authority. The
// separately qualified signed conversation/IAM fixture proves transport scope;
// this regression proves transactional charge and prefix dispatch isolation.
func qualifyHistoryParameters(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T, int64) captureAdmissionScenario) {
	t.Run("history-parameters-custody", func(t *testing.T) {
		s := create(t, 8)
		s.a.Eligibility.VerifiedIdentity.Scopes = []string{"evidence:capture", "evidence:read"}
		role := narrowRole(t, ctx, admin, "history_hub_", "synthetic-history", func(role string) []string {
			g, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
			if !ok {
				t.Fatal("missing hub plan")
			}
			return g
		})
		pool := poolFor(role, "synthetic-history")
		defer pool.Close()
		ledger, err := postgres.NewHistoryParameters(ctx, pool, s.a.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := postgres.New(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		mac, err := auditapp.NewOperationMAC("synthetic-input", bytes.Repeat([]byte{1}, 32), "synthetic-account", bytes.Repeat([]byte{2}, 32))
		if err != nil {
			t.Fatal(err)
		}
		defer mac.Close()
		recovery := func() artifact.RecoveryProof {
			r, e := s.recovery.reader.RecoveryState(ctx)
			if e != nil {
				t.Fatal(e)
			}
			return r
		}
		policies := func() privacy.PolicySet {
			if _, e := s.retention.policies(ctx); e != nil {
				t.Fatal(e)
			}
			set, e := (privacyapp.AcceptedRetentionReader{Topology: s.retention.topology, Sources: s.retention.reader, Now: time.Now}).CaseMetadataPolicies(ctx, s.a.Eligibility.Target)
			if e != nil {
				t.Fatal(e)
			}
			return set
		}
		reservation := func(a capture.Accepted) (capture.HistoryReservation, capture.HistoryParameters) {
			set := policies()
			now := time.Now().UTC().Truncate(time.Microsecond)
			retention, e := privacy.Resolve(set, privacy.Input{ControlKind: "case-metadata", Target: s.a.Eligibility.Target, PrivacyClass: "potentialPersonalData", EvidenceType: "other", RequestedSeconds: 5, AnchorAt: a.CreatedAt}, now)
			if e != nil {
				t.Fatal(e)
			}
			q := s.a.Plan.Input.Target.Request
			p := capture.HistoryParameters{Format: capture.HistoryParametersFormat, Target: targets.WorkloadRequest{ClusterID: q.ClusterID, Namespace: q.Namespace.Name, Kind: q.Workload.Kind, Name: q.Workload.Name}, NamespaceUID: q.Namespace.UID, WorkloadUID: q.Workload.UID, Diagnostic: capture.ContextDiagnosticName, RecipeJSON: json.RawMessage(compiler.ContextRecipeSpec), DependencyJSON: json.RawMessage(`[{"role":"recipe","digest":"0000000000000000000000000000000000000000000000000000000000000001"}]`), RequestedSeconds: 120, OriginalEffectiveSeconds: 120, OriginalExecutionDigest: a.ScopeDigest}
			selector, settings, e := captureapp.HistoryParameterKeys(mac, s.a.RootID, p)
			if e != nil {
				t.Fatal(e)
			}
			r := a.Expectation.Registration
			r.Location.ArtifactID = custodyID()
			r.Location.AttemptID = custodyID()
			r.NativeLimit = capture.MaxHistoryParameters
			r.AnchorAt = a.CreatedAt.In(time.FixedZone("synthetic-offset", 3600))
			r.WriteUntil = a.CreatedAt.Add(1500 * time.Millisecond)
			r.ExpiresAt = retention.ExpiresAt
			r.DeleteBy = retention.DeleteBy
			if a.RepeatedFrom != nil {
				if a.RepeatedFrom.ExpiresAt.Before(r.ExpiresAt) {
					r.ExpiresAt = a.RepeatedFrom.ExpiresAt
				}
				cutoff := a.RepeatedFrom.ExpiresAt.Add(time.Duration(retention.DeletionBudgetSeconds) * time.Second)
				if cutoff.Before(r.DeleteBy) {
					r.DeleteBy = cutoff
				}
			}
			expect := capture.HistoryExpectation{RootID: s.a.RootID, CaptureID: a.CaptureID, Registration: r, SelectorKey: selector, SettingsKey: settings, MACVersion: mac.AccountVersion(), OriginalExecutionDigest: a.ScopeDigest}
			return capture.HistoryReservation{Expectation: expect, Identity: s.a.Eligibility.VerifiedIdentity, Recovery: recovery(), Limits: capture.HistoryLimits{PerSelector: 1, PerInstallation: 2}, SummaryExpiresAt: retention.ExpiresAt, Retention: retention, Source: a.RepeatedFrom}, p
		}
		reserve := func(a capture.Accepted) (capture.HistoryStorage, capture.HistoryParameters) {
			in, p := reservation(a)
			h, e := ledger.ReserveHistoryParameters(ctx, in)
			if e != nil {
				t.Fatal("reserve", e)
			}
			return h, p
		}
		first, err := s.s.AdmitContext(ctx, s.a)
		if err != nil {
			t.Fatal(err)
		}
		h, p := reserve(first)
		bundle, err := objectstore.SealHistoryParameters(ctx, h.Expectation, p, keys, mac)
		if err != nil {
			t.Fatal(err)
		}
		defer bundle.Clear()
		digest, err := capture.HistoryCiphertextsDigest(bundle)
		if err != nil {
			t.Fatal(err)
		}
		write, err := ledger.ClaimHistoryWrite(ctx, capture.HistoryWriteRequest{Storage: h, Identity: s.a.Eligibility.VerifiedIdentity, Recovery: recovery(), RequestID: custodyID(), ExecutorEpoch: custodyID(), BundleDigest: digest})
		if err != nil {
			t.Fatal("claim writer", err)
		}
		objects := objectstore.HistoryObjects{Store: store, StoreID: h.Expectation.Registration.StoreID}
		copies, err := objects.Write(ctx, h.Expectation, bundle)
		if err != nil {
			t.Fatal(err)
		}
		completion := capture.HistoryWriterCompletion{RootID: s.a.RootID, CaptureID: first.CaptureID, AttemptID: h.Expectation.Registration.Location.AttemptID, OperationID: write.RequestID, ProcessEpoch: write.ExecutorEpoch, ExpectationDigest: capture.HistoryExpectationDigest(h.Expectation), CopiesDigest: capture.HistoryCopiesDigest(copies), CompletedAt: time.Now().UTC().Truncate(time.Microsecond), NotAfter: write.NotAfter}
		var storedDigest []byte
		if err = admin.QueryRow(ctx, "SELECT request_digest FROM custody_attempt WHERE id=$1", h.Expectation.Registration.Location.AttemptID).Scan(&storedDigest); err != nil {
			t.Fatal(err)
		}
		normalizedDigest := privacyapp.RegistrationDigest(h.Expectation.Registration)
		if !bytes.Equal(storedDigest, normalizedDigest[:]) {
			t.Fatal("history registration digest retained timestamp representation instead of UTC identity")
		}
		if err = ledger.CompleteHistoryWrite(ctx, capture.HistoryWriteResult{Authority: write, Copies: copies, Completion: completion, Recovery: recovery()}); err != nil {
			t.Fatal("complete writer", err)
		}
		set := policies()
		retained, err := privacy.ResolveRetained(set, h.Retention.Input, h.Effective, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		permission, err := ledger.AuthorizeHistoryRead(ctx, capture.HistoryReadRequest{Query: capture.SettingsQuery{RootID: s.a.RootID, CaptureID: first.CaptureID, Identity: s.a.Eligibility.VerifiedIdentity, Recovery: recovery()}, RequestID: custodyID(), ExecutorEpoch: custodyID(), Retention: retained})
		if err != nil {
			t.Fatal("current history read", err)
		}
		read, err := objects.Read(ctx, h.Expectation, permission.Storage.Copies)
		if err != nil {
			t.Fatal(err)
		}
		defer read.Clear()
		got, err := objectstore.OpenHistoryParameters(ctx, h.Expectation, permission.Storage.Copies, read, keys, mac)
		if err != nil || got.RequestedSeconds != p.RequestedSeconds || got.Target != p.Target {
			t.Fatal("encrypted settings changed", err)
		}
		// Create another accepted incident in the same originating allocation. Its
		// history replaces only that selector's projection, retaining the old charge.
		secondInput := s.a
		now := time.Now().UTC().Truncate(time.Microsecond)
		batch := s.batch
		batch.ObservedAt, batch.FreshUntil = now, now.Add(5*time.Second)
		if err = s.p.RefreshPermissions(ctx, batch); err != nil {
			t.Fatal(err)
		}
		in := secondInput.Plan.Input
		in.CaptureID = custodyID()
		in.Deadline = now.Add(30 * time.Second)
		in.Target.ObservedAt, in.Target.FreshUntil = now, now.Add(5*time.Second)
		in.Capability.ObservedAt, in.Capability.FreshUntil = now, now.Add(5*time.Second)
		set, err = s.retention.policies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		in.Retention, err = privacy.Resolve(set, privacy.Input{Target: s.a.Eligibility.Target, PrivacyClass: "potentialPersonalData", EvidenceType: "context", AnchorAt: now}, time.Now().UTC().Truncate(time.Microsecond))
		if err != nil {
			t.Fatal(err)
		}
		secondInput.Plan, err = compiler.CompileContext(in, time.Now().UTC().Truncate(time.Microsecond))
		if err != nil {
			t.Fatal(err)
		}
		secondInput.IdempotencyKey = "second-history"
		secondInput.SubmissionDigest = artifact.Digest{11}
		secondInput.Registration.Location.ArtifactID = custodyID()
		secondInput.Registration.Location.AttemptID = custodyID()
		secondInput.Registration.AnchorAt = now
		secondInput.Registration.WriteUntil = in.Deadline
		secondInput.Registration.ExpiresAt = in.Retention.ExpiresAt
		secondInput.Registration.DeleteBy = in.Retention.DeleteBy
		projection, err := s.p.Permissions(ctx, s.a.Eligibility.Target)
		if err != nil {
			t.Fatal(err)
		}
		secondInput.Eligibility = authorization.ContextEligibility(s.a.Eligibility.VerifiedIdentity, projection, s.a.Eligibility.Target, time.Now().UTC().Truncate(time.Microsecond))
		secondInput.Recovery = recovery()
		// A source ID is never authority and cannot extend the saved settings.
		bad := secondInput
		bad.IdempotencyKey = "source-expiry-extension"
		bad.RepeatedFrom = &capture.HistoryLineage{CaptureID: first.CaptureID, ExpiresAt: h.Expectation.Registration.ExpiresAt.Add(time.Second)}
		if _, e := s.s.AdmitContext(ctx, bad); !errors.Is(e, capture.ErrChanged) {
			t.Fatal("repeat source expiry extended", e)
		}
		bad.IdempotencyKey = "unknown-history-source"
		bad.RepeatedFrom = &capture.HistoryLineage{CaptureID: custodyID(), ExpiresAt: h.Expectation.Registration.ExpiresAt}
		if _, e := s.s.AdmitContext(ctx, bad); e == nil {
			t.Fatal("unknown source ID authorized a repeat")
		}
		secondInput.RepeatedFrom = &capture.HistoryLineage{CaptureID: first.CaptureID, ExpiresAt: h.Expectation.Registration.ExpiresAt}
		second, err := s.s.AdmitContext(ctx, secondInput)
		if err != nil {
			t.Fatal("second incident", err)
		}
		if second.RepeatedFrom == nil || second.RepeatedFrom.CaptureID != first.CaptureID || !second.RepeatedFrom.ExpiresAt.Equal(h.Expectation.Registration.ExpiresAt) {
			t.Fatal("accepted repeat lost independent lineage", second.RepeatedFrom)
		}
		// Test-induced inconsistency, not an observed production corruption:
		// a visible old row has lost its selector counter. The root ceiling
		// forces eviction, whose zero-row decrement must roll back EVERYTHING,
		// including registerLocked's earlier custody reservation.
		inconsistent, _ := reservation(second)
		inconsistent.Limits.PerInstallation = 1
		type historyCharges struct{ allocationBytes, allocationObjects, poolBytes, poolObjects, attempts int64 }
		charges := func() historyCharges {
			t.Helper()
			var c historyCharges
			if e := admin.QueryRow(ctx, `SELECT a.charged_bytes,a.charged_objects,p.allocated_bytes,p.allocated_objects,(SELECT count(*) FROM custody_attempt WHERE allocation_id=a.id) FROM custody_allocation a JOIN custody_pool p ON p.id=a.pool_id WHERE a.id=$1`, h.Expectation.Registration.AllocationID).Scan(&c.allocationBytes, &c.allocationObjects, &c.poolBytes, &c.poolObjects, &c.attempts); e != nil {
				t.Fatal(e)
			}
			return c
		}
		beforeEviction := charges()
		if changed, e := admin.Exec(ctx, `UPDATE capture_history_quota SET used=0 WHERE root_id=$1 AND selector_key=$2 AND used=1`, s.a.RootID, h.Expectation.SelectorKey[:]); e != nil || changed.RowsAffected() != 1 {
			t.Fatal("inject inconsistent selector quota", e)
		}
		_, refusal := ledger.ReserveHistoryParameters(ctx, inconsistent)
		var oldVisible, newHistory, newAttempt bool
		var rootUsed, selectorUsed int
		if e := admin.QueryRow(ctx, `SELECT visible,
		 (SELECT used FROM capture_history_quota WHERE root_id=$1 AND selector_key=$3),
		 (SELECT used FROM capture_history_quota WHERE root_id=$1 AND selector_key=$4),
		 EXISTS(SELECT 1 FROM capture_history_parameter WHERE capture_id=$5),
		 EXISTS(SELECT 1 FROM custody_attempt WHERE id=$6)
		 FROM capture_history_parameter WHERE root_id=$1 AND capture_id=$2`, s.a.RootID, first.CaptureID, make([]byte, 32), h.Expectation.SelectorKey[:], second.CaptureID, inconsistent.Expectation.Registration.Location.AttemptID).Scan(&oldVisible, &rootUsed, &selectorUsed, &newHistory, &newAttempt); e != nil {
			t.Fatal(e)
		}
		afterEviction := charges()
		if !errors.Is(refusal, privacyapp.ErrFence) || !oldVisible || rootUsed != 1 || selectorUsed != 0 || newHistory || newAttempt || afterEviction != beforeEviction {
			t.Fatalf("inconsistent eviction did not refuse atomically: err=%v visible=%t root=%d selector=%d newHistory=%t newAttempt=%t charges=%+v before=%+v", refusal, oldVisible, rootUsed, selectorUsed, newHistory, newAttempt, afterEviction, beforeEviction)
		}
		if changed, e := admin.Exec(ctx, `UPDATE capture_history_quota SET used=1 WHERE root_id=$1 AND selector_key=$2 AND used=0`, s.a.RootID, h.Expectation.SelectorKey[:]); e != nil || changed.RowsAffected() != 1 {
			t.Fatal("restore fixture selector quota", e)
		}
		t.Log("inconsistent selector eviction refused and rolled back visibility, quota and custody; restored fixture for positive eviction")
		h2, _ := reserve(second)
		if h2.Expectation.Registration.ExpiresAt.After(h.Expectation.Registration.ExpiresAt) {
			t.Fatal("repeat settings extended source lifetime")
		}
		if _, required, e := ledger.ReadHistoryStorage(ctx, capture.SettingsQuery{RootID: s.a.RootID, CaptureID: first.CaptureID, Identity: s.a.Eligibility.VerifiedIdentity, Recovery: recovery()}); e == nil || !required {
			t.Fatal("evicted snapshot fell back to execution scope", e, required)
		}
		legacy, e := postgres.NewContextProgressReads(ctx, pool, s.a.RootID, s.recovery.guard)
		if e != nil {
			t.Fatal(e)
		}
		if settings, e := legacy.ReadCaptureSettings(ctx, capture.SettingsQuery{RootID: s.a.RootID, CaptureID: first.CaptureID, Identity: s.a.Eligibility.VerifiedIdentity, Recovery: recovery()}); e == nil || settings.CaptureID != "" {
			t.Fatal("new recorder-capable capture reconstructed plaintext settings", e)
		}

		var visible bool
		var charged int64
		if err = admin.QueryRow(ctx, "SELECT visible FROM capture_history_parameter WHERE capture_id=$1", first.CaptureID).Scan(&visible); err != nil || visible {
			t.Fatal("own selector did not evict", err)
		}
		if err = admin.QueryRow(ctx, "SELECT charged_bytes FROM custody_allocation WHERE id=$1", h.Expectation.Registration.AllocationID).Scan(&charged); err != nil {
			t.Fatal(err)
		}
		before := charged
		// The wrong raw-evidence prefix really is empty; a backend absence result
		// alone must not authorize release while encrypted history still exists.
		if err = store.PurgeAttempt(ctx, h.Expectation.Registration.Location); err != nil {
			t.Fatal(err)
		}
		if _, err = objects.Read(ctx, h.Expectation, copies); err != nil {
			t.Fatal("raw prefix purge removed history", err)
		}
		time.Sleep(time.Until(h.Expectation.Registration.ExpiresAt) + 10*time.Millisecond)
		if _, err = raw.ClaimDeletion(ctx, h.Expectation.Registration.Location); err == nil {
			t.Fatal("ordinary evidence path acquired history deletion")
		}
		if err = admin.QueryRow(ctx, "SELECT charged_bytes FROM custody_allocation WHERE id=$1", h.Expectation.Registration.AllocationID).Scan(&charged); err != nil || charged != before {
			t.Fatal("wrong-prefix cleanup refunded charge", charged, before, err)
		}
		retire := func(storage capture.HistoryStorage) {
			t.Helper()
			r := recovery()
			deadline := time.Now().Add(4*time.Second + 123*time.Nanosecond)
			bounded, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			claim, e := ledger.ClaimHistoryDeletion(bounded, capture.HistoryDeleteRequest{CaptureID: storage.Expectation.CaptureID, RequestID: custodyID(), ExecutorEpoch: custodyID(), Recovery: r})
			if e != nil {
				t.Fatal("history deletion claim", e)
			}
			if claim.Authority.NotAfter.Nanosecond()%1000 != 0 || claim.Authority.NotAfter.After(deadline) {
				t.Fatal("purge authority did not preserve bounded SQL time precision")
			}
			if e = objects.Purge(ctx, storage.Expectation); e != nil {
				t.Fatal(e)
			}
			c := capture.HistoryDeleteCompletion{RootID: s.a.RootID, CaptureID: storage.Expectation.CaptureID, AttemptID: storage.Expectation.Registration.Location.AttemptID, OperationID: claim.Authority.RequestID, ProcessEpoch: claim.Authority.ExecutorEpoch, ExpectationDigest: capture.HistoryExpectationDigest(storage.Expectation), CopiesDigest: claim.Authority.CopiesDigest, DeletionFence: claim.Authority.DeletionFence, CompletedAt: time.Now().UTC().Truncate(time.Microsecond), NotAfter: claim.Authority.NotAfter}
			if e = ledger.FinishHistoryDeletion(bounded, claim.Authority, c, r); e != nil {
				t.Fatal("history charge settlement", e)
			}
			if e = ledger.FinishHistoryDeletion(bounded, claim.Authority, c, r); e != nil {
				t.Fatal("settlement replay", e)
			}
		}
		retire(h)
		if err = admin.QueryRow(ctx, "SELECT charged_bytes FROM custody_allocation WHERE id=$1", h.Expectation.Registration.AllocationID).Scan(&charged); err != nil || charged != before-h.Expectation.Registration.ReservedBytes() {
			t.Fatal("history charge not released exactly once", charged, before, err)
		}
		// The second reservation never issued any writer. Original WriteUntil and
		// empty-receipt inventory suffice; no idle timer invents writer completion.
		time.Sleep(time.Until(h2.SummaryExpiresAt) + 10*time.Millisecond)
		retire(h2)
		if err = ledger.ExpireHistorySummaries(ctx, recovery()); err != nil {
			t.Fatal(err)
		}
		var used int
		if err = admin.QueryRow(ctx, "SELECT COALESCE((SELECT used FROM capture_history_quota WHERE root_id=$1 AND selector_key=$2),0)", s.a.RootID, h2.Expectation.SelectorKey[:]).Scan(&used); err != nil || used != 0 {
			t.Fatal("expired selector count retained", used, err)
		}
		t.Logf("history physical=%d reserved=%d, own-selector eviction preserved charge until real prefix inventory", copies[0].Bytes+copies[1].Bytes+copies[2].Bytes+copies[3].Bytes, h.Expectation.Registration.ReservedBytes())
	})
}
