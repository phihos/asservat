package integration

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
)

func (f *capacitySQLFixture) qualifyRenewal(t *testing.T, original app.RootConfiguration, first, second app.Enrollment, session capacityManagedSession) {
	t.Helper()
	all := append([]app.Enrollment{first, second}, f.additional...)
	// Refresh only actual fixture source observations/controller leases while
	// original persisted configuration time elapses. No operation/child deadline
	// is rewritten and no synthetic SQL backdating makes renewal eligible.
	for time.Now().Before(original.PlannedUntil.Add(10 * time.Millisecond)) {
		f.refreshBase(t)
		next := time.Now().Add(10 * time.Second)
		if end := original.PlannedUntil.Add(10 * time.Millisecond); end.Before(next) {
			next = end
		}
		capacityWaitUntil(t, f.ctx, next)
	}
	var renewed app.RootConfiguration
	if !t.Run("expired-root-is-unavailable-despite-current-source", func(t *testing.T) {
		f.fresh(t)
		f.assertAdmission(t, 0, first, false)
		f.assertAdmission(t, 1, second, false)
	}) {
		return
	}
	if !t.Run("failed-atomic-renewal-preserves-all-original-rows", func(t *testing.T) {
		// Fixture-only deferred fault after the real renewal's complete child work.
		// It forces COMMIT to fail without changing runtime grants or product code.
		// No assertion uses a fabricated successful SQL result.
		_, err := f.admin.Exec(f.ctx, `CREATE SEQUENCE capacity_native_commit_reached;
   CREATE FUNCTION capacity_native_reject_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('capacity_native_commit_reached'); RAISE EXCEPTION 'synthetic capacity commit fault' USING ERRCODE='23514'; END $$;
   CREATE CONSTRAINT TRIGGER capacity_native_reject_commit AFTER UPDATE ON capacity_source DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.root_configuration IS DISTINCT FROM OLD.root_configuration) EXECUTE FUNCTION capacity_native_reject_commit()`)
		if err != nil {
			t.Fatal("bounded SQL fault setup", err)
		}
		remove := func() {
			clean, end := context.WithTimeout(context.Background(), 5*time.Second)
			defer end()
			if _, e := f.admin.Exec(clean, `DROP TRIGGER IF EXISTS capacity_native_reject_commit ON capacity_source; DROP FUNCTION IF EXISTS capacity_native_reject_commit(); DROP SEQUENCE IF EXISTS capacity_native_commit_reached`); e != nil {
				t.Error("SQL fault cleanup failed", e)
			}
		}
		defer remove()
		o := f.rootObservation(t)
		before := f.renewalRows(t)
		if _, err = f.roots.RenewCapacityRoot(f.ctx, o, original); err == nil {
			t.Fatal("failed deferred COMMIT returned a renewal")
		}
		// Sequence advancement survives transaction rollback and supplies only a
		// fixture-local reachability witness. It confers no product authority.
		var reached bool
		if err = f.admin.QueryRow(f.ctx, `SELECT is_called FROM capacity_native_commit_reached`).Scan(&reached); err != nil || !reached {
			t.Fatal("renewal did not reach the intended deferred COMMIT fault", err)
		}
		after := f.renewalRows(t)
		if before != after {
			t.Fatal("failed atomic renewal changed root, child dates or original spend")
		}
		f.assertOriginalSession(t, session)
	}) {
		return
	}
	if !t.Run("general-renewal-cannot-edit-capture-phase", func(t *testing.T) {
		o := f.rootObservation(t)
		captureBefore := f.captureRows(t)
		start := time.Now()
		var err error
		renewed, err = f.roots.RenewCapacityRoot(f.ctx, o, original)
		if err != nil {
			t.Fatal("actual general renewal", err)
		}
		if !original.CompatibleRenewal(renewed, o) || renewed.Revision != original.Revision+1 || renewed.CaptureBackedAt != nil || renewed.ReadyAt != nil || !renewed.InitialObservedAt.Equal(original.InitialObservedAt) || !renewed.InitialUntil.Equal(original.InitialUntil) {
			t.Fatal("renewal replaced original identity/interval")
		}
		if f.captureRows(t) != captureBefore {
			t.Fatal("role70 rewrote role71 capture fields")
		}
		f.assertOriginalSession(t, session)
		f.assertAdmission(t, 0, first, false)
		f.assertAdmission(t, 1, second, false)
		if _, err = f.roots.PublishCapacityRoot(f.ctx, o, renewed); err == nil {
			t.Fatal("renewal published without independently complete capture phase")
		}
		t.Logf("renewal_accounts=%d renewal_general_ms=%d original_remaining_ms=%d", len(all), time.Since(start).Milliseconds(), time.Until(o.FreshUntil).Milliseconds())
	}) {
		return
	}
	if !t.Run("expired-renewal-observation-new-current-continuation", func(t *testing.T) {
		capacityWaitUntil(t, f.ctx, renewed.RevisionUntil.Add(10*time.Millisecond))
		o := f.rootObservation(t)
		prior := renewed
		var err error
		renewed, err = f.captureRoots.BackCapacityRoot(f.ctx, o, renewed)
		if err != nil {
			t.Fatal("current capture renewal continuation", err)
		}
		if !prior.CompatibleContinuation(renewed) || renewed.CaptureBackedAt == nil || renewed.ReadyAt != nil {
			t.Fatal("capture continuation changed original phase interval")
		}
		f.assertAdmission(t, 0, first, false)
		f.assertAdmission(t, 1, second, false)
		renewed, err = f.roots.PublishCapacityRoot(f.ctx, o, renewed)
		if err != nil || !renewed.AdmissionReady(time.Now()) {
			t.Fatal("actual fully backed renewal publication", err)
		}
		// Root refresh never substitutes for independent current target metadata.
		f.assertAdmission(t, 0, first, false)
		f.assertAdmission(t, 1, second, false)
		for i, w := range all {
			observation := f.workloadObservation(t, i)
			if err = f.enrollments.RefreshCapacityEnrollment(f.ctx, observation, w); err != nil {
				t.Fatal("exact renewed workload observation", err)
			}
			current, e := f.enrollments.ReadCapacityEnrollment(f.ctx, observation)
			if e != nil || current == nil || !reflect.DeepEqual(*current, w) {
				t.Fatal("renewal changed original enrollment or phase facts", e)
			}
			f.assertAdmission(t, i, w, true)
		}
		var attempts, accounts int
		if err = f.admin.QueryRow(f.ctx, `SELECT count(DISTINCT attempt_id),count(DISTINCT allocation_id) FROM capacity_workload WHERE root_id=$1`, f.input.PermissionRootID).Scan(&attempts, &accounts); err != nil || attempts != len(all) || accounts != len(all) {
			t.Fatal("renewal manufactured new workload identities", err)
		}
		f.assertOriginalSession(t, session)
	}) {
		return
	}
	t.Run("ready-replay-is-read-only", func(t *testing.T) {
		o := f.rootObservation(t)
		before := f.renewalRows(t)
		replay, err := (&app.RootBackingCoordinator{Store: f.roots, Capture: f.captureRoots, Now: time.Now}).Reconcile(f.ctx, o)
		if err != nil || !reflect.DeepEqual(replay, renewed) || before != f.renewalRows(t) {
			t.Fatal("completed current replay changed backing", err)
		}
	})
}

func (f *capacitySQLFixture) captureRows(t *testing.T) string {
	t.Helper()
	var b []byte
	err := f.admin.QueryRow(f.ctx, `SELECT jsonb_build_object('pool',(SELECT to_jsonb(x) FROM operation_audit_pool x WHERE root_id=$1 AND lane='capture'),'allocations',(SELECT jsonb_agg(to_jsonb(x) ORDER BY allocation_id) FROM capture_audit_allocation x WHERE root_id=$1),'root',(SELECT to_jsonb(x) FROM capture_audit_root x WHERE root_id=$1))`, f.input.PermissionRootID).Scan(&b)
	if err != nil || !json.Valid(b) {
		t.Fatal("capture accounting read", err)
	}
	return string(b)
}

func (f *capacitySQLFixture) renewalRows(t *testing.T) string {
	t.Helper()
	var b []byte
	// Exclude only current source-observation fields. All fixed source funding,
	// revision/phase facts, counters and child original dates remain compared.
	err := f.admin.QueryRow(f.ctx, `SELECT jsonb_build_object(
 'root',(SELECT to_jsonb(x)-ARRAY['observed_at','fresh_until','accepted_snapshot'] FROM capacity_source x WHERE root_id=$1),
 'custody',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM custody_allocation x WHERE id IN(SELECT allocation_id FROM capacity_workload WHERE root_id=$1)),
 'control',(SELECT jsonb_agg(to_jsonb(x) ORDER BY allocation_id) FROM context_control_account x WHERE root_id=$1),
 'downloads',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM download_allocation x WHERE root_id=$1),
 'responses',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM download_control_allocation x WHERE root_id=$1),
 'native',(SELECT jsonb_agg(to_jsonb(x) ORDER BY allocation_id) FROM download_native_backing x WHERE root_id=$1),
 'stop',(SELECT jsonb_agg(to_jsonb(x) ORDER BY allocation_id) FROM download_stop_backing x WHERE root_id=$1),
 'sessions',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM artifact_download x WHERE root_id=$1),
 'processing',(SELECT to_jsonb(x) FROM processing_root x WHERE root_id=$1),
 'audit',(SELECT jsonb_agg(to_jsonb(x) ORDER BY lane) FROM operation_audit_pool x WHERE root_id=$1))`, f.input.PermissionRootID).Scan(&b)
	if err != nil || !json.Valid(b) {
		t.Fatal("complete original renewal readback", err)
	}
	return string(b) + f.accounting(t) + f.captureRows(t)
}
