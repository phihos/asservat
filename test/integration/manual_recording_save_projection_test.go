//go:build cgo && libpcap

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

// A pristine separate N2 fixture keeps these controlled waits out of the N16
// workflow's original source/request interval. Current SQL authority is real;
// the short caller observation is an explicit synthetic fixture input.
func TestManualRecordingSaveGroupProjectionLockWithRealServices(t *testing.T) {
	qualifySourceSnapshotServicesMode(t, sourceSnapshotQualificationMode{manual: true, groupCount: 2, projection: true})
}

type projectionMutationResult struct {
	err        error
	returnedAt time.Time
}

func qualifyManualRecordingProjectionLock(t *testing.T, ctx context.Context, f *capacitySQLFixture, admissions *postgres.ContextAdmissions, policy policySourceAcceptedFixture, group value.RecordingSaveGroupAdmission) {
	t.Helper()
	if len(group.Children) != 2 || group.RequestBounds != nil {
		t.Fatal("projection control requires genuine legacy-bounded N2 group")
	}
	before := readManualSaveCounters(t, ctx, f, policy)
	windows := manualGroupWindows(t, ctx, f, policy)
	capacity := manualGroupCapacity(t, ctx, f)
	blocker, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(ctx)
	var blockerPID int
	if err = blocker.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	if _, err = blocker.Exec(ctx, "SELECT id FROM custody_pool WHERE id=$1 FOR UPDATE", policy.Scenario.poolID); err != nil {
		t.Fatal(err)
	}
	var sampled time.Time
	if err = f.admin.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&sampled); err != nil {
		t.Fatal(err)
	}
	until := identity.Earlier(sampled.Add(700*time.Millisecond), manualGroupProofDeadline(group)).UTC().Truncate(time.Microsecond)
	probe := group
	probe.Children = append([]value.Admission(nil), group.Children...)
	for n := range probe.Children {
		child := &probe.Children[n]
		manual := *child.RecordingSave
		child.RecordingSave = &manual
		until = identity.Earlier(until, identity.Earlier(child.Eligibility.ValidUntil, manual.Initiator.ValidUntil))
		until = identity.Earlier(until, identity.Earlier(child.Eligibility.VerifiedIdentity.ValidUntil, manual.Initiator.VerifiedIdentity.ValidUntil))
	}
	if until.Sub(sampled) < 500*time.Millisecond {
		t.Fatal("original facts too short before controlled lock probe")
	}
	for n := range probe.Children {
		child := &probe.Children[n]
		child.Eligibility.ValidUntil = until
		child.Eligibility.VerifiedIdentity.ValidUntil = identity.Earlier(child.Eligibility.VerifiedIdentity.ValidUntil, until)
		child.RecordingSave.Initiator.ValidUntil = until
		child.RecordingSave.Initiator.VerifiedIdentity.ValidUntil = identity.Earlier(child.RecordingSave.Initiator.VerifiedIdentity.ValidUntil, until)
	}
	admitContext, cancelAdmission := context.WithCancel(ctx)
	mutationContext, cancelMutation := context.WithCancel(ctx)
	admissionDone := make(chan error, 1)
	var mutationDone chan projectionMutationResult
	admissionJoined, mutationJoined := false, false
	defer func() {
		_ = blocker.Rollback(ctx)
		cancelAdmission()
		cancelMutation()
		if !admissionJoined {
			<-admissionDone
		}
		if mutationDone != nil && !mutationJoined {
			<-mutationDone
		}
	}()
	go func() { _, err := admissions.AdmitRecordingSaveGroup(admitContext, probe); admissionDone <- err }()
	// The grouped preflight has loaded both exact raw projections before this
	// existing pool lock. Do not add a production test hook or cache-monitor row.
	var admissionPID int
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var observed time.Time
		err = f.admin.QueryRow(ctx, `SELECT pid,clock_timestamp() FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid)) AND query LIKE '%-- name: LockPool :one%' LIMIT 1`, f.roles["capture-admit"].Config().ConnConfig.User, blockerPID).Scan(&admissionPID, &observed)
		if err == nil {
			if !observed.Before(until) {
				t.Fatal("admission reached gate after original authority expired")
			}
			break
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("observe real admission pool wait", err)
		}
		if !time.Now().Before(until) {
			t.Fatal("admission did not reach pool gate within original authority")
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	next := policyRecorderCloneBatch(f.batch)
	next.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	next.FreshUntil = next.ObservedAt.Add(5 * time.Second)
	mutationDone = make(chan projectionMutationResult, 1)
	go func() {
		err := f.permission.RefreshPermissions(mutationContext, next)
		mutationDone <- projectionMutationResult{err: err, returnedAt: time.Now()}
	}()
	for {
		var observed time.Time
		err = f.admin.QueryRow(ctx, `SELECT clock_timestamp() FROM pg_stat_activity WHERE usename='authority_runtime' AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%-- name: LockPermissionStream :one%' LIMIT 1`, admissionPID).Scan(&observed)
		if err == nil {
			if !observed.Before(until) {
				t.Fatal("permission writer gate observed only after original authority expiry")
			}
			break
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("observe actual permission writer blocked by admission root", err)
		}
		if !time.Now().Before(until) {
			t.Fatal("actual permission writer did not wait on admission root before expiry")
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	var releasedDBTime time.Time
	for {
		if err = f.admin.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&releasedDBTime); err != nil {
			t.Fatal(err)
		}
		if !releasedDBTime.Before(until) {
			break
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	releasedAt := time.Now()
	if err = blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	admissionErr := <-admissionDone
	admissionJoined = true
	mutation := <-mutationDone
	mutationJoined = true
	if !errors.Is(admissionErr, value.ErrDenied) {
		t.Fatal("expired original group authority crossed blocking pool lock", admissionErr)
	}
	if mutation.err != nil || mutation.returnedAt.Before(releasedAt) {
		t.Fatal("actual permission refresh escaped root lock or failed after rollback", mutation.err)
	}
	// Only the legitimate observer timestamp changes. No expected snapshot of the
	// whole permission row is compared against a writer that must refresh it.
	f.batch = next
	if readManualSaveCounters(t, ctx, f, policy) != before || manualGroupWindows(t, ctx, f, policy) != windows || manualGroupCapacity(t, ctx, f) != capacity {
		t.Fatal("refused cached group retained policy/GCRA/reservation/custody/control spend")
	}
	var rows int
	if err = f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM recording_save_group WHERE id=$1)+(SELECT count(*) FROM context_capture WHERE group_id=$1)`, group.Preview.CaptureID).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("refused cached group retained parent/child rows", rows, err)
	}
	t.Logf("actual_projection_root_lock admission_pid=%d blocker_pid=%d original_until=%s release_dbtime=%s permission_writer_after_release=true parent_children=0 owned_spend_delta=0", admissionPID, blockerPID, until.Format(time.RFC3339Nano), releasedDBTime.Format(time.RFC3339Nano))
}
