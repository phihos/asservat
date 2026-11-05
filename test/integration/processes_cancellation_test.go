package integration

import (
	"context"
	"crypto/tls"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestProcessesCancellationWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, nil, false, false, false, false, false, false, false, false, true, true)
	})
}

// The actual process/node cancellation join is supplied, not performed here.
// This checks the protected SQL state, exact typed owner and nonrefund semantics.
func qualifyProcessesStartedCancellation(t *testing.T, f *capacitySQLFixture, s captureAdmissionScenario, accepted capture.Accepted, store *postgres.APIContextExecutions, running execution.APIExecution, refresh func() executionapp.APIExecutionCheck) {
	t.Helper()
	ctx := f.ctx
	check := refresh()
	e := accepted.Expectation
	var revision, charged int64
	if err := f.admin.QueryRow(ctx, `SELECT progress_revision FROM context_capture WHERE root_id=$1 AND id=$2`, s.a.RootID, accepted.CaptureID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.QueryRow(ctx, `SELECT charged_bytes FROM custody_allocation WHERE id=$1`, e.Registration.AllocationID).Scan(&charged); err != nil {
		t.Fatal(err)
	}
	ids, err := store.StartedRecordings(ctx, time.Now().UTC(), 64)
	if err != nil || len(ids) != 1 || ids[0] != accepted.CaptureID {
		t.Fatal("started process collection locator", ids, err)
	}
	request := capture.CancellationCheck{RootID: s.a.RootID, Request: capture.CancellationRequest{CaptureID: accepted.CaptureID, ExpectedRevision: revision, IdempotencyKey: "stop-processes"}, Identity: check.Eligibility.VerifiedIdentity, Recovery: check.Recovery, CheckedAt: time.Now().UTC().Truncate(time.Microsecond), ValidUntil: check.ValidUntil}
	stopped, err := store.RequestCaptureCancellation(ctx, request)
	if err != nil || stopped.Processes == nil || stopped.Profile != nil || stopped.Recording != nil || stopped.Snapshot != nil || stopped.Group != nil || stopped.Decision.Phase != "Running" || !stopped.Decision.Requested || stopped.Decision.ApplicationStopUnknown {
		t.Fatal("typed process cancellation request", err)
	}
	stop := stopped.Processes
	if stop.CaptureID != accepted.CaptureID || stop.AttemptID != e.Registration.Location.AttemptID || stop.WriterPodUID != running.Process.PodUID || stop.WriterEpoch != running.Process.ProcessEpoch || stop.ExpectationDigest != running.ExpectationDigest || !stop.WriteUntil.Equal(e.Registration.WriteUntil) {
		t.Fatal("Stop changed original owner/expectation/deadline")
	}
	replay, err := store.RequestCaptureCancellation(ctx, request)
	if err != nil || replay.Processes == nil || *replay.Processes != *stop || replay.Decision.Revision != stopped.Decision.Revision {
		t.Fatal("process Stop replay replaced owner", err)
	}
	cancelled := running
	cancelled.Phase = "cancelled"
	cancelled.CompletedAt = time.Now().UTC().Truncate(time.Microsecond)
	proof := artifact.ProcessCancellation{CaptureID: accepted.CaptureID, AttemptID: e.Registration.Location.AttemptID, WriterPodUID: running.Process.PodUID, WriterEpoch: running.Process.ProcessEpoch, ExpectationDigest: running.ExpectationDigest, JoinedAt: cancelled.CompletedAt}
	for name, edit := range map[string]func(*artifact.ProcessCancellation){"capture": func(p *artifact.ProcessCancellation) { p.CaptureID = custodyID() }, "attempt": func(p *artifact.ProcessCancellation) { p.AttemptID = custodyID() }, "pod": func(p *artifact.ProcessCancellation) { p.WriterPodUID = custodyID() }, "epoch": func(p *artifact.ProcessCancellation) { p.WriterEpoch = custodyID() }, "digest": func(p *artifact.ProcessCancellation) { p.ExpectationDigest[0] ^= 1 }} {
		t.Run(name, func(t *testing.T) {
			wrong := proof
			edit(&wrong)
			if _, err := store.RecordAPIProcessesCancellation(ctx, cancelled, wrong, check.Process, check.Recovery); err == nil {
				t.Fatal("changed cancellation accepted")
			}
		})
	}
	done, err := store.RecordAPIProcessesCancellation(ctx, cancelled, proof, check.Process, check.Recovery)
	if err != nil || !reflect.DeepEqual(done, cancelled) {
		t.Fatal("joined process cancellation", err)
	}
	again, err := store.RecordAPIProcessesCancellation(ctx, cancelled, proof, check.Process, check.Recovery)
	if err != nil || !reflect.DeepEqual(again, cancelled) {
		t.Fatal("process join replay", err)
	}
	joined, err := store.RequestCaptureCancellation(ctx, request)
	if err != nil || joined.Processes != nil || joined.Decision.Phase != "Cancelled" || joined.Decision.ApplicationStopUnknown {
		t.Fatal("joined process Stop status", err)
	}
	var after, published int64
	if err = f.admin.QueryRow(ctx, `SELECT (SELECT charged_bytes FROM custody_allocation WHERE id=$1),(SELECT count(*) FROM context_catalog WHERE root_id=$2 AND capture_id=$3)`, e.Registration.AllocationID, s.a.RootID, accepted.CaptureID).Scan(&after, &published); err != nil || after != charged || published != 0 {
		t.Fatal("Stop refunded or published unjoined source", after, charged, published, err)
	}
	t.Log("typed process Stop requested once, exact owner/expectation/original cutoff, wrong owner controls denied, joined SQL replay, original storage charge retained; node join synthetic")
}
