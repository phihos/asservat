package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/browser"
	native "asservat.local/asservat/internal/transport/native"
	"asservat.local/asservat/internal/transport/presentation"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual SQL/S3/three-slot key service, current C03 checks, regional h2 exchange,
// runtime, public content handler and HTTPS sink. The inherited Pod proof,
// protected source/backing qualification, Job API, issuer and browser session
// are explicitly synthetic fixture inputs. No installed SSO/Pod/bootstrap or
// large-file/backend-history qualification is inferred from these tests.
type nativeContextFixture struct {
	retry         *nativeInterruptedState
	mode          string
	dispatcher    *evidence.DownloadDispatcher
	workers       *postgres.DownloadWorkers
	configuration *postgres.WorkerConfigurations
}

func contextNativeSQLRoles(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	// Add only the read sets needed by the new paired adapters. Runtime effect
	// roles retain their existing narrow writes; this never grants key/PKI audit.
	for _, q := range []string{
		"GRANT SELECT ON download_native_backing,download_native_owner,download_response,download_window,download_key_binding,download_worker_enrollment,download_worker_certificate TO download_worker_runtime",
		"GRANT SELECT ON download_native_backing,download_native_owner,download_worker,context_case_locator,custody_copy TO download_runtime",
		"CREATE ROLE native_plan_runtime LOGIN PASSWORD 'synthetic-native-plan'",
		"GRANT CONNECT ON DATABASE custody_test TO native_plan_runtime",
		"GRANT USAGE ON SCHEMA public TO native_plan_runtime",
		"GRANT SELECT ON goose_db_version,fleet_current_trust,download_allocation,download_control_allocation,download_native_backing TO native_plan_runtime",
		"GRANT UPDATE(installation_id) ON fleet_current_trust TO native_plan_runtime",
	} {
		if strings.HasPrefix(q, "CREATE ROLE ") {
			var exists bool
			if e := admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)", strings.Fields(q)[2]).Scan(&exists); e != nil {
				t.Fatal(e)
			}
			if exists {
				continue
			}
		}
		if _, e := admin.Exec(ctx, q); e != nil {
			t.Fatal("native context fixture role", e)
		}
	}
}
func qualifyFirstContextPreparationRace(t *testing.T, ctx context.Context, f nativeExchangeFixture) {
	t.Helper()
	first, e := postgres.NewFirstContextPreparations(f.runtime)
	if e != nil {
		t.Fatal(e)
	}
	a := f.authority()
	session, e := f.runtime.LookupDownload(ctx, f.worker.Intent.SessionID, a.Scope.Principal)
	if e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	done := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, e := first.BeginDownloadBatch(ctx, session.ID, a, artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadMetadata, ReadBytes: evidence.ContextDownloadReadWork})
			done <- e
		}()
	}
	close(start)
	winners := 0
	for range 2 {
		if <-done == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("concurrent first preparation winners", winners)
	}
	// Discarding that positive response models the caller's unknown commit. A
	// fresh request/batch must never turn it into another decrypt/wrapping grant.
	if _, e = first.BeginDownloadBatch(ctx, session.ID, f.authority(), artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadMetadata, ReadBytes: evidence.ContextDownloadReadWork}); e == nil {
		t.Fatal("lost first admission refilled preparation")
	}
	s, e := f.runtime.LookupDownload(ctx, session.ID, a.Scope.Principal)
	if e != nil || s.Generation != 1 || s.ChargedRead != evidence.ContextDownloadReadWork {
		t.Fatal("original attempt accounting", s.Generation, s.ChargedRead, e)
	}
	var batches, keys int
	if e = f.admin.QueryRow(ctx, "SELECT count(*) FROM download_batch WHERE session_id=$1", session.ID).Scan(&batches); e != nil || batches != 1 {
		t.Fatal("second preparation batch", batches, e)
	}
	if e = f.admin.QueryRow(ctx, "SELECT count(*) FROM download_key_binding WHERE session_id=$1", session.ID).Scan(&keys); e != nil || keys != 0 {
		t.Fatal("admission alone performed key work", keys, e)
	}
}

type nativeContextServing struct{ until time.Time }

func (s nativeContextServing) ContextNativeReady(ctx context.Context) (time.Time, error) {
	return minPublicationTime(time.Now().Add(5*time.Second), s.until), ctx.Err()
}

func qualifyContextNativeContent(t *testing.T, ctx context.Context, f nativeExchangeFixture, owners *postgres.NativeOwners, firstOwners *postgres.FirstContextNativeOperations, origins evidence.NativeOrigins, router *native.HubRouter, prepKeys *postgres.DownloadKeys, windowKeys *postgres.NativeKeys, en value.WorkerEnrollment, target value.WorkerCredentialTarget, joined <-chan nativeSQLWorkerOutcome, stopWorker func()) {
	t.Helper()
	root := f.worker.Intent.Authority.Scope.RootID
	first, e := postgres.NewFirstContextPreparations(f.runtime)
	if e != nil {
		t.Fatal(e)
	}
	responses, e := postgres.NewFirstContextResponses(f.runtime)
	if e != nil {
		t.Fatal(e)
	}
	ownerPod, epoch := custodyID(), custodyID()
	cfg := evidence.ContextNativeRuntimeConfig{Serving: nativeContextServing{target.RunUntil}, Profile: f.worker.Intent.Profile, Configuration: f.content.configuration, Workers: f.content.workers, Preparation: first, Dispatcher: f.content.dispatcher, Sources: f.runtime, Authority: f.gate, Audit: &objectstore.DownloadAuditObjects{Store: f.store, Seal: f.keys, Open: f.keys}, Acknowledgements: f.audit, Native: evidence.NativeAttachmentConfig{HubPodUID: ownerPod, HubProcessEpoch: epoch, KeyScope: f.keyScope, Owners: firstOwners, Fences: owners, Origins: origins, Registrar: router, PreparationKeys: prepKeys, WindowKeys: windowKeys}, Now: time.Now, NewID: custodyID}
	runtime, e := evidence.NewContextNativeRuntime(cfg)
	if e != nil {
		t.Fatal("actual native runtime", e)
	}
	defer runtime.Close()
	current := func() identities.CurrentIdentity {
		c, _ := browserCurrentForWorkerTest(t, ctx, f.gate, 5*time.Second)
		return c
	}
	session, e := f.runtime.LookupDownload(ctx, target.SessionID, f.worker.Intent.Authority.Scope.Principal)
	if e != nil {
		t.Fatal("native context initial session lookup", e)
	}
	t.Log("native context initial session resolved")
	if _, found, e := runtime.ReadPreparedContextDownload(ctx, current(), session); e != nil || found {
		t.Fatal("pending read started metadata", found, e)
	}
	t.Log("native context pending metadata read completed")
	source, e := f.runtime.ReadContextDownloadSource(ctx, f.authority())
	if e != nil {
		t.Fatal("native context initial source lookup", e)
	}
	t.Log("native context initial source resolved")
	if result, e := runtime.ContinueContextDownload(ctx, current(), session, source); e != nil || result.Pending {
		t.Fatal("original preparation continuation", result, e)
	}
	source, e = f.runtime.ReadContextDownloadSource(ctx, f.authority())
	if e != nil {
		t.Fatal("native context source lookup before replay", e)
	}
	if _, e = runtime.ContinueContextDownload(ctx, current(), session, source); e != nil {
		t.Fatal("positive committed original preparation replay", e)
	}
	session, e = f.runtime.LookupDownload(ctx, session.ID, session.Scope.Principal)
	if e != nil {
		t.Fatal(e)
	}
	if session.Generation != 1 {
		t.Fatal("preparation was not the sole attempt", session.Generation)
	}
	var batch string
	var roles int
	if e = f.admin.QueryRow(ctx, "SELECT batch_id::text,used_roles FROM download_key_binding WHERE session_id=$1", session.ID).Scan(&batch, &roles); e != nil || roles != 7 {
		t.Fatal("original three preparation key slots", roles, e)
	}
	prep := artifact.DownloadPreparation{SessionID: session.ID, BatchID: batch, Generation: 1}
	control := artifact.DownloadControlAllocation{ID: f.allocation.ID, RootID: root, AuditStoreID: f.published.Expectation.Registration.StoreID, WindowLimit: 2, AuditByteLimit: 4 * artifact.DownloadWindowAuditBytes, ValidUntil: f.allocation.ValidUntil, AuditWriteUntil: f.allocation.ValidUntil.Add(time.Minute)}
	if e = f.config.BindDownloadControlAllocation(ctx, control); e != nil {
		t.Fatal(e)
	}
	if f.content.mode == "native-control-races" || f.content.mode == "native-control-admission-race" {
		requireContextNativeJoined(t, joined, target, 1)
		stopWorker()
		qualifyContextNativeControlRaces(t, ctx, f, en, firstOwners, responses, runtime, prep, ownerPod, epoch)
		return
	}
	firstMetadata, found, e := runtime.ReadPreparedContextDownload(ctx, current(), session)
	if e != nil || !found {
		t.Fatal("original acknowledged native result", found, e)
	}
	updates := func() int64 {
		t.Helper()
		var n int64
		if e := f.admin.QueryRow(ctx, "SELECT updates FROM download_native_owner WHERE worker_id=$1", target.WorkerID).Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	before := updates()
	// The same process hands its acknowledged prepare facts to the first read,
	// so no second Observe conversation is spent (previously four transitions).
	if before != 2 {
		t.Fatal("prepare alone costs two transitions", before)
	}
	for i := 0; i < 40; i++ {
		m, ok, e := runtime.ReadPreparedContextDownload(ctx, current(), session)
		if e != nil || !ok || m != firstMetadata {
			t.Fatal("current warm status", i, e)
		}
	}
	if updates() != before {
		t.Fatal("routine polling consumed native credits")
	}
	// The accepted allocation reader performs no reservation and preserves the
	// earliest backing end. Mutation privileges remain absent on its SQL role.
	planPool := f.poolFor("native_plan_runtime", "synthetic-native-plan")
	defer planPool.Close()
	readLimit := int64(8 << 20)
	if f.content.mode == "native-content-resume" || f.content.mode == "native-content-interrupted" {
		readLimit = 12 << 20
	}
	plans, e := postgres.NewContextDownloadPlans(ctx, planPool, root, target.InstallationID, f.worker.Intent.Profile, f.content.configuration, postgres.ContextDownloadPlanLimits{OutputLimit: 8192, ReadLimit: readLimit})
	if e != nil {
		t.Fatal(e)
	}
	source, e = f.runtime.ReadContextDownloadSource(ctx, f.authority())
	if e != nil {
		t.Fatal(e)
	}
	plan, e := plans.ContextDownloadPlan(ctx, source)
	if (f.content.retry == nil || !f.content.retry.second) && (e != nil || plan.HardUntil.IsZero() || plan.HardUntil.After(f.allocation.ValidUntil)) {
		t.Fatal("accepted allocation plan", e)
	}
	for _, q := range []string{"UPDATE download_allocation SET reserved_output=0 WHERE id=$1", "UPDATE download_native_backing SET charged_rows=0 WHERE allocation_id=$1"} {
		_, e = planPool.Exec(ctx, q, f.allocation.ID)
		var pg *pgconn.PgError
		if !errors.As(e, &pg) || pg.Code != "42501" {
			t.Fatal("plan role gained effects", e)
		}
	}
	objects, e := objectstore.NewDownloadWindowAuditObjects(f.store, control.AuditStoreID, f.keys, f.keys)
	if e != nil {
		t.Fatal(e)
	}
	transfer := evidence.DownloadResponseTransfer{Sessions: first, Responses: responses, Authority: f.gate, Objects: objects, Audit: f.audit, Now: time.Now, NewID: custodyID}
	coordinator := evidence.ContextDownloadCoordinator{RootID: root, InstallationID: target.InstallationID, Routes: f.runtime, Sources: f.runtime, Authority: f.gate, Sessions: f.runtime, Plans: plans, Runtime: runtime, Now: time.Now, NewID: custodyID}
	if f.content.mode == "native-content-interrupted" {
		qualifyContextNativeInterrupted(t, ctx, f, runtime, transfer, coordinator, session, firstMetadata.Native, target, joined, stopWorker)
		return
	}
	if f.content.mode == "native-content-resume" {
		qualifyContextNativeResume(t, ctx, f, runtime, transfer, coordinator, session, firstMetadata.Native, target, joined)
		return
	}
	serveContextNativeGET(t, ctx, f, runtime, transfer, coordinator, session, firstMetadata.Native)
	requireContextNativeJoined(t, joined, target, 2) // prepare and GET; no Observe (ADR-167)
	if updates() != 4 {
		t.Fatal("ordinary pending/prepare/poll/GET did not fit original eight-transition backing", updates())
	}
	var windows, used int
	if e = f.admin.QueryRow(ctx, "SELECT count(*),COALESCE(sum(used_roles),0) FROM download_native_key WHERE worker_id=$1", target.WorkerID).Scan(&windows, &used); e != nil || windows != 1 || used != 7 {
		t.Fatal("one exact content key window", windows, used, e)
	}
	finished, e := f.runtime.LookupDownload(ctx, session.ID, session.Scope.Principal)
	if e != nil || finished.State != artifact.DownloadCompleted {
		t.Fatal("whole native HTTP response completion", finished.State, e)
	}
	// A second exact-target allocation is ambiguous even when it lacks the
	// supported backing. The reader must not fall back to the usable candidate.
	ambiguous := f.allocation
	ambiguous.ID = custodyID()
	if e = f.config.BindDownloadAllocation(ctx, ambiguous); e != nil {
		t.Fatal("second independently configured allocation", e)
	}
	source, e = f.runtime.ReadContextDownloadSource(ctx, f.authority())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = plans.ContextDownloadPlan(ctx, source); e == nil {
		t.Fatal("ambiguous allocation selected a preferred backed candidate")
	}
	t.Log("actual bounded runtime and GET completed; synthetic session, Job, Pod, issuer and accepted installation/backing inputs remain explicit")
}
func requireContextNativeJoined(t *testing.T, joined <-chan nativeSQLWorkerOutcome, target value.WorkerCredentialTarget, count int) {
	t.Helper()
	seen := map[string]bool{}
	for range count {
		select {
		case d := <-joined:
			if d.err != nil || d.result.State != contracts.NativeJoined || d.result.Reference.SessionID != target.SessionID || d.result.Reference.WorkerID != target.WorkerID || seen[d.result.Reference.OperationID] {
				t.Fatal("native conversation not positively joined", d.result.State, d.err)
			}
			seen[d.result.Reference.OperationID] = true
		case <-time.After(5 * time.Second):
			t.Fatal("missing joined native conversation")
		}
	}
}

func qualifyContextNativeControlRaces(t *testing.T, ctx context.Context, f nativeExchangeFixture, en value.WorkerEnrollment, nativeOwners *postgres.FirstContextNativeOperations, responses *postgres.FirstContextResponses, runtime *evidence.ContextNativeRuntime, prep artifact.DownloadPreparation, pod, epoch string) {
	t.Helper()
	if f.content.mode == "native-control-races" {
		qualifyNativeCompletionClosed(t, ctx, f, nativeOwners)
	}
	// A second independent adapter/pool represents another replica. Both locks
	// must serialize through SQL; no shared Go mutex supplies correctness.
	secondPool := f.poolFor("download_runtime", "synthetic-download")
	defer secondPool.Close()
	secondLedger, e := postgres.NewDownloads(ctx, secondPool, f.allocation.RootID, f.guards)
	if e != nil {
		t.Fatal(e)
	}
	second, e := postgres.NewFirstContextResponses(secondLedger)
	if e != nil {
		t.Fatal(e)
	}
	newObserve := func(a artifact.DownloadAuthority) value.NativeOperation {
		fence, e := nativeOwners.NextNativeFence(ctx, f.worker.Intent.ID)
		if e != nil {
			t.Fatal(e)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		return value.NativeOperation{Path: a.Environment.Path, Processing: a.Environment.Processing, Reference: value.NativeReference{InstallationID: f.worker.Binding.InstallationID, SessionID: prep.SessionID, WorkerID: f.worker.Intent.ID, OperationID: custodyID(), Fence: fence}, Kind: value.NativeObserve, HubPodUID: pod, HubProcessEpoch: epoch, WorkerPodUID: f.worker.Binding.PodUID, WorkerPublicKey: en.PublicKeyDigest, SourceVersion: a.Scope.Version, ParentID: prep.BatchID, Generation: prep.Generation, StartedAt: now, Until: minPublicationTime(now.Add(5*time.Second), a.ValidUntil).UTC().Truncate(time.Microsecond)}
	}
	newResponse := func() artifact.DownloadResponse {
		return artifact.DownloadResponse{ID: custodyID(), SessionID: prep.SessionID, OwnerID: custodyID(), Plan: artifact.DownloadResponsePlan{Version: artifact.DownloadResponseVersion, Selection: artifact.DownloadSelection{Length: 1}, WindowReadLimit: evidence.ContextDownloadReadWork}, Until: f.worker.Intent.RunUntil}
	}
	counts := func() [10]int64 {
		t.Helper()
		var v [10]int64
		if e := f.admin.QueryRow(ctx, `SELECT (SELECT updates FROM download_native_owner WHERE worker_id=$1),
 (SELECT count(*) FROM download_response WHERE session_id=$2),
 0::bigint,
 (SELECT reserved_windows FROM download_control_allocation WHERE id=$3),
 (SELECT charged_output FROM artifact_download WHERE id=$2),
 (SELECT charged_read FROM artifact_download WHERE id=$2),
 (SELECT generation FROM artifact_download WHERE id=$2),
 (SELECT coalesce(sum(used_roles),0) FROM download_native_key WHERE worker_id=$1),
 (SELECT coalesce(sum(used_roles),0) FROM download_key_binding WHERE session_id=$2),
 (SELECT generation FROM artifact_download WHERE id=$2)`, f.worker.Intent.ID, prep.SessionID, f.allocation.ID).Scan(&v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9]); e != nil {
			t.Fatal(e)
		}
		return v
	}
	// Both modes use distinct actual SQL pools. The fresh selector reaches this
	// point through its own original allocation/session/worker/preparation;
	// the negative selector keeps its uncertain first response and all charges.
	runRace := func(want int) {
		t.Helper()
		beforeRace := counts()
		a := f.authority()
		op, response := newObserve(a), newResponse()
		type operationResult struct {
			operation value.NativeOperation
			err       error
		}
		type responseResult struct {
			response artifact.DownloadResponse
			err      error
		}
		start := make(chan struct{})
		operations := make(chan operationResult, 1)
		responseResults := make(chan responseResult, 1)
		go func() {
			<-start
			o, err := nativeOwners.ClaimNativeOperation(ctx, en, a, op)
			operations <- operationResult{o, err}
		}()
		go func() {
			<-start
			r, err := second.BeginDownloadResponse(ctx, prep.SessionID, a, response)
			responseResults <- responseResult{r, err}
		}()
		close(start)
		// Join both operations before any assertion/cleanup. Deadline expiry
		// cannot masquerade as the expected uncertain-state or race exclusion.
		o, r := <-operations, <-responseResults
		winners := 0
		if o.err == nil {
			winners++
		}
		if r.err == nil {
			winners++
		}
		if !a.Valid(time.Now()) || !op.CurrentValid(time.Now()) || ctx.Err() != nil {
			t.Fatal("control admission race lost original authority before outcome assertion")
		}
		if winners != want {
			t.Fatal("status/content race admission count", winners, "expected", want,
				"observe", nativeControlRaceError(o.err), "response", nativeControlRaceError(r.err))
		}
		expected := beforeRace
		if o.err == nil {
			if !o.operation.Valid() || !o.operation.Equal(op) {
				t.Fatal("race changed original Observe identity")
			}
			expected[0]++ // Exactly one native claim; no content/key reservation.
		}
		if r.err == nil {
			if !r.response.Valid() || r.response.ID != response.ID || r.response.OwnerID != response.OwnerID || r.response.SessionID != prep.SessionID {
				t.Fatal("race changed original response identity")
			}
			expected[1]++
			expected[3] += response.Plan.Windows()
			expected[9]++ // Response generation; no bytes/keys spent before a window.
		}
		if counts() != expected {
			t.Fatal("race spent beyond the sole admitted operation or changed uncertain spend")
		}
		if o.err == nil {
			// No peer was registered for this SQL-only race. Close only this
			// exact no-I/O owner; never fabricate a remote Joined result.
			if e := nativeOwners.ReleaseNativeOperation(ctx, o.operation); e != nil {
				t.Fatal("close exact race owner", nativeControlRaceError(e))
			}
			expected[0]++
		} else if r.err == nil {
			if e := second.CloseDownloadResponse(ctx, prep.SessionID, r.response.ID, r.response.OwnerID); e != nil {
				t.Fatal("close exact race response", nativeControlRaceError(e))
			}
		}
		if counts() != expected {
			t.Fatal("race cleanup refunded or changed original spend")
		}
	}
	if f.content.mode == "native-control-admission-race" {
		original, e := f.runtime.LookupDownload(ctx, prep.SessionID, f.worker.Intent.Authority.Scope.Principal)
		if e != nil || original.Scope != f.worker.Intent.Authority.Scope || original.Generation != 1 || original.OutputLimit != 8192 || original.ReadLimit != 8<<20 {
			t.Fatal("fresh race must use its own original prepared session and unchanged fixture budgets")
		}
		initial := counts()
		if initial[0] != 2 || initial[1] != 0 || initial[2] != 0 || initial[3] != 0 || initial[7] != 0 || initial[8] != 7 || initial[9] != 1 {
			t.Fatal("fresh race inherited prior operation/response work")
		}
		runRace(1)
		t.Log("fresh independently prepared session admits exactly one concurrent Observe/response, original budgets and loser spend preserved")
		return
	}
	// A blocked native row must not outlive the original admission check or
	// consume an update after the lock is released.
	beforeLock := counts()
	tx, e := f.admin.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT worker_id FROM download_native_owner WHERE worker_id=$1 FOR UPDATE", f.worker.Intent.ID); e != nil {
		t.Fatal(e)
	}
	blockedAuthority := f.authority()
	blockedAuthority.ValidUntil = minPublicationTime(blockedAuthority.ValidUntil, time.Now().Add(600*time.Millisecond))
	blockedOperation := newObserve(blockedAuthority)
	call, cancel := context.WithDeadline(ctx, blockedAuthority.ValidUntil)
	blockedDone := make(chan error, 1)
	go func() {
		_, e := nativeOwners.ClaimNativeOperation(call, en, blockedAuthority, blockedOperation)
		blockedDone <- e
	}()
	waiting := false
	for deadline := time.Now().Add(400 * time.Millisecond); time.Now().Before(deadline); {
		if e = f.admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usename='native_owner_runtime' AND wait_event_type='Lock')").Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !waiting {
		cancel()
		<-blockedDone
		t.Fatal("native admission never waited on held row")
	}
	if e = <-blockedDone; e == nil {
		cancel()
		t.Fatal("native admission crossed original blocked interval")
	}
	cancel()
	if e = tx.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	if counts() != beforeLock {
		t.Fatal("expired held-lock admission spent native/control capacity")
	}
	a := f.authority()
	original := newObserve(a)
	held, e := nativeOwners.ClaimNativeOperation(ctx, en, a, original)
	if e != nil {
		t.Fatal("observe first", e)
	}
	before := counts()
	qualifyNativeCompletionHeld(t, ctx, f, nativeOwners, held)
	if _, e = second.BeginDownloadResponse(ctx, prep.SessionID, f.authority(), newResponse()); e == nil {
		t.Fatal("response interrupted an unjoined Observe")
	}
	if counts() != before {
		t.Fatal("losing response consumed control capacity")
	}
	// Expiry is not joined closure. The same original owner remains exclusive
	// even when a fresh caller arrives after its short lease.
	timer := time.NewTimer(time.Until(held.Until) + time.Millisecond)
	select {
	case <-ctx.Done():
		timer.Stop()
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	if _, e = responses.BeginDownloadResponse(ctx, prep.SessionID, f.authority(), newResponse()); e == nil {
		t.Fatal("expired unjoined Observe admitted content")
	}
	if counts() != before {
		t.Fatal("expired owner refunded or charged losing response")
	}
	if e = nativeOwners.ReleaseNativeOperation(ctx, held); e != nil {
		t.Fatal("positive local no-I/O Observe closure", e)
	}
	// No peer conversation was registered for the held operation above. This
	// explicit close joins that no-I/O owner; time passing supplied no closure.
	a = f.authority()
	r, e := responses.BeginDownloadResponse(ctx, prep.SessionID, a, newResponse())
	if e != nil {
		t.Fatal("response after positive Observe close", e)
	}
	before = counts()
	streaming, e := f.runtime.LookupDownload(ctx, prep.SessionID, f.worker.Intent.Authority.Scope.Principal)
	if e != nil {
		t.Fatal(e)
	}
	coldCurrent, _ := browserCurrentForWorkerTest(t, ctx, f.gate, 5*time.Second)
	if _, found, e := runtime.ReadPreparedContextDownload(ctx, coldCurrent, streaming); e == nil || found {
		t.Fatal("cold cache competed with active content")
	}
	if counts() != before {
		t.Fatal("cold cache spent or disrupted response")
	}
	a = f.authority()
	if _, e = nativeOwners.ClaimNativeOperation(ctx, en, a, newObserve(a)); e == nil {
		t.Fatal("Observe competed with active response")
	}
	if counts() != before {
		t.Fatal("losing Observe half-spent control")
	}
	if e = responses.CloseDownloadResponse(ctx, prep.SessionID, r.ID, r.OwnerID); e != nil {
		t.Fatal(e)
	}
	// Closing a response with no independently acknowledged successful window
	// leaves its first-context outcome uncertain. Neither operation may use it
	// as retry eligibility; fresh-race success is a separate prepared selector.
	runRace(0)
	t.Log("incomplete closed response denies both concurrent admissions, all prior spend retained")
}

// The unused bearer and refresh paths explicitly deny. This fixture exercises
// an actual C02 browser live reader over a synthetic original session; it must
// never mint credentials, refresh or create an owned-refresh claim from GET.
type nativeContentSessions struct{ workerBrowserSession }

// Map the one explicit HTTP-shaped fixture cookie to the existing synthetic
// session store. The production handler and C02 reader still validate it; no
// bearer token or GET refresh is introduced, and other fixture users are unchanged.
func (s nativeContentSessions) Resolve(ctx context.Context, cookie string, refresh bool) (identities.SessionView, error) {
	if cookie != strings.Repeat("s", 43) || refresh {
		return identities.SessionView{}, identity.ErrDenied
	}
	return s.workerBrowserSession.Resolve(ctx, "synthetic-worker-session", false)
}

func (nativeContentSessions) Begin(context.Context, string) (identities.LoginRedirect, error) {
	return identities.LoginRedirect{}, identity.ErrDenied
}
func (nativeContentSessions) Complete(context.Context, string, string, string) (identities.LoginResult, error) {
	return identities.LoginResult{}, identity.ErrDenied
}
func (nativeContentSessions) CSRF(context.Context, string) (string, error) {
	return "", identity.ErrDenied
}
func (nativeContentSessions) CheckCSRF(context.Context, string, string) error {
	return identity.ErrDenied
}
func (nativeContentSessions) End(context.Context, string) error { return identity.ErrDenied }
func (nativeContentSessions) BackchannelLogout(context.Context, string) error {
	return identity.ErrDenied
}

type nativeContentDeniedBearer struct{}

func (nativeContentDeniedBearer) Resolve(context.Context, string) (identity.Identity, error) {
	return identity.Identity{}, identity.ErrDenied
}
func (nativeContentDeniedBearer) ObserveCredential(context.Context, string) (identities.CredentialObservation, error) {
	return identities.CredentialObservation{}, identity.ErrDenied
}

func serveContextNativeGET(t *testing.T, ctx context.Context, f nativeExchangeFixture, runtime *evidence.ContextNativeRuntime, transfer evidence.DownloadResponseTransfer, coordinator evidence.ContextDownloadCoordinator, session artifact.DownloadSession, m artifact.NativeDownloadMetadata) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	origin := "https://" + server.Listener.Addr().String()
	operations, e := presentation.NewContextDownloadOperations(presentation.ContextDownloadOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: custodyID}, coordinator)
	if e != nil {
		t.Fatal(e)
	}
	inner, e := presentation.NewInvestigationOperations(nil, nil, operations)
	if e != nil {
		t.Fatal(e)
	}
	shared := nativeContentAuditFixture(t, ctx, f, inner)
	initial, e := f.gate.Identities.Resolve(ctx, "synthetic-reference")
	if e != nil {
		t.Fatal(e)
	}
	sessions := nativeContentSessions{workerBrowserSession{initial, session.Deadline, 5 * time.Second}}
	handler, e := browser.NewDownloadContentHandler(browser.DownloadContentConfig{PublicOrigin: origin, Issuer: initial.Principal.Issuer, MaxConcurrent: 2, Now: time.Now, NewID: custodyID}, browser.SessionHandler{Origin: origin, Issuer: initial.Principal.Issuer, Sessions: sessions}, nativeContentDeniedBearer{}, shared, runtime, transfer)
	if e != nil {
		t.Fatal("public content constructor", e)
	}
	var completed <-chan struct{}
	server.Config.Handler, completed = nativeContentJoinedHandler(handler)
	server.StartTLS()
	before := func() [3]int64 {
		var n [3]int64
		if e := f.admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM download_response WHERE session_id=$1),(SELECT updates FROM download_native_owner WHERE worker_id=$2),(SELECT used_roles FROM download_key_binding WHERE session_id=$1)", session.ID, f.worker.Intent.ID).Scan(&n[0], &n[1], &n[2]); e != nil {
			t.Fatal(e)
		}
		return n
	}
	original := before()
	request := func(condition string) *http.Response {
		t.Helper()
		r, e := http.NewRequestWithContext(ctx, http.MethodGet, origin+browser.DownloadContentPrefix+session.ID+"/content", nil)
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.AddCookie(&http.Cookie{Name: browser.SessionCookie, Value: strings.Repeat("s", 43)})
		if condition != "" {
			r.Header.Set("If-None-Match", condition)
		}
		out, e := server.Client().Do(r)
		if e != nil {
			t.Fatal("native GET", e)
		}
		return out
	}
	conditional := request(m.ETag)
	b, e := io.ReadAll(conditional.Body)
	conditional.Body.Close()
	waitContextNativeHTTP(t, ctx, completed)
	if e != nil || conditional.StatusCode != http.StatusNotModified || len(b) != 0 || before() != original {
		t.Fatal("conditional response reserved work or failed", conditional.StatusCode, len(b), e)
	}
	response := request("")
	body, e := io.ReadAll(response.Body)
	response.Body.Close()
	waitContextNativeHTTP(t, ctx, completed)
	defer clear(body)
	if e != nil || response.StatusCode != http.StatusOK || int64(len(body)) != m.Size || artifact.Digest(sha256.Sum256(body)) != m.SHA256 {
		t.Fatal("exact native HTTP bytes", response.StatusCode, len(body), e)
	}
	var rows int
	if e = f.admin.QueryRow(ctx, "SELECT count(*) FROM audit_event WHERE operation='download_artifact_content' AND kind='call'").Scan(&rows); e != nil || rows != 2 {
		t.Fatal("conditional/content audit rows", rows, e)
	}
	t.Logf("actual authenticated HTTPS native GET bytes=%d; conditional request disclosed no bytes/reservation and both GETs wrote an audit row", len(body))
}
func nativeContentAuditFixture(t *testing.T, ctx context.Context, f nativeExchangeFixture, inner *presentation.InvestigationOperations) *presentation.AuditedOperations {
	t.Helper()
	return nativeContentAuditFixtureOwned(t, t, ctx, f, inner)
}

func nativeContentAuditFixtureOwned(t, owner *testing.T, ctx context.Context, f nativeExchangeFixture, inner *presentation.InvestigationOperations) *presentation.AuditedOperations {
	return nativeOperationAuditServices(t, owner, ctx, f.allocation.RootID, f.worker.Binding.InstallationID, f.published.Expectation.Registration.StoreID, f.admin, f.poolFor, f.store, f.keys, inner, 8)
}

func nativeOperationAuditServices(t, owner *testing.T, ctx context.Context, root, installation, storeID string, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, inner *presentation.InvestigationOperations, normalRecords int64, diagnostics ...*publicJourneyDiagnostics) *presentation.AuditedOperations {
	t.Helper()
	if len(diagnostics) > 1 || len(diagnostics) == 1 && diagnostics[0] == nil {
		t.Fatal("invalid fixed journey diagnostic")
	}
	recorder, e := postgres.NewAuditEvents(admin)
	if e != nil {
		t.Fatal(e)
	}
	mac, e := auditapp.NewOperationMAC("input-v1", bytes.Repeat([]byte{31}, 32), "accounts-v1", bytes.Repeat([]byte{32}, 32))
	if e != nil {
		t.Fatal(e)
	}
	owner.Cleanup(mac.Close)
	out, e := presentation.NewAuditedOperations(presentation.AuditedOperationsConfig{RootID: root, Now: time.Now, NewID: custodyID}, inner, recorder, mac)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
