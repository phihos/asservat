package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual old/new SQL adapters share one existing fixture database and narrow
// owner role. The parent fixture alone owns setup/audit/admin credentials;
// protected initial roots, human identity and Pod proof remain synthetic.
func qualifyNativeMixedOwners(t *testing.T, ctx context.Context, f nativeExchangeFixture, owners *postgres.NativeOwners, pool *pgxpool.Pool, enrollment value.WorkerEnrollment, peer value.KeyPeer, session artifact.DownloadSession, metadata artifact.NativeDownloadMetadata, objects *objectstore.DownloadWindowAuditObjects) {
	t.Helper()
	manifest := nativeVersionManifestFor(t)
	responseID, ownerID, windowID := custodyID(), custodyID(), custodyID()
	plan := artifact.DownloadResponsePlan{Version: artifact.DownloadResponseVersion, Selection: artifact.DownloadSelection{Length: metadata.Size}, WholeFile: true, WindowReadLimit: evidence.NativeWindowReadWork(f.published.Expectation.Type())}
	response, err := f.runtime.BeginDownloadResponse(ctx, session.ID, f.authority(), artifact.DownloadResponse{ID: responseID, SessionID: session.ID, OwnerID: ownerID, Plan: plan, Until: session.Deadline})
	if err != nil {
		t.Fatal("mixed response", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = f.runtime.CloseDownloadResponse(cleanup, session.ID, responseID, ownerID)
	}()
	intent, err := f.runtime.BeginDownloadWindow(ctx, session.ID, responseID, ownerID, windowID, f.authority())
	if err != nil {
		t.Fatal("mixed window", err)
	}
	receipt, err := objects.CreateDownloadWindowIntent(ctx, intent)
	if err != nil {
		t.Fatal("mixed audit", err)
	}
	if err = f.audit.AcknowledgeDownloadWindowIntent(ctx, intent, receipt); err != nil {
		t.Fatal("mixed audit acknowledgement", err)
	}
	nextDelivery := func() artifact.DownloadDeliveryLease {
		t.Helper()
		lease, err := f.runtime.LeaseDownloadResponse(ctx, session.ID, responseID, ownerID, windowID, f.authority())
		if err != nil {
			t.Fatal("mixed current delivery", err)
		}
		return lease
	}
	nextDelivery()
	snapshot := func() string {
		t.Helper()
		var encoded string
		const query = `SELECT jsonb_build_array(s.id,s.allocation_id,s.deadline,s.generation,s.charged_output,s.charged_read,s.requests,s.emitted_bytes,c.reserved_responses,c.reserved_windows,c.reserved_audit_bytes,b.charged_rows,b.charged_keys,r.id,r.owner_id,r.generation,r.until_at,r.active_window,r.window_count,r.completed_windows,r.emitted_bytes,w.ordinal,w.intent_json,w.outcome_json,(SELECT coalesce(sum(used_roles),0) FROM download_key_binding WHERE session_id=s.id),(SELECT count(*) FROM download_native_key WHERE worker_id=b.worker_id),(SELECT coalesce(sum(used_roles),0) FROM download_native_key WHERE worker_id=b.worker_id))::text
 FROM artifact_download s JOIN download_control_allocation c ON c.id=s.allocation_id JOIN download_response r ON r.session_id=s.id JOIN download_window w ON w.response_id=r.id JOIN (SELECT n.worker_id,x.charged_rows,x.charged_keys FROM download_native_owner n JOIN download_native_backing x ON x.allocation_id=n.allocation_id WHERE n.worker_id=$2) b ON true WHERE s.id=$1 AND r.id=$3 AND w.id=$4`
		if err := f.admin.QueryRow(ctx, query, session.ID, enrollment.Worker.Intent.ID, responseID, windowID).Scan(&encoded); err != nil {
			t.Fatal("mixed accounting snapshot", err)
		}
		return encoded
	}
	initial := snapshot()
	unchanged := func() {
		t.Helper()
		if snapshot() != initial {
			t.Fatal("mixed-version adapter changed reservations, spend, source window or original deadlines")
		}
	}
	claimAuthority := map[string]artifact.DownloadAuthority{}
	makeOperation := func(a artifact.DownloadAuthority, duration time.Duration) value.NativeOperation {
		t.Helper()
		fence, err := owners.NextNativeFence(ctx, enrollment.Worker.Intent.ID)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		end := minPublicationTime(now.Add(duration), minPublicationTime(a.AccessUntil, minPublicationTime(session.Deadline, enrollment.Worker.Intent.RunUntil)))
		operation := value.NativeOperation{Reference: value.NativeReference{InstallationID: enrollment.Worker.Binding.InstallationID, SessionID: session.ID, WorkerID: enrollment.Worker.Intent.ID, OperationID: custodyID(), Fence: fence}, Kind: value.NativeResponse, HubPodUID: custodyID(), HubProcessEpoch: custodyID(), WorkerPodUID: peer.PeerID, WorkerPublicKey: enrollment.PublicKeyDigest, SourceVersion: session.Scope.Version, ParentID: responseID, Generation: response.Generation, StartedAt: now, Until: end, Path: a.Environment.Path, Processing: a.Environment.Processing}
		claimAuthority[operation.Reference.OperationID] = a
		return operation
	}
	input := func(action string, operation value.NativeOperation) nativeVersionInput {
		authority := f.authority()
		if action == "claim" {
			authority = claimAuthority[operation.Reference.OperationID]
		}
		return nativeVersionInput{Action: action, Postgres: pool.Config().ConnConfig.ConnString(), Root: f.allocation.RootID, Installation: enrollment.Worker.Binding.InstallationID, TopologySource: f.topologySource, Profile: enrollment.Worker.Intent.Profile, Enrollment: enrollment, Authority: authority, Operation: operation, Peer: peer}
	}
	accepted := func(version, action string, operation value.NativeOperation) nativeVersionOutput {
		t.Helper()
		out := runNativeVersion(t, ctx, manifest.Binaries[version], input(action, operation))
		raw, _ := json.Marshal(operation)
		hash := sha256.Sum256(raw)
		if !out.Accepted || out.Stage != action || out.OperationSHA256 != hex.EncodeToString(hash[:]) || out.HasRenewer != (version == "new") {
			t.Fatal("actual version adapter did not preserve exact operation", version, action, out.Stage, out.ErrorClass)
		}
		unchanged()
		return out
	}
	denied := func(version, action string, operation value.NativeOperation) {
		t.Helper()
		out := runNativeVersion(t, ctx, manifest.Binaries[version], input(action, operation))
		if out.Accepted || out.Stage != action || out.ErrorClass != "unavailable" {
			t.Fatal("actual old/new adapter refusal occurred outside operation", version, action, out.Stage, out.ErrorClass)
		}
		unchanged()
	}
	waitUntil := func(until time.Time) {
		t.Helper()
		timer := time.NewTimer(time.Until(until.Add(25 * time.Millisecond)))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal("mixed fixture original parent ended")
		case <-timer.C:
		}
	}
	closeOwner := func(operation value.NativeOperation) {
		t.Helper()
		out := runNativeVersion(t, ctx, manifest.Binaries["old"], input("release", operation))
		if out.Stage != "release" {
			t.Fatal("old cleanup did not reach actual adapter", out.Stage)
		}
		readClosed := func() bool {
			t.Helper()
			var closed bool
			if err := f.admin.QueryRow(ctx, "SELECT closed FROM download_native_owner WHERE worker_id=$1 AND operation_id=$2 AND fence=$3", operation.Reference.WorkerID, operation.Reference.OperationID, operation.Reference.Fence).Scan(&closed); err != nil {
				t.Fatal("exact owner cleanup read-back", err)
			}
			return closed
		}
		closed := readClosed()
		t.Logf("observed old historical close accepted=%t class=%s persistedClosed=%t", out.Accepted, out.ErrorClass, closed)
		unchanged()
		// Record old rejection rather than changing the operation to make it
		// accepted. Only fixture teardown may use the new actual restrictive
		// close, under the same exact original identity and bounded parent.
		if !closed {
			accepted("new", "release", operation)
			closed = readClosed()
			t.Log("fixture required new-side bounded cleanup; old cleanup is not qualified")
		}
		if !closed {
			t.Fatal("original owner never reached restrictive closure")
		}
	}
	// This row is actually created by old ClaimNativeOperation, not a new
	// command labeled old. New observation accepts it only inside its old end.
	oldOperation := makeOperation(f.authority(), 3*time.Second)
	accepted("old", "claim", oldOperation)
	accepted("new", "observe", oldOperation)
	waitUntil(oldOperation.Until)
	denied("new", "observe", oldOperation)
	nextDelivery()
	denied("new", "renew", oldOperation)
	closeOwner(oldOperation)
	// A new long owner remains original despite fresh short SQL leases. Old
	// adapter refusal is immediate; a common schema floor does not imply support.
	delivery := nextDelivery()
	long := makeOperation(f.authority(), 20*time.Second)
	accepted("new", "claim", long)
	denied("old", "observe", long)
	accepted("new", "observe", long)
	missing := runNativeVersion(t, ctx, manifest.Binaries["old"], input("renew", long))
	if missing.Accepted || missing.Stage != "renew-unimplemented" || missing.HasRenewer {
		t.Fatal("old binary fabricated new renewal capability")
	}
	unchanged()
	waitUntil(delivery.Until)
	denied("new", "observe", long)
	renewedDelivery := nextDelivery()
	renewed := accepted("new", "renew", long)
	if renewed.Sequence != renewedDelivery.Sequence || renewed.Sequence <= delivery.Sequence || renewed.Until.After(long.Until) {
		t.Fatal("new lease changed original operation or failed sequence advance")
	}
	denied("old", "observe", long)
	accepted("new", "observe", long)
	closeOwner(long)
	nextDelivery()
	denied("new", "renew", long)
	t.Log("actual old-created short owner/new observation and expiry; new long owner/old refusal; monotonic renewal, observed version-specific cleanup, no refill; original window stays conservatively charged")
}
