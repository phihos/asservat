package integration

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// This exercises the existing SQL owner-renewal transition after actual
// metadata preparation. Human/bootstrap/Pod-proof inputs remain the parent
// fixture's explicit synthetic facts; the SQL, encrypted audit and registered
// worker certificate are real. It does not claim a paced end-to-end transfer.
func qualifyNativeOwnerRenewal(t *testing.T, ctx context.Context, f nativeExchangeFixture, owners *postgres.NativeOwners, enrollment value.WorkerEnrollment, peer value.KeyPeer, session artifact.DownloadSession, metadata artifact.NativeDownloadMetadata, objects *objectstore.DownloadWindowAuditObjects) {
	t.Helper()
	a := f.authority()
	responseID, ownerID, windowID := custodyID(), custodyID(), custodyID()
	plan := artifact.DownloadResponsePlan{Version: artifact.DownloadResponseVersion, Selection: artifact.DownloadSelection{Length: metadata.Size}, WholeFile: true, WindowReadLimit: evidence.NativeWindowReadWork(f.published.Expectation.Type())}
	response, err := f.runtime.BeginDownloadResponse(ctx, session.ID, a, artifact.DownloadResponse{ID: responseID, SessionID: session.ID, OwnerID: ownerID, Plan: plan, Until: session.Deadline})
	if err != nil {
		t.Fatal("renewal response", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = f.runtime.CloseDownloadResponse(cleanup, session.ID, responseID, ownerID)
	}()
	intent, err := f.runtime.BeginDownloadWindow(ctx, session.ID, responseID, ownerID, windowID, f.authority())
	if err != nil {
		t.Fatal("renewal window", err)
	}
	receipt, err := objects.CreateDownloadWindowIntent(ctx, intent)
	if err != nil {
		t.Fatal("renewal intent audit", err)
	}
	if err := f.audit.AcknowledgeDownloadWindowIntent(ctx, intent, receipt); err != nil {
		t.Fatal("renewal intent acknowledgement", err)
	}
	a = f.authority()
	first, err := f.runtime.LeaseDownloadResponse(ctx, session.ID, responseID, ownerID, windowID, a)
	if err != nil {
		t.Fatal("first delivery lease", err)
	}
	fence, err := owners.NextNativeFence(ctx, enrollment.Worker.Intent.ID)
	if err != nil {
		t.Fatal("renewal native fence", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := minPublicationTime(now.Add(value.NativeConversationWindow(value.NativeResponse)), minPublicationTime(a.AccessUntil, minPublicationTime(session.Deadline, enrollment.Worker.Intent.RunUntil)))
	o := value.NativeOperation{Reference: value.NativeReference{InstallationID: enrollment.Worker.Binding.InstallationID, SessionID: session.ID, WorkerID: enrollment.Worker.Intent.ID, OperationID: custodyID(), Fence: fence}, Kind: value.NativeResponse, HubPodUID: custodyID(), HubProcessEpoch: custodyID(), WorkerPodUID: peer.PeerID, WorkerPublicKey: enrollment.PublicKeyDigest, SourceVersion: session.Scope.Version, ParentID: responseID, Generation: response.Generation, StartedAt: now, Until: until, Path: a.Environment.Path, Processing: a.Environment.Processing}
	if _, err := owners.ClaimNativeOperation(ctx, enrollment, a, o); err != nil {
		t.Fatal("initial native response", err)
	}
	if _, err := owners.RenewNativeOperation(ctx, o.Reference, f.authority(), peer); err == nil {
		t.Fatal("same response lease sequence renewed native authority")
	}
	// Cross the real first SQL/source observation boundary. No data may use
	// that expired observation; a separately admitted newer lease is required.
	wait := time.NewTimer(time.Until(first.Until.Add(25 * time.Millisecond)))
	defer wait.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-wait.C:
	}
	if _, err := owners.ObserveNativeOperation(ctx, o.Reference, peer); err == nil {
		t.Fatal("expired original observation remained usable")
	}
	a = f.authority()
	second, err := f.runtime.LeaseDownloadResponse(ctx, session.ID, responseID, ownerID, windowID, a)
	if err != nil || second.Sequence <= first.Sequence {
		t.Fatal("new delivery lease", err)
	}
	foreign := peer
	foreign.PeerID = custodyID()
	if _, err := owners.RenewNativeOperation(ctx, o.Reference, a, foreign); err == nil {
		t.Fatal("replacement worker renewed the original operation")
	}
	wrong := a
	wrong.Scope.Principal.Subject = "another-synthetic-user"
	if _, err := owners.RenewNativeOperation(ctx, o.Reference, wrong, peer); err == nil {
		t.Fatal("another caller renewed the original operation")
	}
	changed := a
	changed.Environment.Processing.StateDigest[0] ^= 1
	if _, err := owners.RenewNativeOperation(ctx, o.Reference, changed, peer); err == nil {
		t.Fatal("changed processing state renewed the original operation")
	}
	l, err := owners.RenewNativeOperation(ctx, o.Reference, a, peer)
	if err != nil || !l.Valid(time.Now()) || !l.Operation.Equal(o) || l.Sequence != second.Sequence || l.Until.After(o.Until) {
		t.Fatal("fresh native renewal changed the original operation or deadline", err)
	}
	observed, err := owners.ObserveNativeOperation(ctx, o.Reference, peer)
	if err != nil || observed.Sequence != second.Sequence || !observed.Operation.Equal(o) {
		t.Fatal("renewed native observation", err)
	}
	if _, err := owners.RenewNativeOperation(ctx, o.Reference, a, peer); err == nil {
		t.Fatal("same sequence replay renewed twice")
	}
	if err := owners.CompleteNativeOperation(ctx, observed); err != nil {
		t.Fatal("close renewed native owner", err)
	}
	a = f.authority()
	if _, err := f.runtime.LeaseDownloadResponse(ctx, session.ID, responseID, ownerID, windowID, a); err != nil {
		t.Fatal("third delivery lease", err)
	}
	if _, err := owners.RenewNativeOperation(ctx, o.Reference, a, peer); err == nil {
		t.Fatal("closed native owner was revived")
	}
}
