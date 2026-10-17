package native_test

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	native "asservat.local/asservat/internal/transport/native"
	"context"
	"testing"
	"time"
)

// Real h2/mTLS carries the last marker successfully to the worker's transport,
// then the test drops it before the worker consumes it. A positive hub result
// is not a remote Joined result and must never authorize a refund/replacement.
func TestNativePositiveContentAcknowledgementDoesNotProveRemoteJoined(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	source := flowSourceValue(t)
	now := time.Now()
	target := value.WorkerCredentialTarget{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, PodUID: nativeID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	reader := &flowSource{}
	result, err := evidence.NewRegionalContextResult(ctx, target, reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { result.Close(); _ = result.Wait(context.Background()) }()
	prep, client, _ := flowOperation(t, ctx, source, value.NativePrepare, 1, artifact.DownloadDeliveryLease{})
	done := flowRunWorker(t, ctx, client, target, result)
	m, err := prep.Prepared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = prep.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	prep.Close()
	now = time.Now()
	a := artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: nativeID, ArtifactID: nativeID, CaptureID: nativeID, ClusterID: nativeID, NamespaceUID: nativeID, WorkloadUID: nativeID, PodUID: nativeID, Version: evidence.ContextCopiesDigest(source.Copies), Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}, PermissionEpoch: nativeID, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{3}}, CheckedAt: now, ValidUntil: now.Add(4 * time.Second), AccessUntil: source.Expectation.Registration.ExpiresAt, DeleteBy: source.Expectation.Registration.DeleteBy}
	lease := artifact.DownloadDeliveryLease{ResponseID: nativeID, WindowID: nativeID, OwnerID: nativeID, Generation: 1, Sequence: 1, Length: m.Size, StartedAt: now, Until: a.ValidUntil, Authority: a}
	response, client, op := flowOperation(t, ctx, source, value.NativeResponse, 2, lease)
	stream, err := client.Open(ctx, workerHello())
	if err != nil {
		t.Fatal(err)
	}
	lossy := &losePreparedFinal{NativeStream: stream}
	type outcome struct {
		state contracts.NativeConversationResult
		err   error
	}
	worker := make(chan outcome, 1)
	go func() {
		state, err := native.RunWorkerConversation(ctx, lossy, workerHello(), target, artifact.Digest{1}, result)
		worker <- outcome{state, err}
	}()
	chunk, err := response.ReadChunk(ctx, lease, 0, m.Size)
	if err != nil {
		t.Fatal(err)
	}
	if string(chunk.Bytes) != string(flowBody) {
		t.Fatal("native source changed")
	}
	clear(chunk.Bytes)
	if err = response.AcknowledgeNativeChunk(ctx, lease, 0, m.Size); err != nil {
		t.Fatal("hub did not positively acknowledge content", err)
	}
	response.Close()
	select {
	case out := <-worker:
		if out.err == nil || out.state.State != contracts.NativeUncertain || out.state.Reference != (contracts.NativeReference{InstallationID: op.Reference.InstallationID, SessionID: op.Reference.SessionID, WorkerID: op.Reference.WorkerID, OperationID: op.Reference.OperationID, Fence: op.Reference.Fence}) || !lossy.lost.Load() {
			t.Fatal("local close fabricated remote Joined", out)
		}
	case <-ctx.Done():
		t.Fatal("uncertain worker did not join")
	}
	if reader.reads.Load() != 2 {
		t.Fatal("uncertainty repeated decrypt", reader.reads.Load())
	}
}
