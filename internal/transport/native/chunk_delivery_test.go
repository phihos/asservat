package native

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func chunkDeliveryFixture(t *testing.T) (*HubOperation, artifact.DownloadDeliveryLease, *atomic.Int64, *atomic.Bool, *atomic.Int64) {
	t.Helper()
	lease, command, source, _ := admissionFixture(t)
	lease.Operation.Kind = value.NativeResponse
	command.Kind = string(value.NativeResponse)
	command.Operation, _ = json.Marshal(lease.Operation)
	command.Reference = nativeReference(lease.Operation)
	command.WindowID, command.Length = admissionID, 1
	var sequence, actions atomic.Int64
	var deny atomic.Bool
	sequence.Store(1)
	gate, err := evidence.NewNativeFrameGate(t.Context(), func(context.Context) (value.NativeLease, error) {
		if deny.Load() {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		current := lease
		current.Sequence = sequence.Load()
		return current, nil
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	authority := artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: admissionID, ArtifactID: admissionID, CaptureID: admissionID, ClusterID: admissionID, NamespaceUID: admissionID, WorkloadUID: admissionID, PodUID: admissionID, Version: lease.Operation.SourceVersion, Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}, PermissionEpoch: admissionID, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{3}}, CheckedAt: now, ValidUntil: lease.Until, AccessUntil: now.Add(time.Minute), DeleteBy: now.Add(2 * time.Minute)}
	delivery := artifact.DownloadDeliveryLease{ResponseID: admissionID, WindowID: admissionID, OwnerID: admissionID, Generation: 1, Sequence: 1, Length: 1, StartedAt: now, Until: authority.ValidUntil, Authority: authority}
	operation, err := NewHubResponseOperation(gate, command, source, delivery, admissionComplete)
	if err != nil {
		gate.Close()
		t.Fatal(err)
	}
	operation.body = make(chan []byte, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		for {
			select {
			case <-operation.Context().Done():
				return
			case action := <-operation.action:
				actions.Add(1)
				action.done <- nil
			}
		}
	}()
	t.Cleanup(func() {
		operation.Close()
		gate.Close()
		gate.Wait(context.Background())
		<-joined
	})
	return operation, delivery, &sequence, &deny, &actions
}

func TestHubReadFailureDoesNotAcceptUnconfirmedDelivery(t *testing.T) {
	for _, mode := range []string{"mismatched-sequence", "gate-denied"} {
		t.Run(mode, func(t *testing.T) {
			operation, original, _, deny, actions := chunkDeliveryFixture(t)
			future := original
			future.Sequence++
			future.Authority.DecisionDigest[0]++
			deny.Store(mode == "gate-denied")
			body := []byte{'x'}
			operation.body <- body
			if _, err := operation.ReadChunk(t.Context(), future, 0, 1); err == nil {
				t.Fatal("unconfirmed caller lease returned bytes")
			}
			if operation.delivery != original {
				t.Error("failed read ratcheted accepted delivery authority")
			}
			if body[0] != 0 {
				t.Error("failed read retained plaintext")
			}
			if operation.Context().Err() == nil {
				t.Error("failed read retained live operation")
			}
			if err := operation.AcknowledgeNativeChunk(t.Context(), original, 0, 1); err == nil || actions.Load() != 0 {
				t.Fatal("failed read acknowledged undisclosed bytes", err, actions.Load())
			}
			if operation.pending != 1 || operation.next != 0 {
				t.Fatal("failed read/ACK changed pending accounting", operation.pending, operation.next)
			}
		})
	}
}

func TestHubAcknowledgementRequiresSuccessfullyAcceptedSequence(t *testing.T) {
	operation, original, sequence, _, actions := chunkDeliveryFixture(t)
	confirmed := original
	confirmed.Sequence++
	sequence.Store(confirmed.Sequence)
	operation.body <- []byte{'x'}
	chunk, err := operation.ReadChunk(t.Context(), confirmed, 0, 1)
	defer clear(chunk.Bytes)
	if err != nil || string(chunk.Bytes) != "x" || operation.delivery != confirmed {
		t.Fatal("confirmed native sequence not retained", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := operation.AcknowledgeNativeChunk(canceled, confirmed, 0, 1); err == nil || operation.pending != 1 || operation.next != 0 || actions.Load() != 0 {
		t.Fatal("canceled ACK consumed pending bytes", err)
	}
	future := confirmed
	future.Sequence++
	if err := operation.AcknowledgeNativeChunk(t.Context(), future, 0, 1); err == nil {
		t.Error("unverified future sequence acknowledged pending bytes")
	}
	if actions.Load() != 0 || operation.pending != 1 || operation.next != 0 {
		t.Fatal("rejected ACK consumed pending state", actions.Load(), operation.pending, operation.next)
	}
	if err := operation.AcknowledgeNativeChunk(t.Context(), confirmed, 0, 1); err != nil || actions.Load() != 1 {
		t.Fatal("exact confirmed sequence could not acknowledge", err, actions.Load())
	}
}
