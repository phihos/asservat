package native

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Synthetic authority/source only. None of these values grants production authority.
const admissionID = "11111111-1111-4111-8111-111111111111"

func admissionSource(t *testing.T) evidence.NativeContextSource {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := admissionID
	e := artifact.ContextExpectation{ExecutionClass: artifact.ContextAPIExecution, Registration: artifact.Registration{Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, StoreID: id, AllocationID: id, PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: now, WriteUntil: now.Add(30 * time.Second), ExpiresAt: now.Add(time.Minute), DeleteBy: now.Add(90 * time.Second)}, CaseID: id, OccurrenceID: id, PodUID: id, Namespace: "app", NamespaceUID: id, WorkloadUID: id, CollectorVersion: "synthetic", CollectorImageDigest: artifact.Digest{1}, RecipeDigest: artifact.Digest{2}, PlanDigest: artifact.Digest{3}, CaptureUID: id, ActionID: "pod-status", DataClass: "metadata", PurposeRef: "synthetic", Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://id.invalid", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: id, AssignmentID: id, BasisDigest: artifact.Digest{4}}}, RequestedAgeSeconds: 60, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 30, RetentionRules: []artifact.RetentionRule{{UID: id, Generation: 1, Digest: artifact.Digest{5}}}, TriggeredAt: now}
	s := evidence.NativeContextSource{Expectation: e}
	for i := range s.Copies {
		s.Copies[i] = artifact.CopyReceipt{ETag: "synthetic", Bytes: 128, SHA256: artifact.Digest{byte(i + 1)}}
	}
	if !s.Valid(evidence.ContextCopiesDigest(s.Copies)) {
		t.Fatal("invalid source")
	}
	return s
}

func admissionProcessingPath(o value.NativeOperation) value.NativeOperation {
	id := o.Reference.InstallationID
	rev := identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{7}}
	o.Path = artifact.DownloadPath{ID: id, TargetClusterID: id, StoreID: id, StorageRegion: "fixture", AcquisitionClusterID: id, AcquisitionRegion: "fixture", ConnectorClusterID: id, ConnectorRegion: "fixture", HubClusterID: id, HubRegion: "fixture", WorkerConfiguration: rev, HubConfiguration: rev}
	o.Processing = artifact.DownloadProcessingProof{RootID: id, Epoch: id, CaptureID: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, Sequence: 1, StateDigest: artifact.Digest{8}, ObservedAt: o.StartedAt, ValidUntil: o.Until}
	return o
}

func admissionFixture(t *testing.T) (value.NativeLease, contracts.NativeCommand, evidence.NativeContextSource, contracts.NativeHello) {
	t.Helper()
	source := admissionSource(t)
	n := time.Now()
	operation := value.NativeOperation{Reference: value.NativeReference{InstallationID: admissionID, SessionID: admissionID, WorkerID: admissionID, OperationID: admissionID, Fence: 1}, Kind: value.NativePrepare, HubPodUID: admissionID, HubProcessEpoch: admissionID, WorkerPodUID: admissionID, WorkerPublicKey: artifact.Digest{1}, SourceVersion: evidence.ContextCopiesDigest(source.Copies), ParentID: admissionID, Generation: 1, StartedAt: n, Until: n.Add(4 * time.Second)}
	operation = admissionProcessingPath(operation)
	lease := value.NativeLease{Operation: operation, Certificate: artifact.Digest{3}, Sequence: 1, ObservedAt: n, Until: operation.Until}
	wire, _ := json.Marshal(operation)
	encoded, _ := json.Marshal(source)
	command := contracts.NativeCommand{Format: contracts.NativeExchangeFormat, Reference: nativeReference(operation), Kind: string(operation.Kind), Source: encoded, Operation: wire, ParentID: operation.ParentID, Generation: 1, LeaseSequence: 1, Until: operation.Until.UTC().Format(time.RFC3339Nano)}
	hello := contracts.NativeHello{Format: contracts.NativeExchangeFormat, Reference: command.Reference, Nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	if !contracts.ValidWorkerNonce(hello.Nonce) || !lease.Valid(n) || !operation.CurrentValid(n) {
		t.Fatal("invalid synthetic fixture")
	}
	return lease, command, source, hello
}
func admissionGate(t *testing.T, lease value.NativeLease) *evidence.NativeFrameGate {
	t.Helper()
	gate, err := evidence.NewNativeFrameGate(context.Background(), func(context.Context) (value.NativeLease, error) { return lease, nil }, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		gate.Close()
		if err := gate.Wait(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return gate
}
func admissionComplete(context.Context, value.NativeLease) error { return nil }

func TestNativePrivateAdmissionRejectsChangedProof(t *testing.T) {
	for _, entry := range []string{"constructor", "attach"} {
		for _, mode := range []string{"missing", "wrong-gate", "wrong-operation", "wrong-certificate", "wrong-sequence", "expired", "cancelled", "closed", "used"} {
			t.Run(entry+"/"+mode, func(t *testing.T) {
				lease, command, source, hello := admissionFixture(t)
				gate := admissionGate(t, lease)
				operation, err := NewHubOperation(gate, command, source, admissionComplete)
				if err != nil {
					t.Fatal(err)
				}
				defer operation.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				checked, err := checkNativeAdmission(ctx, gate)
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "missing":
					checked = nil
				case "wrong-gate":
					checked.gate = admissionGate(t, lease)
				case "wrong-operation":
					checked.lease.Operation.Reference.Fence++
				case "wrong-certificate":
					checked.lease.Certificate[0]++
				case "wrong-sequence":
					checked.lease.Sequence++
				case "expired":
					checked.lease.Until = time.Now().Add(-time.Nanosecond)
				case "cancelled":
					cancel()
				case "closed":
					gate.Close()
				case "used":
					if _, err = checked.take(gate); err != nil {
						t.Fatal(err)
					}
				}
				if entry == "constructor" {
					got, err := newHubOperationChecked(gate, checked, command, source, artifact.DownloadDeliveryLease{}, admissionComplete)
					if err == nil || got != nil {
						if got != nil {
							got.Close()
						}
						t.Fatal("invalid private constructor proof accepted")
					}
				} else {
					got, err := operation.attachChecked(checked, hello)
					if err == nil || got != nil || operation.reserved {
						t.Fatal("invalid private attachment proof accepted")
					}
				}
			})
		}
	}
}

func TestNativePrivateAdmissionRetainsCallerCancellationAcrossLock(t *testing.T) {
	lease, command, source, hello := admissionFixture(t)
	gate := admissionGate(t, lease)
	operation, err := NewHubOperation(gate, command, source, admissionComplete)
	if err != nil {
		t.Fatal(err)
	}
	defer operation.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	checked, err := checkNativeAdmission(ctx, gate)
	if err != nil {
		t.Fatal(err)
	}
	operation.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := operation.attachChecked(checked, hello); done <- err }()
	<-ctx.Done()
	operation.mu.Unlock()
	if err := <-done; err == nil || operation.reserved {
		t.Fatal("expired original caller became attached after lock")
	}
}

func TestNativePrivateAdmissionCannotBroadenKnownShortening(t *testing.T) {
	lease, command, source, hello := admissionFixture(t)
	var short atomic.Bool
	cutoff := time.Now().Add(120 * time.Millisecond)
	gate, err := evidence.NewNativeFrameGate(context.Background(), func(context.Context) (value.NativeLease, error) {
		result := lease
		if short.Load() {
			result.Until = cutoff
		}
		return result, nil
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { gate.Close(); gate.Wait(context.Background()) }()
	operation, err := NewHubOperation(gate, command, source, admissionComplete)
	if err != nil {
		t.Fatal(err)
	}
	defer operation.Close()
	construct, err := checkNativeAdmission(context.Background(), gate)
	if err != nil {
		t.Fatal(err)
	}
	attach, err := checkNativeAdmission(context.Background(), gate)
	if err != nil {
		t.Fatal(err)
	}
	short.Store(true)
	if _, err = gate.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, err := newHubOperationChecked(gate, construct, command, source, artifact.DownloadDeliveryLease{}, admissionComplete); err == nil || got != nil {
		if got != nil {
			got.Close()
		}
		t.Fatal("old command deadline ignored known shortening")
	}
	if restricted, err := attach.restrict(gate); err != nil || !restricted.Until.Equal(cutoff) {
		t.Fatal("private proof broadened known shortening", err)
	}
	<-time.After(time.Until(cutoff))
	if got, err := operation.attachChecked(attach, hello); err == nil || got != nil || operation.reserved {
		t.Fatal("expired known shortening became attached")
	}
}

// A Context may have a noncomparable concrete type. The proof retains its call;
// it never depends on comparing arbitrary Context interface values.
type admissionContext struct {
	context.Context
	label []byte
}

func TestNativePrivateAdmissionUsesOriginalNoncomparableContext(t *testing.T) {
	lease, _, _, _ := admissionFixture(t)
	gate := admissionGate(t, lease)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := admissionContext{Context: parent, label: []byte{1}}
	checked, err := checkNativeAdmission(original, gate)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err = checked.take(gate); err == nil {
		t.Fatal("original context cancellation was lost")
	}
}

func TestNativePublicAdmissionAlwaysPerformsCurrentCheck(t *testing.T) {
	for _, entry := range []string{"constructor", "response-constructor", "attach"} {
		t.Run(entry, func(t *testing.T) {
			lease, command, source, hello := admissionFixture(t)
			var deny atomic.Bool
			var calls atomic.Int32
			gate, err := evidence.NewNativeFrameGate(context.Background(), func(context.Context) (value.NativeLease, error) {
				calls.Add(1)
				if deny.Load() {
					return value.NativeLease{}, artifact.ErrDownloadUnavailable
				}
				return lease, nil
			}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { gate.Close(); gate.Wait(context.Background()) }()
			var operation *HubOperation
			if entry == "attach" {
				operation, err = NewHubOperation(gate, command, source, admissionComplete)
				if err != nil {
					t.Fatal(err)
				}
				defer operation.Close()
			}
			now := time.Now()
			authority := artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: admissionID, ArtifactID: admissionID, CaptureID: admissionID, ClusterID: admissionID, NamespaceUID: admissionID, WorkloadUID: admissionID, PodUID: admissionID, Version: lease.Operation.SourceVersion, Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}, PermissionEpoch: admissionID, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{3}}, CheckedAt: now, ValidUntil: now.Add(time.Second), AccessUntil: now.Add(time.Minute), DeleteBy: now.Add(2 * time.Minute)}
			delivery := artifact.DownloadDeliveryLease{ResponseID: admissionID, WindowID: admissionID, OwnerID: admissionID, Generation: 1, Sequence: 1, Length: 1, StartedAt: now, Until: authority.ValidUntil, Authority: authority}
			if !delivery.Valid(now) {
				t.Fatal("invalid synthetic delivery")
			}
			before := calls.Load()
			deny.Store(true)
			switch entry {
			case "constructor":
				operation, err = NewHubOperation(gate, command, source, admissionComplete)
			case "response-constructor":
				command.Kind = string(value.NativeResponse)
				operation, err = NewHubResponseOperation(gate, command, source, delivery, admissionComplete)
			case "attach":
				_, err = operation.Attach(context.Background(), hello)
			}
			if err == nil || calls.Load() != before+1 {
				t.Fatal("public admission skipped current authority", calls.Load()-before, err)
			}
		})
	}
}
