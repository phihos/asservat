package integration

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
)

// Real native-owner SQL locks consume an actual encrypted metadata pair. The
// zero-byte metadata outcome and the original protected capacity values remain
// explicit fixture facts, not evidence decoding or production qualification.
func qualifyNativeParentHistoricalVersions(t *testing.T, ctx context.Context, f nativeExchangeFixture, enrollment value.WorkerEnrollment, refresh func() error) {
	t.Helper()
	ownerPool := f.poolFor("native_owner_runtime", "synthetic-native-owner")
	defer ownerPool.Close()
	historyPool := f.poolFor("native_history_runtime", "synthetic-native-history")
	defer historyPool.Close()
	root := f.allocation.RootID
	owners, err := postgres.NewNativeOwners(ctx, ownerPool, root, f.worker.Intent.Profile, f.guards)
	if err != nil {
		t.Fatal(err)
	}
	history, err := postgres.NewNativeHistory(ctx, historyPool, root)
	if err != nil {
		t.Fatal(err)
	}
	backing := value.NativeBacking{AllocationID: f.allocation.ID, RootID: root, PolicyID: custodyID(), PolicyDigest: artifact.Digest{77}, Rows: 1, Keys: 2, TransitionsPerRow: 32, BackupBytes: 16 << 20, WALBytes: 16 << 20, CleanupSeconds: 30, ValidUntil: f.allocation.ValidUntil, RetireBy: f.allocation.ValidUntil.Add(30 * time.Second), History: value.NativeHistoryQualification{ID: custodyID(), Digest: artifact.Digest{78}, RowBytes: 64 << 10, TransitionWALBytes: 64 << 10, BackupCopies: 1, WALCopies: 1}}
	if err = history.InstallNativeBacking(ctx, backing); err != nil {
		t.Fatal(err)
	}
	if err = refresh(); err != nil {
		t.Fatal(err)
	}
	intent, err := f.runtime.BeginDownloadBatch(ctx, f.worker.Intent.SessionID, f.authority(), artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadMetadata, ReadBytes: 2 << 20})
	if err != nil {
		t.Fatal(err)
	}
	objects := &objectstore.DownloadAuditObjects{Store: f.store, Seal: f.keys, Open: f.keys}
	receipt, err := objects.WriteDownloadIntent(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.audit.AcknowledgeDownloadIntent(ctx, intent, receipt); err != nil {
		t.Fatal(err)
	}
	outcome, err := f.runtime.FinishDownloadBatch(ctx, intent.SessionID, intent.Batch.ID, intent.Batch.Generation, 0, true, false)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err = objects.WriteDownloadOutcome(ctx, outcome)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.audit.AcknowledgeDownloadOutcome(ctx, outcome, receipt); err != nil {
		t.Fatal(err)
	}
	candidate := func(t *testing.T) (artifact.DownloadAuthority, value.NativeOperation) {
		t.Helper()
		if err := refresh(); err != nil {
			t.Fatal(err)
		}
		a := f.authority()
		fence, err := owners.NextNativeFence(ctx, f.worker.Intent.ID)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		return a, value.NativeOperation{Path: a.Environment.Path, Processing: a.Environment.Processing, Reference: value.NativeReference{InstallationID: f.worker.Binding.InstallationID, SessionID: intent.SessionID, WorkerID: f.worker.Intent.ID, OperationID: custodyID(), Fence: fence}, Kind: value.NativeObserve, HubPodUID: custodyID(), HubProcessEpoch: custodyID(), WorkerPodUID: f.worker.Binding.PodUID, WorkerPublicKey: enrollment.PublicKeyDigest, SourceVersion: a.Scope.Version, ParentID: intent.Batch.ID, Generation: intent.Batch.Generation, StartedAt: now, Until: minPublicationTime(now.Add(5*time.Second), a.ValidUntil)}
	}
	// One genuine baseline, followed by denials that must not mutate/refill it.
	a, o := candidate(t)
	original, err := owners.ClaimNativeOperation(ctx, enrollment, a, o)
	if err != nil {
		t.Fatal("versioned native parent baseline", err)
	}
	if err = owners.ReleaseNativeOperation(ctx, original); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"intent", "outcome", "worker", "enrollment"} {
		for _, version := range []string{"", "null"} {
			name := version
			if name == "" {
				name = "empty"
			}
			t.Run("native-parent-"+kind+"-"+name, func(t *testing.T) {
				a, o := candidate(t)
				var read, update string
				var args []any
				switch kind {
				case "intent":
					read = "SELECT audit_receipt_json FROM download_batch WHERE id=$1"
					update = "UPDATE download_batch SET audit_receipt_json=$2 WHERE id=$1"
					args = []any{intent.Batch.ID}
				case "outcome":
					read = "SELECT outcome_receipt_json FROM download_batch WHERE id=$1"
					update = "UPDATE download_batch SET outcome_receipt_json=$2 WHERE id=$1"
					args = []any{intent.Batch.ID}
				case "worker":
					read = "SELECT audit_receipt_json FROM download_worker WHERE id=$1"
					update = "UPDATE download_worker SET audit_receipt_json=$2 WHERE id=$1"
					args = []any{f.worker.Intent.ID}
				case "enrollment":
					read = "SELECT audit_receipt_json FROM download_worker_enrollment WHERE worker_id=$1"
					update = "UPDATE download_worker_enrollment SET audit_receipt_json=$2 WHERE worker_id=$1"
					args = []any{f.worker.Intent.ID}
				}
				withHistoricalAuditReceipt(t, ctx, f.admin, read, update, args, func(r *audit.Receipt) { r.Version = version }, func() {
					if _, err := owners.ClaimNativeOperation(ctx, enrollment, a, o); err == nil {
						t.Fatal("historical audit admitted a native operation")
					}
					if !a.Valid(time.Now()) || !o.CurrentValid(time.Now()) {
						t.Fatal("denial crossed original native deadline")
					}
				})
				fence, err := owners.NextNativeFence(ctx, f.worker.Intent.ID)
				if err != nil || fence != o.Reference.Fence {
					t.Fatal("denial spent or changed the original native fence", err)
				}
			})
		}
	}
	a, o = candidate(t)
	restored, err := owners.ClaimNativeOperation(ctx, enrollment, a, o)
	if err != nil {
		t.Fatal("exact original receipt restore", err)
	}
	if err = owners.ReleaseNativeOperation(ctx, restored); err != nil {
		t.Fatal(err)
	}
	qualifyHistoricalDownloadAccounting(t, ctx, f, refresh)
}

// A historical acknowledgement cannot admit new I/O, but the original bounded
// row must still record the already performed byte and retain every charge.
func qualifyHistoricalDownloadAccounting(t *testing.T, ctx context.Context, f nativeExchangeFixture, refresh func() error) {
	t.Helper()
	objects := &objectstore.DownloadAuditObjects{Store: f.store, Seal: f.keys, Open: f.keys}
	for _, version := range []string{"", "null"} {
		label := version
		if label == "" {
			label = "empty"
		}
		t.Run("historical-accounting-"+label, func(t *testing.T) {
			if err := refresh(); err != nil {
				t.Fatal(err)
			}
			a := f.authority()
			i, err := f.runtime.BeginDownloadBatch(ctx, f.worker.Intent.SessionID, a, artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadContent, OutputBytes: 1, ReadBytes: 1})
			if err != nil {
				t.Fatal(err)
			}
			r, err := objects.WriteDownloadIntent(ctx, i)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.audit.AcknowledgeDownloadIntent(ctx, i, r); err != nil {
				t.Fatal(err)
			}
			if err = f.runtime.PermitDownloadBatch(ctx, i.SessionID, a, i.Batch.ID, i.Batch.Generation); err != nil {
				t.Fatal("original byte permission", err)
			}
			var beforeOutput, beforeRead, beforeRequests int64
			if err = f.admin.QueryRow(ctx, "SELECT charged_output,charged_read,requests FROM artifact_download WHERE id=$1", i.SessionID).Scan(&beforeOutput, &beforeRead, &beforeRequests); err != nil {
				t.Fatal(err)
			}
			var outcome audit.DownloadOutcome
			withHistoricalAuditReceipt(t, ctx, f.admin, "SELECT audit_receipt_json FROM download_batch WHERE id=$1", "UPDATE download_batch SET audit_receipt_json=$2 WHERE id=$1", []any{i.Batch.ID}, func(r *audit.Receipt) { r.Version = version }, func() {
				if err = f.runtime.PermitDownloadBatch(ctx, i.SessionID, a, i.Batch.ID, i.Batch.Generation); err == nil {
					t.Fatal("historical receipt permitted new bytes")
				}
				if !a.Valid(time.Now()) {
					t.Fatal("original byte permission expired during denial")
				}
				// The single byte is an explicit fixture accounting observation, made
				// under the positive original permission above, not a new transfer here.
				outcome, err = f.runtime.FinishDownloadBatch(ctx, i.SessionID, i.Batch.ID, i.Batch.Generation, 1, false, false)
				if err != nil {
					t.Fatal("historical physical outcome unavailable", err)
				}
			})
			r, err = objects.WriteDownloadOutcome(ctx, outcome)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.audit.AcknowledgeDownloadOutcome(ctx, outcome, r); err != nil {
				t.Fatal(err)
			}
			var output, read, requests int64
			if err = f.admin.QueryRow(ctx, "SELECT charged_output,charged_read,requests FROM artifact_download WHERE id=$1", i.SessionID).Scan(&output, &read, &requests); err != nil || output != beforeOutput || read != beforeRead || requests != beforeRequests {
				t.Fatal("historical accounting refunded spend", err)
			}
		})
	}
	// The fourth originally prepaid request tests cancellation without opening
	// a second session or changing any quota. Null history remains charged.
	if err := refresh(); err != nil {
		t.Fatal(err)
	}
	a := f.authority()
	i, err := f.runtime.BeginDownloadBatch(ctx, f.worker.Intent.SessionID, a, artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadContent, OutputBytes: 1, ReadBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	r, err := objects.WriteDownloadIntent(ctx, i)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.audit.AcknowledgeDownloadIntent(ctx, i, r); err != nil {
		t.Fatal(err)
	}
	var beforeOutput, beforeRead, beforeRequests int64
	if err = f.admin.QueryRow(ctx, "SELECT charged_output,charged_read,requests FROM artifact_download WHERE id=$1", i.SessionID).Scan(&beforeOutput, &beforeRead, &beforeRequests); err != nil {
		t.Fatal(err)
	}
	withHistoricalAuditReceipt(t, ctx, f.admin, "SELECT audit_receipt_json FROM download_batch WHERE id=$1", "UPDATE download_batch SET audit_receipt_json=$2 WHERE id=$1", []any{i.Batch.ID}, func(r *audit.Receipt) { r.Version = "null" }, func() {
		canceled, err := f.runtime.CancelDownload(ctx, i.SessionID, a.Scope.Principal)
		if err != nil || canceled.State != artifact.DownloadCancelled || canceled.ChargedOutput != beforeOutput || canceled.ChargedRead != beforeRead || canceled.Requests != beforeRequests {
			t.Fatal("historical cancellation changed spend or failed", err)
		}
	})
}
