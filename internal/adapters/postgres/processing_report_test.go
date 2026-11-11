package postgres

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
)

func TestProcessingReportDeletedArtifactKeepsOriginalBounds(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	parents, _ := json.Marshal([]artifact.Location{})
	row := custodydb.ReportProcessingArtifactsRow{
		ArtifactID: id("00000000-0000-4000-8000-000000000001"), CaptureID: id("00000000-0000-4000-8000-000000000002"),
		CaseID: id("00000000-0000-4000-8000-000000000003"), ClusterID: id("00000000-0000-4000-8000-000000000004"),
		AttemptID: id("00000000-0000-4000-8000-000000000005"), StoreID: "00000000-0000-4000-8000-000000000006",
		NamespaceUid: "namespace", WorkloadUid: "workload", Origin: "capture", Parents: parents, RetireBy: ts(now.Add(time.Hour)),
		AnchorAt: ts(now.Add(-time.Minute)), OriginalExpiresAt: ts(now.Add(time.Minute)), OriginalDeleteBy: ts(now.Add(2 * time.Minute)),
		EffectiveExpiresAt: ts(now.Add(-time.Minute)), EffectiveDeleteBy: ts(now.Add(2 * time.Minute)), State: artifact.Deleted,
		DeletedAt: ts(now.Add(-time.Second)), PurposeRef: "diagnostics", ActionID: "pod-status", NativeType: artifact.PodStatusArtifact, DataClass: "metadata",
	}
	record, err := processingReportArtifact(row, now)
	if err != nil || record.Artifact == nil || record.Artifact.DeletionState != "deleted" ||
		!record.Artifact.OriginalExpiresAt.Equal(row.OriginalExpiresAt.Time) || !record.Artifact.ExpiresAt.Equal(row.AnchorAt.Time) ||
		!record.VisibleUntil.Equal(row.RetireBy.Time) {
		t.Fatal("deleted report projection lost original provenance", record, err)
	}
	row.RetireBy = ts(now)
	if _, err = processingReportArtifact(row, now); err == nil {
		t.Fatal("retired control metadata remained reportable")
	}
}
