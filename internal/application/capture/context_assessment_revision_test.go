package capture

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
)

func TestContextOldAnchorReviewNeedsRefreshButAcceptedRequestRemainsRecoverable(t *testing.T) {
	legacy := map[artifact.ContextExecutionClass]string{
		artifact.ContextNodeExecution: "50bade393d4dca58374e58e5478aded51b98a5be9fec17f5e23e88321ea91bb4",
		artifact.ContextAPIExecution:  "bdeec016b739b4d465ead76af39f8153cb55ac80c57b919d9a4be4c9fd551bbe",
	}
	for class, previous := range legacy {
		t.Run(string(class), func(t *testing.T) {
			old, err := hex.DecodeString(previous)
			if err != nil {
				t.Fatal(err)
			}
			fixture := func() *investigationFixture {
				f := newInvestigationFixture()
				f.target.ExecutionClass, f.cap.ExecutionClass = class, class
				if class == artifact.ContextAPIExecution {
					f.target.Pin.NodeName, f.target.NodeUID, f.target.NodeBootID = "", "", ""
				}
				return f
			}
			f := fixture()
			p := f.preview(t)
			copy(p.AssessmentRulesDigest[:], old)
			f.previews[p.ID] = p
			if _, err := f.request(t, p, "unsubmitted-v1"); !errors.Is(err, value.ErrChanged) || f.admissions.Load() != 0 {
				t.Fatalf("old unsubmitted anchor review admitted: %v", err)
			}

			f = fixture()
			p = f.preview(t)
			accepted, err := f.request(t, p, "accepted-original")
			if err != nil {
				t.Fatal(err)
			}
			// An existing accepted registration is independent of the old draft's
			// explanation. Updating the rule must neither hide it nor reset dates.
			copy(p.AssessmentRulesDigest[:], old)
			f.previews[p.ID] = p
			beforeReads := f.previewReads.Load()
			f.now = f.now.Add(2 * time.Second)
			replayed, err := f.request(t, p, "accepted-original")
			if err != nil || !replayed.Replay || replayed.CaptureID != accepted.CaptureID || f.admissions.Load() != 1 || f.previewReads.Load() != beforeReads {
				t.Fatalf("new anchor rules lost accepted-operation replay: %v", err)
			}
			if !reflect.DeepEqual(replayed.Expectation.Registration, accepted.Expectation.Registration) || !replayed.CreatedAt.Equal(accepted.CreatedAt) || !replayed.Deadline.Equal(accepted.Deadline) {
				t.Fatal("accepted replay changed original retention or operation dates")
			}
		})
	}
}

// Persisted v1 recorder rules described a different retention anchor. A new
// interpretation must require another review before any grant or admission.
func TestRecorderOldRetentionAnchorReviewNeedsRefresh(t *testing.T) {
	f := newInvestigationFixture()
	f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
	f.target.ExecutionClass, f.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	f.svc.Recorders = availableRecording{}
	f.svc.Filters = &stubFilters{}
	ctx := context.Background()
	r, err := f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition()))
	if err != nil {
		t.Fatal(err)
	}
	old, err := hex.DecodeString("20e562ac0561ec3e07ebc73fbbbed44fdc099ce805e9b44ff8aa37f2f4c16d4e")
	if err != nil {
		t.Fatal(err)
	}
	p := r.Preview
	if string(p.AssessmentRulesDigest[:]) == string(old) {
		t.Fatal("manual retention interpretation kept v1 digest")
	}
	copy(p.AssessmentRulesDigest[:], old)
	f.previews[p.ID] = p
	if _, err := f.request(t, p, "unsubmitted-recorder-v1"); !errors.Is(err, value.ErrChanged) || f.admissions.Load() != 0 {
		t.Fatalf("old recorder timing reached admission: %v", err)
	}
}
