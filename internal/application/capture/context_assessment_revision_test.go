package capture

import (
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
