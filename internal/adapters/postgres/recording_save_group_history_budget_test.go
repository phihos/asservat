package postgres

import (
	"testing"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	value "asservat.local/asservat/internal/domain/capture"
)

func TestGroupHistoryWorkBudgetCountsChildrenWithoutSkippingNextParent(t *testing.T) {
	rows := make([]custodydb.ListCaptureHistoryCandidatesRow, value.HistoryScan)
	for n := range rows {
		rows[n].Grouped, rows[n].MemberCount = true, 16
		rows[n].ID.Bytes[15] = byte(n)
		rows[n].ID.Valid = true
	}
	bounded, more, err := boundedRecordingHistoryCandidates(rows)
	if err != nil || !more || len(bounded) != 11 || len(bounded)*17 > value.HistoryScan {
		t.Fatal("parent-only counting exceeded existing metadata work", len(bounded), more, err)
	}
	// The next request resumes AFTER the last examined row, so the first
	// unexamined parent remains first in the next bounded page.
	rest, _, err := boundedRecordingHistoryCandidates(rows[len(bounded):])
	if err != nil || len(rest) == 0 || rest[0].ID != rows[11].ID {
		t.Fatal("continuation skipped a parent at the child-work boundary", err)
	}
	for n := range rows {
		rows[n].Grouped, rows[n].MemberCount = false, 1
	}
	if singles, more, err := boundedRecordingHistoryCandidates(rows); err != nil || more || len(singles) != value.HistoryScan {
		t.Fatal("group support reduced unchanged singleton scan", len(singles), more, err)
	}
	rows[0].Grouped, rows[0].MemberCount = true, 17
	if _, _, err := boundedRecordingHistoryCandidates(rows); err == nil {
		t.Fatal("unbounded/corrupt group size was accepted")
	}
}
