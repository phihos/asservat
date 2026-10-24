package artifact

import (
	"fmt"
	"testing"
	"time"
)

func responseFixture(t *testing.T, size int64) (DownloadSession, DownloadAuthority, DownloadResponse, time.Time) {
	t.Helper()
	s, a, n := downloadFixture()
	s.State = DownloadReady
	s.Requests = 1
	s.OutputLimit = max(1, size)
	s.ReadLimit = max(1, size) + DownloadWindowBytes
	p := DownloadResponsePlan{Version: 1, Selection: DownloadSelection{Length: size}, WholeFile: true, WindowReadLimit: DownloadWindowBytes}
	r := DownloadResponse{ID: s.ID, SessionID: s.ID, OwnerID: s.ID, Plan: p, Until: s.Deadline}
	var e error
	s, r, e = s.BeginResponse(a, r, n)
	if e != nil {
		t.Fatal(e)
	}
	return s, a, r, n
}
func TestLargeDownloadOneTiBHasFiniteWindowBackingAndCumulativeCompletion(t *testing.T) {
	s, a, r, n := responseFixture(t, MaxNativeBytes)
	if r.Plan.Windows() != 16384 || r.Plan.AuditBytes() != int64(32768)*(128<<10) {
		t.Fatal("incorrect paired audit envelope", r.Plan)
	}
	for index := int64(0); index < r.Plan.Windows(); index++ {
		id := fmt.Sprintf("10000000-0000-4000-8000-%012d", index+10)
		var w DownloadWindow
		var e error
		s, r, w, e = r.BeginWindow(s, a, id, s.ID, r.Until.Add(time.Minute), n)
		if e != nil {
			t.Fatal(index, e)
		}
		if w.Length != DownloadWindowBytes || w.Offset != index*DownloadWindowBytes {
			t.Fatal("wrong contiguous window", w)
		}
		if _, _, e = r.Lease(s, w, a, r.OwnerID, n); e == nil {
			t.Fatal("unaudited window leased")
		}
		w.IntentAcknowledged = true
		var l DownloadDeliveryLease
		r, l, e = r.Lease(s, w, a, r.OwnerID, n)
		if e != nil {
			t.Fatal(e)
		}
		if !l.Allows(w.Offset, DeliveryBytes, n) || !l.Allows(w.Offset+DeliveryBytes, DeliveryBytes, n) || l.Allows(w.Offset, DeliveryBytes+1, n) || l.Allows(w.Offset, 1, l.Until) {
			t.Fatal("chunk/current lease bounds")
		}
		final := index+1 == r.Plan.Windows()
		s, r, w, e = r.RecordWindow(s, w, DownloadWindowOutcome{EmittedBytes: w.Length, Success: true, VerifiedFinal: final}, n)
		if e != nil {
			t.Fatal(e)
		}
		if s.State == DownloadCompleted {
			t.Fatal("completion before outcome acknowledgement")
		}
		s, r, w, e = r.AcknowledgeWindow(s, w, n)
		if e != nil {
			t.Fatal(e)
		}
	}
	if s.State != DownloadCompleted || s.EmittedBytes != MaxNativeBytes || s.ChargedOutput != MaxNativeBytes || s.Requests != 1 || r.EmittedBytes != MaxNativeBytes || !r.Closed {
		t.Fatal("whole response did not complete independently of legacy batches", s.State, s.Requests, r)
	}
}
func TestLargeDownloadUncertaintySpendsWindowAndCannotCloseGaps(t *testing.T) {
	s, a, r, n := responseFixture(t, 2*DownloadWindowBytes)
	before := s
	s, r, w, e := r.BeginWindow(s, a, s.ID, s.ID, r.Until.Add(time.Minute), n)
	if e != nil {
		t.Fatal(e)
	}
	if s.ChargedOutput != DownloadWindowBytes || s.ChargedRead-before.ChargedRead != DownloadWindowBytes {
		t.Fatal("window not fully prepaid")
	}
	if _, _, _, e = r.BeginWindow(s, a, s.ID, s.ID, r.Until, n); e == nil {
		t.Fatal("unacknowledged window duplicated")
	}
	w.IntentAcknowledged = true
	bad := w
	bad.Offset++
	if _, _, _, e = r.RecordWindow(s, bad, DownloadWindowOutcome{EmittedBytes: 1}, n); e == nil {
		t.Fatal("gap accepted")
	}
	s, r, w, e = r.RecordWindow(s, w, DownloadWindowOutcome{EmittedBytes: DeliveryBytes}, n)
	if e != nil {
		t.Fatal(e)
	}
	s, r, w, e = r.AcknowledgeWindow(s, w, n)
	if e != nil || s.ChargedOutput != DownloadWindowBytes || s.State != DownloadInterrupted || !r.Closed {
		t.Fatal("uncertainty refunded or stayed live", e)
	}
	if _, _, _, e = r.BeginWindow(s, a, s.ID, s.ID, r.Until, n); e == nil {
		t.Fatal("closed response restarted")
	}
}
func TestLargeDownloadHistoricalOutcomeCannotReviveOrCompleteReplacement(t *testing.T) {
	for _, mode := range []string{"cancelled", "replacement", "expired", "missing-final-verification"} {
		t.Run(mode, func(t *testing.T) {
			s, a, r, n := responseFixture(t, DeliveryBytes)
			s, r, w, e := r.BeginWindow(s, a, s.ID, s.ID, r.Until.Add(time.Minute), n)
			if e != nil {
				t.Fatal(e)
			}
			w.IntentAcknowledged = true
			switch mode {
			case "cancelled":
				s.State = DownloadCancelled
			case "replacement":
				s.Generation++
			case "expired":
				n = s.Deadline
			}
			s, r, w, e = r.RecordWindow(s, w, DownloadWindowOutcome{EmittedBytes: w.Length, Success: true, VerifiedFinal: mode != "missing-final-verification"}, n)
			if e != nil {
				t.Fatal(e)
			}
			s, _, _, e = r.AcknowledgeWindow(s, w, n)
			if e != nil || s.State == DownloadCompleted {
				t.Fatal("old/unverified outcome completed", mode, e)
			}
		})
	}
}
func TestLargeDownloadPlanBoundariesAndPartialRange(t *testing.T) {
	for _, size := range []int64{0, 1, DownloadWindowBytes, DownloadWindowBytes + 1, MaxNativeBytes} {
		s, a, r, n := responseFixture(t, size)
		if !r.Plan.Valid() || r.Plan.Windows() != max(1, (size+DownloadWindowBytes-1)/DownloadWindowBytes) {
			t.Fatal(size)
		}
		r.Generation = 0
		r.StartedAt = time.Time{}
		r.Plan.WindowReadLimit = MaxDownloadReadWork
		if r.Plan.Windows() > 1 {
			if _, _, e := s.BeginResponse(a, r, n); e == nil {
				t.Fatal("overflow read budget")
			}
		}
	}
	s, a, r, n := responseFixture(t, DeliveryBytes)
	r.Plan.Selection = DownloadSelection{Offset: 100, Length: DeliveryBytes, Partial: true}
	r.Plan.WholeFile = false
	s, r, w, e := r.BeginWindow(s, a, s.ID, s.ID, r.Until.Add(time.Minute), n)
	if e != nil {
		t.Fatal(e)
	}
	w.IntentAcknowledged = true
	s, r, w, e = r.RecordWindow(s, w, DownloadWindowOutcome{EmittedBytes: w.Length, Success: true, VerifiedFinal: true}, n)
	if e != nil {
		t.Fatal(e)
	}
	s, r, _, e = r.AcknowledgeWindow(s, w, n)
	if e != nil || !r.Closed || s.State != DownloadInterrupted {
		t.Fatal("partial range became full session completion", e)
	}
}

// Installed native91: SQL pins a window's WriteUntil to its control's
// AuditWriteUntil, which a protected-capacity control sets about 24 h ahead.
// The window must accept it; a deadline beyond the capacity bound still fails.
func TestDownloadWindowAcceptsCapacityControlAuditDeadline(t *testing.T) {
	s, a, r, n := responseFixture(t, DeliveryBytes)
	if _, _, _, e := r.BeginWindow(s, a, s.ID, s.ID, n.Add(24*time.Hour+30*time.Second), n); e != nil {
		t.Fatal("capacity control audit deadline refused the window", e)
	}
	if _, _, _, e := r.BeginWindow(s, a, s.ID, s.ID, n.Add(MaxDownloadWindowWrite+time.Second), n); e == nil {
		t.Fatal("unbounded window audit deadline accepted")
	}
}
