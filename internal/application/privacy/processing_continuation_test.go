package privacy

import (
	"context"
	"testing"
	"time"
)

func TestProcessingContinuationRetainsEarliestOriginalAndIdentityBounds(t *testing.T) {
	for _, mode := range []string{"narrowed-identity", "refreshed-identity"} {
		t.Run(mode, func(t *testing.T) {
			f, s, c := newProcessingFixture(t)
			original := f.now
			want := f.i.ValidUntil
			if mode == "narrowed-identity" {
				want = original.Add(time.Second)
				f.afterFinish = func() { f.i.ValidUntil = want }
				// A subsequent identity observation cannot undo the narrower
				// bound already passed to the effect transaction.
				f.afterApply = func() { f.i.ValidUntil = original.Add(2 * time.Second) }
			} else {
				f.afterFinish = func() {
					f.now = original.Add(4 * time.Second)
					f.i.VerifiedAt, f.i.ValidUntil = f.now, f.now.Add(5*time.Second)
				}
			}
			out, err := s.Change(context.Background(), f, c)
			if err != nil || !out.ValidUntil.Equal(want) || f.receipt == nil || !f.receipt.ValidUntil.Equal(want) || f.applies != 1 {
				t.Fatal("continuation renewed original authority or lost identity narrowing", out, err, f.applies)
			}
			if f.policyObservations != 1 || f.recoveryObservations != 1 {
				t.Fatal("continuation repeated complete observations", f.policyObservations, f.recoveryObservations)
			}
		})
	}
}
