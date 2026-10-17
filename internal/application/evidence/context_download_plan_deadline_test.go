package evidence

import (
	"context"
	"testing"
	"time"
)

func TestContextDownloadPlanKeepsAbsoluteBackingEndAcrossLookupWait(t *testing.T) {
	for _, delay := range []time.Duration{2 * time.Second, 6 * time.Second} {
		t.Run(delay.String(), func(t *testing.T) {
			f, s := newDownloadControlFixture(t)
			hard := f.now.Add(10 * time.Second)
			f.plan.HardUntil = hard
			f.after = func(step string) {
				if step == "plan" {
					f.now = f.now.Add(delay)
				}
			}
			out, e := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "original")
			if delay > 5*time.Second {
				if e == nil || countDownloadCalls(f, "reserve") != 0 {
					t.Fatal("expired plan reserved")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if !out.Session.Deadline.Equal(hard.UTC().Truncate(time.Microsecond)) || countDownloadCalls(f, "reserve") != 1 {
				t.Fatal("lookup wait moved original backing end", out.Session.Deadline, hard)
			}
		})
	}
}
