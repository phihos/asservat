package postgres

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
)

func TestFirstContextPreparationDoesNotGrantASecondAttempt(t *testing.T) {
	original := artifact.DownloadSession{StopProtocol: artifact.DownloadStopProtocol, State: artifact.DownloadPreparing}
	batch := artifact.DownloadBatch{Purpose: artifact.DownloadMetadata, ReadBytes: evidence.ContextDownloadReadWork}
	if !firstContextPreparation(original, batch) {
		t.Fatal("first preparation rejected")
	}
	for _, change := range []func(*artifact.DownloadSession){
		func(s *artifact.DownloadSession) { s.StopProtocol = "" },
		func(s *artifact.DownloadSession) { s.State = artifact.DownloadReady },
		func(s *artifact.DownloadSession) { s.Generation = 1 },
		func(s *artifact.DownloadSession) { s.Requests = 1 },
		func(s *artifact.DownloadSession) { s.Active = &batch },
		func(s *artifact.DownloadSession) { s.ChargedRead = 1 },
		func(s *artifact.DownloadSession) { s.ChargedOutput = 1 },
		func(s *artifact.DownloadSession) { s.EmittedBytes = 1 },
	} {
		s := original
		change(&s)
		if firstContextPreparation(s, batch) {
			t.Fatal("spent/historical session admitted", s)
		}
	}
	for _, change := range []func(*artifact.DownloadBatch){
		func(b *artifact.DownloadBatch) { b.ReadBytes-- },
		func(b *artifact.DownloadBatch) { b.Purpose = artifact.DownloadContent },
		func(b *artifact.DownloadBatch) { b.Offset = 1 },
		func(b *artifact.DownloadBatch) { b.OutputBytes = 1 },
	} {
		b := batch
		change(&b)
		if firstContextPreparation(original, b) {
			t.Fatal("noninitial work admitted", b)
		}
	}
}
func TestFirstContextObservePreservesContentAndRetirementHeadroom(t *testing.T) {
	// Claim + positive close cost two updates. Content reserves another two;
	// final independently confirmed retirement consumes one. Unknown closure
	// remains busy even if its original lease expired; it never replenishes five.
	for remaining := int64(0); remaining <= 8; remaining++ {
		for _, busy := range []contextNativeControl{{}, {nativeBusy: true}, {responseBusy: true}, {nativeBusy: true, uncertain: true}, {responseBusy: true, uncertain: true}} {
			busy.remaining = remaining
			want := remaining >= 5 && !busy.nativeBusy && !busy.responseBusy
			if busy.canObserve(4096) != want {
				t.Fatal("incorrect finite observation admission", busy)
			}
		}
	}
}

func TestNativeProfileResponsePreservesTwoWindowHeadroom(t *testing.T) {
	for _, size := range []int64{0, 4096, artifact.DownloadWindowBytes, artifact.DownloadWindowBytes + 1, artifact.MaxGoTraceBytes} {
		plan := artifact.DownloadResponsePlan{Version: 1, Selection: artifact.DownloadSelection{Length: size}, WindowReadLimit: 80 << 20}
		for remaining := int64(0); remaining <= 9; remaining++ {
			c := contextNativeControl{remaining: remaining}
			want := remaining >= 2*plan.Windows()+1
			if c.canRespond(plan) != want {
				t.Fatalf("size %d remaining %d: content or retirement headroom lost", size, remaining)
			}
			if c.canObserve(size) != (remaining >= 2*plan.Windows()+3) {
				t.Fatalf("size %d remaining %d: observation consumes content headroom", size, remaining)
			}
		}
	}
	c := contextNativeControl{remaining: 100}
	if c.canRespond(artifact.DownloadResponsePlan{}) || c.canObserve(-1) {
		t.Fatal("invalid bounds accepted")
	}
	plan := artifact.DownloadResponsePlan{Version: 1, Selection: artifact.DownloadSelection{Length: artifact.MaxGoTraceBytes + 1}, WindowReadLimit: 80 << 20}
	if c.canRespond(plan) {
		t.Fatal("unsupported response size admitted")
	}
	plan.Selection.Length = artifact.MaxGoTraceBytes
	plan.Selection.Offset = 1
	if c.canRespond(plan) {
		t.Fatal("unsupported response end admitted")
	}
}
