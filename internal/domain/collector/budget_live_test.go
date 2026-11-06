package collector

import (
	"testing"
	"time"
)

func TestLiveUploadCannotConsumeIncidentBurst(t *testing.T) {
	now := time.Now()
	b, e := NewBudget(Ceilings{UploadBytesPerSecond: 32 << 20, UploadBurstBytes: MaxPacketCaptureBytes + 24576}, now)
	if e != nil {
		t.Fatal(e)
	}
	if !b.TakeLiveUpload(now, 24576) || b.TakeLiveUpload(now, 1) {
		t.Fatal("live crossed reserved incident burst")
	}
	if wait, e := b.TakeUpload(now, MaxPacketCaptureBytes); e != nil || wait != 0 {
		t.Fatal("live delayed existing incident upload", wait, e)
	}
	if b.TakeLiveUpload(now, 1) {
		t.Fatal("unrefilled viewer")
	}
	b, e = NewBudget(Ceilings{UploadBytesPerSecond: 1 << 20, UploadBurstBytes: 1 << 20}, now)
	if e != nil {
		t.Fatal(e)
	}
	if b.TakeLiveUpload(now, 1) {
		t.Fatal("viewer raised small upload ceiling")
	}
}
