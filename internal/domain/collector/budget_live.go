package collector

import "time"

// TakeLiveUpload consumes only spare upload tokens. The largest existing whole
// packet result keeps its original ready-to-send burst; live work never waits
// in an incident's upload queue or consumes that reserved burst. A smaller
// configured burst makes live unavailable, rather than raising the limit.
func (b *Budget) TakeLiveUpload(now time.Time, n int64) bool {
	if b == nil || now.IsZero() || n < 1 || n > 24<<10+4096 || b.ceilings.UploadBurstBytes <= MaxPacketCaptureBytes {
		return false
	}
	b.refill(now)
	if b.tokens < int64(MaxPacketCaptureBytes)+n {
		return false
	}
	b.tokens -= n
	return true
}
