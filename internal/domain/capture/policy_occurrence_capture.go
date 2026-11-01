package capture

import (
	"crypto/sha256"
	"fmt"
)

// OccurrenceCaptureKey is the idempotency key of a further recorder's capture
// of one policy occurrence (ADR-275): a UUID derived from the occurrence ID
// and action ID, so a retry reuses it and two recorders never share one.
func OccurrenceCaptureKey(occurrenceID, actionID string) string {
	h := sha256.Sum256([]byte("asservat/occurrence-capture/v1\x00" + occurrenceID + "\x00" + actionID))
	h[6] = h[6]&0x0f | 0x80 // version 8
	h[8] = h[8]&0x3f | 0x80 // RFC 9562 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}
