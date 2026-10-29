//go:build gadget && linux

package gadget

import (
	"testing"
	"time"
)

func BenchmarkPacketClockSample(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := newPacketClock(time.Now, readPacketMonotonic); err != nil {
			b.Fatal(err)
		}
	}
}
