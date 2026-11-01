package manifest

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestSnapshotNativeCheckRejectsNewerPacketsAndClockAmbiguity(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	request := artifact.SourceSnapshotRequest{T0: now, Before: time.Second, SourceStartedAt: now.Add(-time.Minute)}
	makeStream := func(at time.Time, resolution byte) []byte {
		order := binary.LittleEndian
		body := make([]byte, 20)
		order.PutUint16(body, 1)
		order.PutUint32(body[4:], 134)
		order.PutUint16(body[8:], 9)
		order.PutUint16(body[10:], 1)
		body[12] = resolution
		block := epb(order, 0, 54, 1000)
		stamp := uint64(at.UnixNano())
		order.PutUint32(block[12:], uint32(stamp>>32))
		order.PutUint32(block[16:], uint32(stamp))
		return bytes.Join([][]byte{shb(order), pcapngBlock(order, pcapngIDB, body), block}, nil)
	}
	for name, test := range map[string]struct {
		at         time.Time
		resolution byte
		valid      bool
	}{
		"after known source stop":                 {now, 9, false},
		"original anchor":                         {now, 9, true},
		"original lower bound":                    {now.Add(-time.Second), 9, true},
		"after manual cutoff":                     {now.Add(time.Nanosecond), 9, false},
		"before selected history":                 {now.Add(-time.Second - time.Nanosecond), 9, false},
		"microseconds interpreted as nanoseconds": {now, 6, false},
	} {
		t.Run(name, func(t *testing.T) {
			check := &pcapngCheck{window: &request}
			if name == "after known source stop" {
				check.until = now.Add(-time.Nanosecond)
			}
			err := runCheck(t, check, makeStream(test.at, test.resolution), 7)
			if (err == nil) != test.valid {
				t.Fatal("snapshot window validation", err)
			}
		})
	}
}
