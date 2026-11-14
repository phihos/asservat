package integration

import (
	"encoding/binary"
	"testing"
)

// This serialized fixture executes exactly one one-column integer statement:
// the fixed observation producer. Basis/read/clock statements have different
// arity/types. Accept only its closed disposition 3, never arbitrary error text.
func fleetObservationLockDisposition(body []byte) bool {
	if len(body) < 6 || binary.BigEndian.Uint16(body[:2]) != 1 {
		return false
	}
	n := binary.BigEndian.Uint32(body[2:6])
	if n == 4 && len(body) == 10 {
		return binary.BigEndian.Uint32(body[6:]) == 3
	}
	return n == 1 && len(body) == 7 && body[6] == '3'
}

func TestFleetObservationLockDispositionIsClosed(t *testing.T) {
	for _, tc := range []struct {
		body []byte
		want bool
	}{
		{[]byte{0, 1, 0, 0, 0, 4, 0, 0, 0, 3}, true}, {[]byte{0, 1, 0, 0, 0, 1, '3'}, true},
		{[]byte{0, 1, 0, 0, 0, 4, 0, 0, 0, 1}, false}, {[]byte{0, 1, 0, 0, 0, 1, '0'}, false},
		{[]byte{0, 2, 0, 0, 0, 4, 0, 0, 0, 3}, false}, {[]byte{0, 1, 0, 0, 0, 4, 0, 0, 0, 3, 0}, false},
		{[]byte{0, 1, 255, 255, 255, 255}, false}, {[]byte("C55P03\x00"), false},
	} {
		if got := fleetObservationLockDisposition(tc.body); got != tc.want {
			t.Fatal("unexpected disposition classification")
		}
	}
}
