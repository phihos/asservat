package gadget

import "time"

// packetClock pairs the published gadget's MONOTONIC stamps with one source's
// wall sample. It does not qualify wall-clock steps or event-time coverage.
// Its delivery/failure state is serialized by the capture's existing mutex.
type packetClock struct {
	wall    time.Time
	mono    int64
	now     func() time.Time
	invalid bool
}

func packetWallValid(t time.Time) bool {
	n := t.UnixNano()
	return n > 0 && time.Unix(0, n).Equal(t)
}
func newPacketClock(now func() time.Time, monotonic func() (int64, error)) (packetClock, error) {
	before := now().UTC()
	mono, err := monotonic()
	after := now().UTC()
	if err != nil || mono <= 0 || !packetWallValid(before) || !packetWallValid(after) || after.Before(before) {
		return packetClock{}, ErrEngineUnavailable
	}
	return packetClock{wall: before.Add(after.Sub(before) / 2), mono: mono, now: now}, nil
}
func (c packetClock) at(raw uint64) (time.Time, bool) {
	if raw == 0 {
		// Legacy arrival fallback, not an original kernel timestamp.
		return time.Unix(0, c.now().UnixNano()).UTC(), true
	}
	if raw > uint64(1<<63-1) {
		return time.Time{}, false
	}
	at := c.wall.Add(time.Duration(int64(raw) - c.mono)).UTC()
	return at, packetWallValid(at)
}
func (c *packetClock) deliver(data []byte, wire uint32, raw uint64, notice func(InputNotice), deliver func(Frame)) {
	at, ok := c.at(raw)
	if !ok {
		c.invalid = true
		if notice != nil {
			notice(InputNotice{})
		}
		return
	}
	deliver(Frame{Data: data, Wire: wire, At: at})
}

func packetMonotonicNanos(sec, nsec int64) (int64, error) {
	if sec < 0 || nsec < 0 || nsec >= int64(time.Second) || sec > (1<<63-1-nsec)/int64(time.Second) {
		return 0, ErrEngineUnavailable
	}
	return sec*int64(time.Second) + nsec, nil
}
