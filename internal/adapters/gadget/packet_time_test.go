package gadget

import (
	"errors"
	"testing"
	"time"
)

func packetClockFixture(t *testing.T) (packetClock, *int, *int, time.Time) {
	t.Helper()
	wall := time.Unix(1700000000, 0).UTC()
	walls, monos := 0, 0
	c, err := newPacketClock(func() time.Time {
		walls++
		if walls == 1 {
			return wall.Add(-10 * time.Nanosecond)
		}
		if walls == 2 {
			return wall.Add(10 * time.Nanosecond)
		}
		return wall.Add(time.Second)
	}, func() (int64, error) { monos++; return int64(time.Hour), nil })
	if err != nil {
		t.Fatal(err)
	}
	return c, &walls, &monos, wall
}
func TestPacketClockMatchingMonotonicSample(t *testing.T) {
	c, walls, monos, wall := packetClockFixture(t)
	for _, delta := range []time.Duration{-time.Minute, 0, time.Minute} {
		got, ok := c.at(uint64(time.Hour + delta))
		if !ok || !got.Equal(wall.Add(delta)) || got.Location() != time.UTC {
			t.Fatal(got, ok)
		}
	}
	if *walls != 2 || *monos != 1 {
		t.Fatal("per-frame clock reads", *walls, *monos)
	}
	if n := testing.AllocsPerRun(100, func() { c.at(uint64(time.Hour)) }); n != 0 {
		t.Fatal(n)
	}
	got, ok := c.at(0)
	if !ok || !got.Equal(wall.Add(time.Second)) || *walls != 3 || *monos != 1 {
		t.Fatal("legacy zero fallback changed", got, ok, *walls)
	}
	// An independent source observes a new wall anchor, never a shared old offset.
	c2, err := newPacketClock(func() time.Time { return wall.Add(time.Hour) }, func() (int64, error) { return int64(time.Hour), nil })
	if err != nil {
		t.Fatal(err)
	}
	got, _ = c2.at(uint64(time.Hour))
	if !got.Equal(wall.Add(time.Hour)) {
		t.Fatal(got)
	}
}
func TestPacketClockConstructorAndBounds(t *testing.T) {
	wall := time.Unix(1700000000, 0)
	for _, mode := range []string{"syscall", "zero-mono", "negative-mono", "zero-wall", "backward-wall", "outside-wall"} {
		t.Run(mode, func(t *testing.T) {
			n := 0
			_, err := newPacketClock(func() time.Time {
				n++
				switch mode {
				case "zero-wall":
					return time.Time{}
				case "outside-wall":
					return time.Unix(1<<62, 0)
				case "backward-wall":
					return wall.Add(-time.Duration(n) * time.Second)
				}
				return wall
			}, func() (int64, error) {
				switch mode {
				case "syscall":
					return 0, errors.New("private fixture")
				case "zero-mono":
					return 0, nil
				case "negative-mono":
					return -1, nil
				}
				return int64(time.Hour), nil
			})
			if !errors.Is(err, ErrEngineUnavailable) {
				t.Fatal(err)
			}
		})
	}
	for _, v := range [][2]int64{{-1, 0}, {0, -1}, {0, int64(time.Second)}, {1<<63 - 1, 0}, {(1<<63 - 1) / int64(time.Second), (1<<63-1)%int64(time.Second) + 1}} {
		if _, err := packetMonotonicNanos(v[0], v[1]); err == nil {
			t.Fatal(v)
		}
	}
	if n, err := packetMonotonicNanos(1, 2); err != nil || n != int64(time.Second)+2 {
		t.Fatal(n, err)
	}
	early := packetClock{wall: time.Unix(0, 1), mono: int64(time.Hour), now: time.Now}
	if at, ok := early.at(1); ok {
		t.Fatal("pre-epoch output normalized", at)
	}
	c, _, _, _ := packetClockFixture(t)
	for _, raw := range []uint64{1<<63 - 1, 1 << 63, ^uint64(0)} {
		if at, ok := c.at(raw); ok {
			t.Fatal("invalid time normalized", raw, at)
		}
	}
}
func TestPacketClockActualDeliveryAndFailureFlag(t *testing.T) {
	for _, withNotice := range []bool{false, true} {
		c, _, _, wall := packetClockFixture(t)
		frames, notices := 0, 0
		var notice func(InputNotice)
		if withNotice {
			notice = func(n InputNotice) {
				if n.LostSamples != 0 {
					t.Fatal(n)
				}
				notices++
			}
		}
		deliver := func(f Frame) {
			frames++
			if !f.At.Equal(wall) || f.Wire != 3 || len(f.Data) != 2 {
				t.Fatal(f)
			}
		}
		c.deliver([]byte{1, 2}, 3, uint64(time.Hour), notice, deliver)
		c.deliver([]byte{1, 2}, 3, ^uint64(0), notice, deliver)
		if frames != 1 || !c.invalid || (withNotice && notices != 1) || (!withNotice && notices != 0) {
			t.Fatal(frames, notices, c.invalid)
		}
	}
}
func BenchmarkPacketClockConvert(b *testing.B) {
	c := packetClock{wall: time.Unix(1700000000, 0), mono: int64(time.Hour), now: time.Now}
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := c.at(uint64(time.Hour)); !ok {
			b.Fatal("invalid")
		}
	}
}

func TestPacketClockArrivalFallbackIsExplicitWithoutChangingFiniteFrame(t *testing.T) {
	c, _, _, wall := packetClockFixture(t)
	var frames []Frame
	c.deliver([]byte{1, 2}, 2, 0, nil, func(f Frame) { frames = append(frames, f) })
	if len(frames) != 1 || !frames[0].TimestampUnknown || !frames[0].At.Equal(wall.Add(time.Second)) || frames[0].Wire != 2 || len(frames[0].Data) != 2 {
		t.Fatal("legacy finite arrival bytes/timestamp changed", frames)
	}
}
