package feasibility

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"
)

// boundedRing isolates allocation/rotation semantics, not the production recorder.
// This model bounds payload/framing; metadata and actual runtime heap need separate qualification.
type boundedRing struct {
	mu                          sync.Mutex
	data                        []byte
	segmentSize, count, current int
	used                        []int
	oldest                      []time.Time
	maxAge                      time.Duration
	maxFrozen, frozen           int
	drops, refusals             int
}

func newRing(segmentSize, count, maxFrozen int, age time.Duration) *boundedRing {
	return &boundedRing{data: make([]byte, segmentSize*count), segmentSize: segmentSize, count: count, used: make([]int, count), oldest: make([]time.Time, count), maxAge: age, maxFrozen: maxFrozen}
}
func (r *boundedRing) expire(now time.Time) {
	for i := range r.used {
		if r.used[i] > 0 && now.Sub(r.oldest[i]) > r.maxAge {
			clear(r.data[i*r.segmentSize : (i+1)*r.segmentSize])
			r.used[i] = 0
		}
	}
}
func (r *boundedRing) write(now time.Time, p []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expire(now)
	n := len(p) + 4
	if n > r.segmentSize {
		r.drops++
		return false
	}
	if r.used[r.current]+n > r.segmentSize {
		r.current = (r.current + 1) % r.count
		r.used[r.current] = 0
		clear(r.data[r.current*r.segmentSize : (r.current+1)*r.segmentSize])
	}
	if r.used[r.current] == 0 {
		r.oldest[r.current] = now
	}
	start := r.current*r.segmentSize + r.used[r.current]
	binary.LittleEndian.PutUint32(r.data[start:], uint32(len(p)))
	copy(r.data[start+4:], p)
	r.used[r.current] += n
	return true
}

type ringSnapshot struct {
	Data []byte
	r    *boundedRing
	once sync.Once
}

func (r *boundedRing) snapshot(now time.Time) (*ringSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expire(now)
	if r.frozen+len(r.data) > r.maxFrozen {
		r.refusals++
		return nil, errors.New("frozen capacity exhausted")
	}
	r.frozen += len(r.data)
	return &ringSnapshot{Data: bytes.Clone(r.data), r: r}, nil
}
func (s *ringSnapshot) release() {
	s.once.Do(func() { s.r.mu.Lock(); defer s.r.mu.Unlock(); s.r.frozen -= len(s.Data); clear(s.Data); s.Data = nil })
}
func TestRingStormAndStalledSnapshot(t *testing.T) {
	now := time.Unix(1700000000, 0)
	r := newRing(4096, 4, 16384, time.Second)
	p := bytes.Repeat([]byte{7}, 128)
	for i := 0; i < 100; i++ {
		r.write(now, p)
	}
	s, e := r.snapshot(now)
	if e != nil {
		t.Fatal(e)
	}
	before := hash(s.Data)
	for i := 0; i < 100000; i++ {
		r.write(now.Add(time.Duration(i)*time.Microsecond), p)
		if i%10 == 0 {
			if _, e = r.snapshot(now); e == nil {
				t.Fatal("storm exceeded frozen limit")
			}
		}
	}
	if hash(s.Data) != before || len(r.data) != 16384 || r.frozen != 16384 || r.refusals != 10000 {
		t.Fatal("ring/snapshot invariant")
	}
	if r.write(now, make([]byte, 4096)) {
		t.Fatal("oversized record admitted")
	}
	r.mu.Lock()
	r.expire(now.Add(2 * time.Second))
	for _, n := range r.used {
		if n != 0 {
			t.Error("old data remains")
		}
	}
	r.mu.Unlock()
	s.release()
	s.release()
	if r.frozen != 0 {
		t.Fatal("double release changed accounting")
	}
	again, e := r.snapshot(now.Add(2 * time.Second))
	if e != nil {
		t.Fatal(e)
	}
	again.release()
	t.Log("100,000 writes and 10,000 refused overlapping snapshots: fixed 16 KiB live + 16 KiB frozen payload/framing buffers; preserved snapshot; age eviction and oversize rejection. Go heap, Gadget stream and uploader scheduling not qualified")
}
func TestRingConcurrentWritersAndSnapshots(t *testing.T) {
	r := newRing(4096, 4, 16384, time.Second)
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				r.write(time.Now(), []byte("synthetic"))
				if s, e := r.snapshot(time.Now()); e == nil {
					s.release()
				}
			}
		}()
	}
	wg.Wait()
	if r.frozen != 0 {
		t.Fatal("leaked frozen reservation")
	}
}
