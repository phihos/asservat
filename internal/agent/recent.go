package agent

import (
	"encoding/binary"
	"time"
)

// recent holds the most recent records of a stream, packets or lines, each
// with its time, in one circular buffer of bytes. A record costs its bytes
// and recordHead more; kept as a slice of its own it cost an allocation, a
// slice header and a time, half as much again for the headers of a packet.
// Whoever uses it guards it.
type recent struct {
	// buf holds the records, each after its head, from first on and around
	// the buffer's end. It grows as it fills, up to the limit.
	buf   []byte
	first int
	used  int
}

// recordHead precedes every record: its time in nanoseconds, and its length.
const recordHead = 8 + 4

// add appends a record of the given parts. The oldest records go to keep
// the buffer within limit bytes, heads included, and so do those that are
// more than window older than the new one. A record that the limit cannot
// hold is not kept.
func (r *recent) add(at time.Time, window time.Duration, limit int, parts ...[]byte) {
	size := recordHead
	for _, part := range parts {
		size += len(part)
	}
	if size > limit {
		return
	}
	for r.used > 0 {
		then, length := r.head(r.first)
		if r.used+size <= limit && at.Sub(then) <= window {
			break
		}
		r.first, r.used = r.wrapped(r.first+recordHead+length), r.used-recordHead-length
	}
	if r.used+size > len(r.buf) {
		// Twice as large, laid out from the beginning.
		grown := make([]byte, min(limit, max(2*len(r.buf), r.used+size, 4<<10)))
		n := copy(grown, r.buf[r.first:min(r.first+r.used, len(r.buf))])
		copy(grown[n:], r.buf[:r.used-n])
		r.buf, r.first = grown, 0
	}
	var head [recordHead]byte
	binary.LittleEndian.PutUint64(head[:], uint64(at.UnixNano()))
	binary.LittleEndian.PutUint32(head[8:], uint32(size-recordHead))
	r.put(head[:])
	for _, part := range parts {
		r.put(part)
	}
}

// since appends the records from a moment on to out, oldest first.
func (r *recent) since(from time.Time, out []byte) []byte {
	found := false
	for at, left := r.first, r.used; left > 0; {
		then, length := r.head(at)
		at = r.wrapped(at + recordHead)
		if found = found || !then.Before(from); found {
			n := min(length, len(r.buf)-at)
			out = append(append(out, r.buf[at:at+n]...), r.buf[:length-n]...)
		}
		at, left = r.wrapped(at+length), left-recordHead-length
	}
	return out
}

// head reads the head of the record at an offset.
func (r *recent) head(at int) (then time.Time, length int) {
	var head [recordHead]byte
	n := copy(head[:], r.buf[at:])
	copy(head[n:], r.buf)
	return time.Unix(0, int64(binary.LittleEndian.Uint64(head[:]))), int(binary.LittleEndian.Uint32(head[8:]))
}

// put writes bytes behind the last record. There is room for them.
func (r *recent) put(p []byte) {
	n := copy(r.buf[r.wrapped(r.first+r.used):], p)
	copy(r.buf, p[n:])
	r.used += len(p)
}

// wrapped is an offset behind the buffer's end, taken around it.
func (r *recent) wrapped(at int) int {
	if at >= len(r.buf) {
		at -= len(r.buf)
	}
	return at
}
