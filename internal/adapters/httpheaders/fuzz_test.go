package httpheaders

import (
	"bytes"
	"testing"
	"time"
)

// FuzzProjector drives one connection whose streams start with fuzzed bytes
// and continue with a message carrying the secret in its credentials and
// body; segment sizes, order, duplication and truncation come from the
// input. It also feeds the input as a raw frame. The projection must stay
// within its bounds, release all state and never contain the secret.
func FuzzProjector(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), []byte{3, 7, 0, 1})
	f.Add([]byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"), []byte("HTTP/1.1 100 Continue\r\n\r\n"), []byte{200, 1, 1, 9})
	f.Add([]byte{0x16, 3, 1}, []byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"), []byte{0})
	f.Add([]byte("HEAD / HTTP/1.1\r\n\r\nCONNECT a:1 HTTP/1.1\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"), []byte{5, 255, 128})
	f.Fuzz(func(t *testing.T, client, server, shape []byte) {
		if len(client) > 4096 || len(server) > 4096 || len(shape) > 64 {
			return
		}
		tail := "GET /" + secret + " HTTP/1.1\r\nHost: h\r\nCookie: " + secret + "\r\nContent-Length: 13\r\n\r\n" + secret
		rtail := "HTTP/1.1 200 OK\r\nSet-Cookie: " + secret + "\r\nContent-Length: 13\r\n\r\n" + secret
		l := smallLimits()
		l.MaxFlows = 1
		fd := newFeeder(t, l)
		c := newConn(44000)
		var frames [][]byte
		frames = append(frames, c.handshake()...)
		sizes := []int{1}
		for _, b := range shape {
			sizes = append(sizes, int(b)%1400+1)
		}
		cs := c.data(true, append(append([]byte(nil), client...), tail...), sizes...)
		ss := c.data(false, append(append([]byte(nil), server...), rtail...), sizes[1:]...)
		for i := 0; i < max(len(cs), len(ss)); i++ {
			if i < len(cs) {
				frames = append(frames, cs[i])
			}
			if i < len(ss) {
				frames = append(frames, ss[i])
			}
		}
		for i, b := range shape {
			j := int(b) % len(frames)
			switch i % 4 {
			case 0: // swap
				k := (j + 1) % len(frames)
				frames[j], frames[k] = frames[k], frames[j]
			case 1: // duplicate
				frames = append(frames, frames[j])
			case 2: // truncate (keeps the original wire length below)
				if len(frames[j]) > 60 {
					frames[j] = frames[j][:len(frames[j])-1]
				}
			}
		}
		for _, fr := range frames {
			fd.at = fd.at.Add(time.Millisecond)
			fd.p.Add(fr, uint32(len(fr)+1), fd.at)
			if fd.p.readers.used > fd.p.readers.limit || fd.p.active > l.MaxFlows {
				t.Fatalf("bound exceeded: readers %d/%d flows %d", fd.p.readers.used, fd.p.readers.limit, fd.p.active)
			}
		}
		fd.p.Add(client, uint32(len(client)), fd.at)
		pr, n, b := fd.close(t)
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("secret in projection: %s", b)
		}
		if len(pr.Records) > maxRecords || n.Records != uint64(len(pr.Records)) || n.Frames != uint64(len(frames)+1) {
			t.Fatalf("records %d counters %+v", len(pr.Records), n)
		}
	})
}
