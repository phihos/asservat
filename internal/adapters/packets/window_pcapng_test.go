package packets

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
)

func TestEncodeWindowPreservesSourceBytesAndTimes(t *testing.T) {
	r, now := ringFixture(t, nil)
	full := ringAdd(t, r, now, now)
	s := ringCopy(t, r, now, now, now)
	out, count, err := EncodeWindow(t.Context(), s, 65536, now, now)
	if err != nil || count.Retained != 1 || cap(out) != 65536 {
		t.Fatal(count, cap(out), err)
	}
	if n, e := CheckHeadersOnly(bytes.NewReader(out)); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(out), pcapgo.NgReaderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	data, info, err := reader.ReadPacketData()
	if err != nil || !info.Timestamp.Equal(now) || info.Length != len(full) || !bytes.Equal(data, full[:len(data)]) {
		t.Fatal(info, err)
	}
	if r.State().Packets.Seen != 1 {
		t.Fatal("encoding charged another observation")
	}
}

type repeatedWindowPacket struct {
	p RingPacket
	n int
}

func (r *repeatedWindowPacket) Next(p *RingPacket) error {
	if r.n == 0 {
		return io.EOF
	}
	*p = r.p
	r.n--
	return nil
}
func TestEncodeWindowCapsWholeBlocksAndRejectsLateRecord(t *testing.T) {
	now := time.Now().UTC()
	frame := tcp4(t, true)
	p := RingPacket{At: now, Wire: uint32(len(frame)), Length: len(frame) - len(marker)}
	// Obtain the exact sanitized header using the existing ring path.
	r, start := ringFixture(t, nil)
	ringAdd(t, r, start, start)
	snapshot := ringCopy(t, r, start, start, start)
	if err := snapshot.Next(&p); err != nil {
		t.Fatal(err)
	}
	out, c, err := EncodeWindow(t.Context(), &repeatedWindowPacket{p, 1000}, 4096, p.At, p.At)
	if err != nil || len(out) > 4096 || c.OutputFull == 0 || c.Retained == 0 || c.Seen != 1000 {
		t.Fatal(len(out), c, err)
	}
	if n, e := CheckHeadersOnly(bytes.NewReader(out)); e != nil || uint64(n) != c.Retained {
		t.Fatal(n, c, e)
	}
	p.At = p.At.Add(time.Second)
	if _, _, e := EncodeWindow(t.Context(), &repeatedWindowPacket{p, 1}, 4096, start, start); !errors.Is(e, ErrInvalid) {
		t.Fatal("accepted newer packet", e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, e := EncodeWindow(ctx, &repeatedWindowPacket{p, 1}, 4096, start, start); e == nil {
		t.Fatal("ignored cancellation")
	}
}
