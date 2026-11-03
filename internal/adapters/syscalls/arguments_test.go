package syscalls

import (
	"encoding/binary"
	"testing"
)

func TestArgumentDefinitionsBoundReads(t *testing.T) {
	for _, buffers := range []bool{false, true} {
		ds, err := ArgumentDefinitions([]string{"read", "write", "openat", "close", "pread64", "pwrite64"}, buffers, 256)
		if err != nil || len(ds) != 6 || ArgumentMaxProbeBytes(ds) != 512 {
			t.Fatal(ds, err)
		}
		for _, d := range ds {
			if d.Name != "openat" && !buffers && d.Lengths != ([6]uint64{}) {
				t.Fatal("buffers disabled but read configured")
			}
		}
	}
	for _, names := range [][]string{{"read"}, {"write"}, {"openat"}} {
		if _, err := ArgumentDefinitions(names, true, 128); err != nil {
			t.Fatal("actual128-byte bound incorrectly refused", err)
		}
		if _, err := ArgumentDefinitions(names, true, 127); err == nil {
			t.Fatal("unqualified small bound accepted")
		}
	}
	if ds, err := ArgumentDefinitions([]string{"read", "write"}, false, 1); err != nil || ArgumentMaxProbeBytes(ds) != 256 {
		t.Fatal(ds, err)
	}
	for _, names := range [][]string{nil, {"read", "read"}, {"connect"}, {"mmap"}, {"all"}} {
		if _, err := ArgumentDefinitions(names, true, 4096); err == nil {
			t.Fatal(names)
		}
	}
	a, _ := ArgumentDefinitions([]string{"write", "read"}, true, 256)
	b, _ := ArgumentDefinitions([]string{"read", "write"}, true, 4096)
	if ArgumentDefinitionDigest(a) != ArgumentDefinitionDigest(b) {
		t.Fatal("selection order or redundant cap changes fixed table")
	}
}

func argumentBase(typ uint32) []byte {
	b := make([]byte, 164)
	le := binary.LittleEndian
	le.PutUint32(b, typ)
	le.PutUint32(b[72:], 50)
	le.PutUint32(b[104:], 51)
	le.PutUint32(b[108:], 1)
	le.PutUint64(b[56:], 300)
	le.PutUint64(b[64:], 400)
	le.PutUint64(b[112:], 200)
	le.PutUint64(b[120:], 100)
	return b
}
func TestArgumentDecoderUsesClosedIdentityAndNoPointers(t *testing.T) {
	ds, _ := ArgumentDefinitions([]string{"read"}, true, 256)
	b := argumentBase(EventEnter)
	le := binary.LittleEndian
	for i := 0; i < 6; i++ {
		le.PutUint64(b[8+i*8:], uint64(900+i))
	}
	r, err := DecodeArgumentRecord(b, ds)
	if err != nil || r.TID != 51 || r.Scalar[1] != 0 || r.Scalar[0] != 900 || r.Scalar[2] != 902 || r.TaskStart != 200 {
		t.Fatal(r, err)
	}
	for _, offset := range []int{104, 108, 112, 120} {
		bad := append([]byte(nil), b...)
		clear(bad[offset : offset+4])
		if _, err := DecodeArgumentRecord(bad, ds); err == nil {
			t.Fatal(offset)
		}
	}
	b = argumentBase(EventExit)
	b[96] = 1
	le.PutUint64(b[8:], ^uint64(0))
	r, err = DecodeArgumentRecord(b, ds)
	if err != nil || r.Ret != -1 || r.ScalarMask != 0 {
		t.Fatal(r, err)
	}
}
func TestArgumentContinuationPreservesFaultAndTruncation(t *testing.T) {
	b := make([]byte, 167)
	le := binary.LittleEndian
	le.PutUint32(b, EventCont)
	le.PutUint64(b[136:], 300)
	le.PutUint32(b[156:], 51)
	b[152] = 1
	b[154] = 1
	copy(b[4:], []byte("secret trailing bytes"))
	r, err := DecodeArgumentRecord(b, nil)
	if err != nil || len(r.Data) != 0 {
		t.Fatal("zero read retained trailing bytes", r, err)
	}
	le.PutUint64(b[144:], 3)
	r, err = DecodeArgumentRecord(b, nil)
	if err != nil || string(r.Data) != "sec" || r.Truncated {
		t.Fatal(r, err)
	}
	b[153] = 1
	r, err = DecodeArgumentRecord(b, nil)
	if err != nil || !r.Failed || r.Data != nil {
		t.Fatal("fault leaked bytes", r, err)
	}
	b[153] = 0
	le.PutUint64(b[144:], 129)
	if _, err = DecodeArgumentRecord(b, nil); err == nil {
		t.Fatal("oversized continuation")
	}
	le.PutUint64(b[144:], ArgumentStringLength)
	clear(b[4:132])
	copy(b[4:], "path")
	r, err = DecodeArgumentRecord(b, nil)
	if err != nil || string(r.Data) != "path" || r.Truncated {
		t.Fatal(r, err)
	}
}
func FuzzArgumentRecord(f *testing.F) {
	f.Add(argumentBase(EventEnter))
	f.Add([]byte{1, 2, 3})
	ds, _ := ArgumentDefinitions([]string{"read", "write", "openat", "close"}, true, 256)
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeArgumentRecord(b, ds)
		if err == nil && len(r.Data) > 128 {
			t.Fatal("unbounded data")
		}
	})
}
func TestArgumentDecoderInterleavedThreadsAndReuse(t *testing.T) {
	d, err := NewArgumentDecoder([]string{"write"}, true, 256, 2)
	if err != nil {
		t.Fatal(err)
	}
	le := binary.LittleEndian
	base := func(tid uint32, mono, start uint64) []byte {
		b := argumentBase(EventEnter)
		le.PutUint16(b[78:], 1)
		le.PutUint32(b[104:], tid)
		le.PutUint64(b[56:], mono)
		le.PutUint64(b[112:], start)
		b[96] = 1
		return b
	}
	cont := func(tid uint32, mono uint64) []byte {
		b := make([]byte, 160)
		le.PutUint32(b, EventCont)
		le.PutUint32(b[156:], tid)
		le.PutUint64(b[136:], mono)
		le.PutUint64(b[144:], 1)
		b[152] = 1
		b[4] = 'x'
		return b
	}
	for _, b := range [][]byte{base(51, 300, 200), base(52, 300, 201)} {
		if p, e := d.Add(b); p != nil || e != nil {
			t.Fatal(p, e)
		}
	}
	for _, tid := range []uint32{52, 51} {
		p, e := d.Add(cont(tid, 300))
		if e != nil || p == nil || p.Event.TID != tid || p.Event.PID != 50 || string(p.Memory.Data) != "x" {
			t.Fatal(p, e)
		}
	}
	_, _ = d.Add(base(51, 301, 200))
	_, _ = d.Add(base(51, 302, 250))
	if p, e := d.Add(cont(51, 301)); p != nil || e != nil {
		t.Fatal("old thread continuation attached", p, e)
	}
	p, e := d.Add(cont(51, 302))
	if e != nil || p == nil || p.Event.TaskStart != 250 {
		t.Fatal(p, e)
	}
	if gaps := d.Flush(); gaps != 2 {
		t.Fatal(gaps)
	}
}
func TestArgumentDecoderUsesActualCountForBufferTruncation(t *testing.T) {
	for _, count := range []uint64{128, 129} {
		d, _ := NewArgumentDecoder([]string{"write"}, true, 128, 1)
		b := argumentBase(EventEnter)
		binary.LittleEndian.PutUint16(b[78:], 1)
		binary.LittleEndian.PutUint64(b[24:], count)
		b[96] = 1
		if _, err := d.Add(b); err != nil {
			t.Fatal(err)
		}
		c := make([]byte, 160)
		binary.LittleEndian.PutUint32(c, EventCont)
		binary.LittleEndian.PutUint64(c[136:], 300)
		binary.LittleEndian.PutUint64(c[144:], 128)
		binary.LittleEndian.PutUint32(c[156:], 51)
		c[152] = 1
		p, err := d.Add(c)
		if err != nil || p == nil || p.Memory.Truncated != (count > 128) {
			t.Fatal(count, p, err)
		}
	}
}
