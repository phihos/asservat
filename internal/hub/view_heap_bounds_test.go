package hub

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"runtime"
	"testing"
)

// A heap dump is a file that a workload wrote or an agent sent. What it
// says of its own sizes is not taken for memory before the bytes are
// there: a few dozen bytes that claim gigabytes end as a dump that is cut
// off, not as a hub that is out of memory.
func TestAHeapDumpsClaimsAreNotAllocated(t *testing.T) {
	u := func(values ...any) []byte {
		var b bytes.Buffer
		for _, v := range values {
			binary.Write(&b, binary.BigEndian, v)
		}
		return b.Bytes()
	}
	head := append([]byte("JAVA PROFILE 1.0.2\x00"), u(uint32(8), uint64(0))...)
	// A string that is really there, and long, is not kept whole either:
	// a dump made of strings would be held in memory at its full size.
	long := append(u(byte(0x01), uint32(0), uint32(8+32<<20), uint64(1)), bytes.Repeat([]byte("x"), 32<<20)...)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := summarizeHeap(io.MultiReader(bytes.NewReader(head), bytes.NewReader(long), bytes.NewReader(long), bytes.NewReader(long), bytes.NewReader(long))); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 16<<20 {
		t.Errorf("four strings of 32 MiB took %d MiB", grown>>20)
	}
	for name, record := range map[string][]byte{
		"a string of 4 GiB":             append(u(byte(0x01), uint32(0), uint32(0xFFFFFFFF), uint64(1)), "short"...),
		"a string shorter than its ID":  u(byte(0x01), uint32(0), uint32(3), uint64(1)),
		"a stack of 500 million frames": u(byte(0x05), uint32(0), uint32(12), uint32(1), uint32(1), uint32(500_000_000), uint64(1)),
	} {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := summarizeHeap(bytes.NewReader(append(bytes.Clone(head), record...)))
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Errorf("%s was read as a dump", name)
		}
		if grown := after.TotalAlloc - before.TotalAlloc; grown > 64<<20 {
			t.Errorf("%s took %d MiB to refuse", name, grown>>20)
		}
	}
}

// A profile is held in memory to be shown, and a compressed one unpacks
// there: one that unpacks to more than the hub holds is refused while it
// unpacks, not after.
func TestAProfileThatUnpacksWithoutEndIsRefused(t *testing.T) {
	var packed bytes.Buffer
	z := gzip.NewWriter(&packed)
	zeros := make([]byte, 1<<20)
	for range 2 * inMemory >> 20 {
		z.Write(zeros)
	}
	z.Close()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := unpackedProfile(packed.Bytes())
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("it was unpacked")
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 3*inMemory {
		t.Errorf("refusing it took %d MiB", grown>>20)
	}
	// One of an ordinary size is taken as it is, packed or not.
	for _, profile := range [][]byte{[]byte("plain"), gz([]byte("packed"))} {
		if got, err := unpackedProfile(profile); err != nil || (string(got) != "plain" && string(got) != "packed") {
			t.Fatal(string(got), err)
		}
	}
}

func gz(b []byte) []byte {
	var packed bytes.Buffer
	z := gzip.NewWriter(&packed)
	z.Write(b)
	z.Close()
	return packed.Bytes()
}
