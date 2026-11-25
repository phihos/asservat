package holes

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// A core of a process that maps memory it never touched is mostly holes:
// gigabytes by its size, megabytes on the disk. Packed, it is its data
// with the places they belong at, and unpacks to the same bytes.
func TestPackedFileUnpacksToTheSameBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const size = 3 << 30
	parts := map[int64]string{0: "\x7fELF the start", 1 << 30: "in the middle", size - 7: "the end"}
	for at, text := range parts {
		if _, err := f.WriteAt([]byte(text), at); err != nil {
			t.Fatal(err)
		}
	}
	if !Sparse(f) {
		t.Skip("this file system keeps no holes")
	}
	var packed bytes.Buffer
	if _, err := io.Copy(&packed, Pack(f)); err != nil {
		t.Fatal(err)
	}
	if packed.Len() > 1<<20 {
		t.Fatalf("3 GiB of holes pack to %d bytes", packed.Len())
	}
	// Into a file, the holes are holes again; into a stream, zeros.
	out, err := os.Create(filepath.Join(t.TempDir(), "unpacked"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if n, err := Unpack(out, bytes.NewReader(packed.Bytes())); err != nil || n != size {
		t.Fatal(n, err)
	}
	if info, _ := out.Stat(); info.Size() != size || !Sparse(out) {
		t.Fatal("the unpacked file is not the size of the packed one, or holds its holes as zeros")
	}
	for at, text := range parts {
		got := make([]byte, len(text))
		if _, err := out.ReadAt(got, at); err != nil || string(got) != text {
			t.Fatalf("at %d: %q, %v", at, got, err)
		}
	}
	sum := sha256.New()
	if n, err := Unpack(sum, bytes.NewReader(packed.Bytes())); err != nil || n != size {
		t.Fatal(n, err)
	}
	f.Seek(0, io.SeekStart)
	whole := sha256.New()
	io.Copy(whole, f)
	if !bytes.Equal(sum.Sum(nil), whole.Sum(nil)) {
		t.Fatal("unpacked to a stream, the bytes are not the file's")
	}
}

// What is unpacked comes from a cluster's agent and is not trusted.
func TestWhatIsNoPackedFileIsRefused(t *testing.T) {
	record := func(at, length uint64, data string) []byte {
		b := binary.BigEndian.AppendUint64(nil, at)
		return append(binary.BigEndian.AppendUint64(b, length), data...)
	}
	for name, packed := range map[string][]byte{
		"no packed file":                []byte("\x7fELF a core as it is"),
		"data that goes back":           bytes.Join([][]byte{[]byte(magic), record(100, 3, "abc"), record(50, 3, "abc"), record(200, 0, "")}, nil),
		"data over one another":         bytes.Join([][]byte{[]byte(magic), record(0, 3, "abc"), record(2, 3, "abc"), record(200, 0, "")}, nil),
		"an end before the data's":      bytes.Join([][]byte{[]byte(magic), record(100, 3, "abc"), record(50, 0, "")}, nil),
		"no end":                        bytes.Join([][]byte{[]byte(magic), record(0, 3, "abc")}, nil),
		"data cut short":                bytes.Join([][]byte{[]byte(magic), record(0, 30, "abc")}, nil),
		"something after the end":       bytes.Join([][]byte{[]byte(magic), record(3, 0, ""), []byte("more")}, nil),
		"a size beyond any process's":   bytes.Join([][]byte{[]byte(magic), record(1<<60, 0, "")}, nil),
		"a length that wraps the place": bytes.Join([][]byte{[]byte(magic), record(1<<40, ^uint64(0), "abc"), record(1<<41, 0, "")}, nil),
	} {
		if _, err := Unpack(io.Discard, bytes.NewReader(packed)); err == nil {
			t.Errorf("%s was unpacked", name)
		}
	}
}

// A reader of a part of the file, as a tool that reads a window of it,
// passes over a hole without being written its zeros.
func TestAHoleIsPassedOverAtOnce(t *testing.T) {
	record := func(at, length uint64, data string) []byte {
		b := binary.BigEndian.AppendUint64(nil, at)
		return append(binary.BigEndian.AppendUint64(b, length), data...)
	}
	packed := bytes.Join([][]byte{[]byte(magic), record(0, 3, "abc"), record(200<<40, 3, "xyz"), record(200<<40+3, 0, "")}, nil)
	var past passed
	if n, err := Unpack(&past, bytes.NewReader(packed)); err != nil || n != 200<<40+3 || past.skipped != 200<<40-3 || past.written.String() != "abcxyz" {
		t.Fatal(n, err, past.skipped, past.written.String())
	}
}

type passed struct {
	written bytes.Buffer
	skipped int64
}

func (p *passed) Write(b []byte) (int, error) { return p.written.Write(b) }
func (p *passed) Skip(zeros int64) error      { p.skipped += zeros; return nil }
