package feasibility

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/klauspost/compress/zstd"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"io"
	"testing"
)

// This is an in-memory composition experiment, not a persisted format implementation.
// Each frame is a complete library-generated streaming ciphertext, not a custom AEAD segment.
func TestIndependentFramesForNativeRanges(t *testing.T) {
	const chunk = 1 << 20
	plain := make([]byte, 3*chunk+11)
	if _, e := rand.Read(plain); e != nil {
		t.Fatal(e)
	}
	key, e := keyset.NewHandle(streamingaead.AES256GCMHKDF1MBKeyTemplate())
	if e != nil {
		t.Fatal(e)
	}
	a, e := streamingaead.New(key)
	if e != nil {
		t.Fatal(e)
	}
	var object bytes.Buffer
	starts := []int{}
	lengths := []int{}
	aad := func(i int) []byte {
		return []byte(fmt.Sprintf("synthetic-artifact/version/chunk/%d/native-offset/%d", i, i*chunk))
	}
	for i, off := 0, 0; off < len(plain); i, off = i+1, off+chunk {
		end := min(off+chunk, len(plain))
		starts = append(starts, object.Len())
		w, e := a.NewEncryptingWriter(&object, aad(i))
		if e != nil {
			t.Fatal(e)
		}
		z, e := zstd.NewWriter(w, zstd.WithEncoderConcurrency(1))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = z.Write(plain[off:end]); e != nil {
			t.Fatal(e)
		}
		if e = z.Close(); e != nil {
			t.Fatal(e)
		}
		if e = w.Close(); e != nil {
			t.Fatal(e)
		}
		lengths = append(lengths, object.Len()-starts[i])
	}
	decode := func(i int, cipher []byte) ([]byte, error) {
		r, e := a.NewDecryptingReader(bytes.NewReader(cipher), aad(i))
		if e != nil {
			return nil, e
		}
		z, e := zstd.NewReader(r, zstd.WithDecoderMaxMemory(16<<20), zstd.WithDecoderConcurrency(1))
		if e != nil {
			return nil, e
		}
		defer z.Close()
		return io.ReadAll(io.LimitReader(z, chunk+1))
	}
	start, end := chunk+37, 2*chunk+19
	var got bytes.Buffer
	readBytes := 0
	for i := start / chunk; i <= (end-1)/chunk; i++ {
		c := object.Bytes()[starts[i] : starts[i]+lengths[i]]
		readBytes += len(c)
		p, e := decode(i, c)
		if e != nil {
			t.Fatal(e)
		}
		lo := max(start-i*chunk, 0)
		hi := min(end-i*chunk, len(p))
		got.Write(p[lo:hi])
	}
	if !bytes.Equal(got.Bytes(), plain[start:end]) {
		t.Fatal("native range mismatch")
	}
	if readBytes >= object.Len() {
		t.Fatal("range read unexpectedly read whole object")
	}
	c := object.Bytes()[starts[1] : starts[1]+lengths[1]]
	if _, e := decode(0, c); e == nil {
		t.Fatal("reordered frame accepted")
	}
	bad := bytes.Clone(c)
	bad[len(bad)/2] ^= 128
	if _, e := decode(1, bad); e == nil {
		t.Fatal("tamper accepted")
	}
	if _, e := decode(1, c[:len(c)-1]); e == nil {
		t.Fatal("truncated frame accepted")
	}
	t.Logf("native bytes=%d object bytes=%d frames=%d range bytes=%d ciphertext read=%d; encrypted index, object store and authorization NOT tested", len(plain), object.Len(), len(starts), got.Len(), readBytes)
}
