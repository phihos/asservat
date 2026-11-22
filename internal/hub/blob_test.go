package hub

import (
	"bytes"
	"crypto/rand"
	"io"
	"runtime"
	"testing"
)

func TestEncryptRoundTripAndTamper(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	for _, size := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 17} {
		plain := make([]byte, size)
		rand.Read(plain)
		var sealed, opened bytes.Buffer
		if err := encrypt(&sealed, bytes.NewReader(plain), key); err != nil {
			t.Fatal(size, err)
		}
		if err := decrypt(&opened, bytes.NewReader(sealed.Bytes()), key); err != nil || !bytes.Equal(opened.Bytes(), plain) {
			t.Fatal("round trip", size, err)
		}
		if size > 0 && bytes.Contains(sealed.Bytes(), plain[:min(size, 32)]) && size >= 32 {
			t.Fatal("plaintext stored", size)
		}
		// A flipped bit, a missing tail and a missing last chunk all fail.
		flipped := bytes.Clone(sealed.Bytes())
		flipped[len(flipped)-1] ^= 1
		if decrypt(&bytes.Buffer{}, bytes.NewReader(flipped), key) == nil {
			t.Fatal("tampered stream opened", size)
		}
		if decrypt(&bytes.Buffer{}, bytes.NewReader(sealed.Bytes()[:sealed.Len()-1]), key) == nil {
			t.Fatal("truncated stream opened", size)
		}
		if size > chunkSize {
			first := 4 + chunkSize + 16
			if decrypt(&bytes.Buffer{}, bytes.NewReader(sealed.Bytes()[:first]), key) == nil {
				t.Fatal("stream without its last chunk opened", size)
			}
		}
	}
}

func TestWrapKey(t *testing.T) {
	master, key := make([]byte, 32), make([]byte, 32)
	rand.Read(master)
	rand.Read(key)
	wrapped, err := wrapKey(master, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unwrapKey(master, wrapped)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("unwrap", err)
	}
	master[0] ^= 1
	if _, err := unwrapKey(master, wrapped); err == nil {
		t.Fatal("unwrapped with another master key")
	}
}

// Sealing and opening a file takes memory for a few chunks, however long
// the file is: the buffers serve every chunk. (Found with a memory growth
// profile of the hub, which took new memory for each chunk of a download.)
func TestEncryptionReusesItsBuffers(t *testing.T) {
	key := make([]byte, 32)
	plain := make([]byte, 64*chunkSize)
	var sealed bytes.Buffer
	sealed.Grow(len(plain) + 64*32)
	allocated := func(run func()) uint64 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		run()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	if got := allocated(func() {
		if err := encrypt(&sealed, bytes.NewReader(plain), key); err != nil {
			t.Fatal(err)
		}
	}); got > 4*chunkSize {
		t.Errorf("sealing 64 chunks allocated %d bytes, more than 4 chunks", got)
	}
	if got := allocated(func() {
		if err := decrypt(io.Discard, bytes.NewReader(sealed.Bytes()), key); err != nil {
			t.Fatal(err)
		}
	}); got > 4*chunkSize {
		t.Errorf("opening 64 chunks allocated %d bytes, more than 4 chunks", got)
	}
}
