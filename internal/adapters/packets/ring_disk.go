package packets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
)

// ErrMediumUnavailable: the encrypted-disk medium could not seal or read a
// segment (for example a full volume); the ring closes (ADR-278).
var ErrMediumUnavailable = errors.New("ring medium unavailable")

// sealedSegments keeps finished ring segments on disk, each sealed with an
// AES-256-GCM key that exists only in this process (ADR-278). Losing the key
// (close, restart, crash) makes every file unreadable; nothing is written in
// plaintext. Not safe for concurrent use; the ring's mutex serializes it.
type sealedSegments struct {
	dir  string
	aead cipher.AEAD
}

func newSealedSegments(parent string) (*sealedSegments, error) {
	if parent == "" {
		return nil, ErrMediumUnavailable
	}
	dir, err := os.MkdirTemp(parent, "ring-")
	if err != nil {
		return nil, ErrMediumUnavailable
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		_ = os.RemoveAll(dir)
		return nil, ErrMediumUnavailable
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, ErrMediumUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, ErrMediumUnavailable
	}
	return &sealedSegments{dir: dir, aead: aead}, nil
}

// diskBlock is the allocation unit assumed for the ring volume; files are
// charged in whole blocks so the kubelet's du-based limit is never reached.
const diskBlock = 4096

// SealedRingBytes is the most a disk ring can occupy on its volume: every
// segment sealed with its nonce and tag, rounded up to whole blocks, plus the
// ring's directory.
func SealedRingBytes(l RingLimits) int64 {
	file := (l.SegmentBytes + 12 + 16 + diskBlock - 1) / diskBlock * diskBlock
	return int64(l.MaxSegments)*file + diskBlock
}

func (s *sealedSegments) path(i int) string { return filepath.Join(s.dir, strconv.Itoa(i)) }

// aad binds a sealed body to its slot and its in-memory header, so a file can
// be neither moved to another slot nor paired with another header.
func aad(i int, header []byte) []byte {
	out := binary.LittleEndian.AppendUint32(nil, uint32(i))
	return append(out, header...)
}

func (s *sealedSegments) seal(i int, header, body []byte) error {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return ErrMediumUnavailable
	}
	out := s.aead.Seal(nonce, nonce, body, aad(i, header))
	f, err := os.OpenFile(s.path(i), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return ErrMediumUnavailable
	}
	_, werr := f.Write(out)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(s.path(i))
		return ErrMediumUnavailable
	}
	return nil
}

func (s *sealedSegments) open(i int, header []byte) ([]byte, error) {
	raw, err := os.ReadFile(s.path(i))
	n := s.aead.NonceSize()
	if err != nil || len(raw) < n {
		return nil, ErrMediumUnavailable
	}
	body, err := s.aead.Open(nil, raw[:n], raw[n:], aad(i, header))
	if err != nil {
		return nil, ErrMediumUnavailable
	}
	return body, nil
}

func (s *sealedSegments) remove(i int) { _ = os.Remove(s.path(i)) }

func (s *sealedSegments) close() {
	_ = os.RemoveAll(s.dir)
	s.aead = nil
}
