package objectstore

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestSnapshotNativeReaderVerifiesExactBytesBeforeEOF(t *testing.T) {
	native := []byte("synthetic native bytes")
	digest := artifact.Digest(sha256.Sum256(native))
	for name, edit := range map[string]func(*snapshotNativeReader){
		"exact":      func(*snapshotNativeReader) {},
		"wrong hash": func(r *snapshotNativeReader) { r.expected[0] ^= 1 },
		"truncated":  func(r *snapshotNativeReader) { r.remaining++ },
		"trailing":   func(r *snapshotNativeReader) { r.remaining-- },
	} {
		t.Run(name, func(t *testing.T) {
			r := &snapshotNativeReader{src: bytes.NewReader(native), hash: sha256.New(), expected: digest, remaining: int64(len(native))}
			edit(r)
			out, err := io.ReadAll(r)
			if name == "exact" {
				if err != nil || !r.verified || !bytes.Equal(out, native) {
					t.Fatal("lost native stream", err, r.verified)
				}
			} else if err == nil || r.verified {
				t.Fatal("unverified native stream accepted", err, r.verified)
			}
		})
	}
}
