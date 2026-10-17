// Package artifact contains storage values, not credentials or access decisions.
package artifact

import "errors"

const (
	StorageFormat        = "asservat-framed/v1"
	FrameBytes     int64 = 8 << 20
	MaxNativeBytes int64 = 1 << 40
	FramesPerPage        = 256
	MaxFrames            = int(MaxNativeBytes / FrameBytes)
	MaxPages             = MaxFrames / FramesPerPage
	PageBytes      int64 = 256 << 10
	CipherOverhead int64 = 64 << 10
	MaxRootBytes   int64 = 1 << 20
	DeliveryBytes        = 1 << 20
)

var (
	ErrInvalid   = errors.New("invalid artifact storage descriptor")
	ErrLimit     = errors.New("artifact storage limit exceeded")
	ErrIntegrity = errors.New("artifact integrity failure")
)

// Binding is supplied by an accepted immutable acquisition, never a download query.
// The three IDs are opaque canonical UUIDs. MediaType describes the native file.
type Binding struct {
	ClusterID, ArtifactID, AttemptID, MediaType string
}

func uuid(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != "00000000-0000-0000-0000-000000000000"
}

func (b Binding) Validate() error {
	if !uuid(b.ClusterID) || !uuid(b.ArtifactID) || !uuid(b.AttemptID) || len(b.MediaType) < 1 || len(b.MediaType) > 128 {
		return ErrInvalid
	}
	for _, c := range b.MediaType {
		if c < 33 || c > 126 {
			return ErrInvalid
		}
	}
	return nil
}

type Digest [32]byte

// SealedKey is opaque KMS ciphertext. It never contains a clear keyset.
type SealedKey struct{ Reference, Ciphertext string }

type Page struct {
	Number, FirstFrame, FrameCount                   int
	NativeOffset, NativeBytes, DataOffset, DataBytes int64
	IndexOffset, IndexBytes                          int64
	IndexSHA256                                      Digest
}

// Layout lives inside the encrypted detailed manifest. Object identities and
// custody state belong to the separate commit/copy ledger, not this byte codec.
type Layout struct {
	Format                                string
	Binding                               Binding
	NativeBytes, DataBytes, IndexBytes    int64
	NativeSHA256, DataSHA256, IndexSHA256 Digest
	DataKey, IndexKey                     SealedKey
	Pages                                 []Page
}

// WorstCase covers ciphertext data and index streams. The caller separately
// reserves the manifest, commit envelope, attempts, object slots and replicas.
func WorstCase(nativeLimit int64) (data, index int64, err error) {
	if nativeLimit < 0 || nativeLimit > MaxNativeBytes {
		return 0, 0, ErrLimit
	}
	n := (nativeLimit + FrameBytes - 1) / FrameBytes
	if n == 0 {
		n = 1
	}
	return nativeLimit + n*CipherOverhead, ((n + FramesPerPage - 1) / FramesPerPage) * (PageBytes + CipherOverhead), nil
}

func validKey(k SealedKey) bool {
	return len(k.Reference) > 0 && len(k.Reference) <= 256 && len(k.Ciphertext) > 0 && len(k.Ciphertext) <= 16384
}

func (l Layout) Validate() error {
	if l.Format != StorageFormat || l.Binding.Validate() != nil || !validKey(l.DataKey) || !validKey(l.IndexKey) {
		return ErrInvalid
	}
	dataMax, indexMax, err := WorstCase(l.NativeBytes)
	if err != nil || l.DataBytes < 1 || l.DataBytes > dataMax || l.IndexBytes < 1 || l.IndexBytes > indexMax || len(l.Pages) < 1 || len(l.Pages) > MaxPages {
		return ErrInvalid
	}
	frames := int((l.NativeBytes + FrameBytes - 1) / FrameBytes)
	if frames == 0 {
		frames = 1
	}
	if len(l.Pages) != (frames+FramesPerPage-1)/FramesPerPage {
		return ErrInvalid
	}
	var native, data, index int64
	var count int
	for i, p := range l.Pages {
		n := min(FramesPerPage, frames-count)
		wantNative := min(int64(n)*FrameBytes, l.NativeBytes-native)
		if p.Number != i || p.FirstFrame != count || p.FrameCount != n || p.NativeOffset != native || p.NativeBytes != wantNative || p.DataOffset != data || p.DataBytes < 1 || p.DataBytes > wantNative+int64(n)*CipherOverhead || p.IndexOffset != index || p.IndexBytes < 1 || p.IndexBytes > PageBytes+CipherOverhead {
			return ErrInvalid
		}
		native += p.NativeBytes
		data += p.DataBytes
		index += p.IndexBytes
		count += n
	}
	if native != l.NativeBytes || data != l.DataBytes || index != l.IndexBytes || count != frames {
		return ErrInvalid
	}
	return nil
}
