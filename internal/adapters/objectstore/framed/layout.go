package framed

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"io"

	"asservat.local/asservat/internal/domain/artifact"
)

// The persistent DTO is deliberately separate from the domain representation.
// These bytes belong inside an authenticated encrypted detailed manifest.
type bindingDTO struct {
	ClusterID  string `json:"clusterID"`
	ArtifactID string `json:"artifactID"`
	AttemptID  string `json:"attemptID"`
	MediaType  string `json:"mediaType"`
}
type keyDTO struct {
	Reference  string `json:"reference"`
	Ciphertext string `json:"ciphertext"`
}
type pageDTO struct {
	Number       int    `json:"number"`
	FirstFrame   int    `json:"firstFrame"`
	FrameCount   int    `json:"frameCount"`
	NativeOffset int64  `json:"nativeOffset"`
	NativeBytes  int64  `json:"nativeBytes"`
	DataOffset   int64  `json:"dataOffset"`
	DataBytes    int64  `json:"dataBytes"`
	IndexOffset  int64  `json:"indexOffset"`
	IndexBytes   int64  `json:"indexBytes"`
	IndexSHA256  string `json:"indexSHA256"`
}
type layoutDTO struct {
	Format       string     `json:"format"`
	Binding      bindingDTO `json:"binding"`
	NativeBytes  int64      `json:"nativeBytes"`
	DataBytes    int64      `json:"dataBytes"`
	IndexBytes   int64      `json:"indexBytes"`
	NativeSHA256 string     `json:"nativeSHA256"`
	DataSHA256   string     `json:"dataSHA256"`
	IndexSHA256  string     `json:"indexSHA256"`
	DataKey      keyDTO     `json:"dataKey"`
	IndexKey     keyDTO     `json:"indexKey"`
	Pages        []pageDTO  `json:"pages"`
}

func hashString(h artifact.Digest) string { return hex.EncodeToString(h[:]) }
func parseHash(s string) (artifact.Digest, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 || hex.EncodeToString(b) != s {
		return artifact.Digest{}, artifact.ErrInvalid
	}
	var h artifact.Digest
	copy(h[:], b)
	return h, nil
}

func MarshalLayout(l artifact.Layout) ([]byte, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	v := layoutDTO{Format: l.Format, Binding: bindingDTO{l.Binding.ClusterID, l.Binding.ArtifactID, l.Binding.AttemptID, l.Binding.MediaType}, NativeBytes: l.NativeBytes, DataBytes: l.DataBytes, IndexBytes: l.IndexBytes, NativeSHA256: hashString(l.NativeSHA256), DataSHA256: hashString(l.DataSHA256), IndexSHA256: hashString(l.IndexSHA256), DataKey: keyDTO{l.DataKey.Reference, l.DataKey.Ciphertext}, IndexKey: keyDTO{l.IndexKey.Reference, l.IndexKey.Ciphertext}}
	for _, p := range l.Pages {
		v.Pages = append(v.Pages, pageDTO{p.Number, p.FirstFrame, p.FrameCount, p.NativeOffset, p.NativeBytes, p.DataOffset, p.DataBytes, p.IndexOffset, p.IndexBytes, hashString(p.IndexSHA256)})
	}
	b, err := json.Marshal(v)
	if int64(len(b)) > artifact.MaxRootBytes {
		return nil, artifact.ErrLimit
	}
	return b, err
}

func ParseLayout(b []byte, expected artifact.Binding) (artifact.Layout, error) {
	if len(b) == 0 || int64(len(b)) > artifact.MaxRootBytes || expected.Validate() != nil {
		return artifact.Layout{}, artifact.ErrInvalid
	}
	// Canonicalization rejects duplicate keys and invalid UTF-8. Decode original
	// bytes so fractional/rounded numbers cannot become accepted integer fields.
	canonical := jsontext.Value(append([]byte(nil), b...))
	if canonical.Canonicalize() != nil {
		return artifact.Layout{}, artifact.ErrInvalid
	}
	if err := layoutFields(b); err != nil {
		return artifact.Layout{}, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var v layoutDTO
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF {
		return artifact.Layout{}, artifact.ErrInvalid
	}
	l := artifact.Layout{Format: v.Format, Binding: artifact.Binding{ClusterID: v.Binding.ClusterID, ArtifactID: v.Binding.ArtifactID, AttemptID: v.Binding.AttemptID, MediaType: v.Binding.MediaType}, NativeBytes: v.NativeBytes, DataBytes: v.DataBytes, IndexBytes: v.IndexBytes, DataKey: artifact.SealedKey{Reference: v.DataKey.Reference, Ciphertext: v.DataKey.Ciphertext}, IndexKey: artifact.SealedKey{Reference: v.IndexKey.Reference, Ciphertext: v.IndexKey.Ciphertext}}
	if l.Binding != expected {
		return artifact.Layout{}, artifact.ErrInvalid
	}
	for _, pair := range []struct {
		s   string
		out *artifact.Digest
	}{{v.NativeSHA256, &l.NativeSHA256}, {v.DataSHA256, &l.DataSHA256}, {v.IndexSHA256, &l.IndexSHA256}} {
		h, err := parseHash(pair.s)
		if err != nil {
			return artifact.Layout{}, err
		}
		*pair.out = h
	}
	for _, p := range v.Pages {
		h, err := parseHash(p.IndexSHA256)
		if err != nil {
			return artifact.Layout{}, err
		}
		l.Pages = append(l.Pages, artifact.Page{Number: p.Number, FirstFrame: p.FirstFrame, FrameCount: p.FrameCount, NativeOffset: p.NativeOffset, NativeBytes: p.NativeBytes, DataOffset: p.DataOffset, DataBytes: p.DataBytes, IndexOffset: p.IndexOffset, IndexBytes: p.IndexBytes, IndexSHA256: h})
	}
	if err := l.Validate(); err != nil {
		return artifact.Layout{}, err
	}
	return l, nil
}
