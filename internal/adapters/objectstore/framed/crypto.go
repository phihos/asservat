// Package framed implements the versioned storage wrapper. It owns no grants,
// SQL state, object credentials, native parsers or execution authority.
package framed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"io"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	streampb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_hkdf_streaming_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/proto"
)

type associated struct {
	Format       string `json:"format"`
	Schema       string `json:"schema"`
	ClusterID    string `json:"clusterID"`
	ArtifactID   string `json:"artifactID"`
	AttemptID    string `json:"attemptID"`
	MediaType    string `json:"mediaType"`
	Role         string `json:"role"`
	Sequence     int    `json:"sequence"`
	NativeOffset int64  `json:"nativeOffset"`
	NativeBytes  int64  `json:"nativeBytes"`
	Codec        string `json:"codec"`
}

func aad(b artifact.Binding, role string, sequence int, offset, size int64, codec string) []byte {
	if role == "data-key" || role == "index-key" || role == "manifest-key" {
		if sequence != 0 || offset != 0 || size != 0 || codec != "none" {
			panic("invalid internal key binding")
		}
		out, err := evidence.ArtifactKeyBinding(b, role)
		if err != nil {
			panic("invalid internal key binding")
		}
		return out
	}
	v, _ := json.Marshal(associated{artifact.StorageFormat, "artifact/v1", b.ClusterID, b.ArtifactID, b.AttemptID, b.MediaType, role, sequence, offset, size, codec})
	// All fields are validated ASCII and integers below 2^53; canonicalization
	// has no lossy numeric conversion. Never use map iteration as a digest rule.
	c := jsontext.Value(v)
	if err := c.Canonicalize(); err != nil {
		panic("invalid internal associated data")
	}
	return c
}

func newKey(ctx context.Context, s evidence.KeySealer, binding []byte) (tink.StreamingAEAD, artifact.SealedKey, error) {
	h, err := keyset.NewHandle(streamingaead.AES256GCMHKDF1MBKeyTemplate())
	if err != nil {
		return nil, artifact.SealedKey{}, err
	}
	var buf bytes.Buffer
	// Tink WriteWithAssociatedData performs a decrypt self-check, which would
	// violate the collector's wrap-only KMS role. Serialize only to memory and
	// pass to the wrap-only port instead. Never persist this intermediate value.
	if err = insecurecleartextkeyset.Write(h, keyset.NewBinaryWriter(&buf)); err != nil {
		return nil, artifact.SealedKey{}, err
	}
	defer clear(buf.Bytes())
	sealed, err := s.Seal(ctx, buf.Bytes(), binding)
	if err != nil {
		return nil, artifact.SealedKey{}, err
	}
	a, err := streamingaead.New(h)
	return a, sealed, err
}

func openKey(ctx context.Context, s evidence.KeyOpener, sealed artifact.SealedKey, binding []byte) (tink.StreamingAEAD, error) {
	b, err := s.Open(ctx, sealed, binding)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	if len(b) == 0 || len(b) > 4096 {
		return nil, artifact.ErrLimit
	}
	if !supportedKeyset(b) {
		return nil, artifact.ErrIntegrity
	}
	h, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(b)))
	if err != nil {
		return nil, artifact.ErrIntegrity
	}
	return streamingaead.New(h)
}

// The format fixes one suite, not every primitive that Tink happens to support.
// Validate official protobuf fields before constructing the reader primitive.
func supportedKeyset(b []byte) bool {
	var ks tinkpb.Keyset
	if proto.Unmarshal(b, &ks) != nil || len(ks.Key) != 1 {
		return false
	}
	k := ks.Key[0]
	if k == nil || k.KeyData == nil {
		return false
	}
	defer clear(k.KeyData.Value)
	if ks.PrimaryKeyId != k.KeyId || k.Status != tinkpb.KeyStatusType_ENABLED || k.OutputPrefixType != tinkpb.OutputPrefixType_RAW || k.KeyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC || k.KeyData.TypeUrl != "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey" {
		return false
	}
	var stream streampb.AesGcmHkdfStreamingKey
	if proto.Unmarshal(k.KeyData.Value, &stream) != nil {
		return false
	}
	defer clear(stream.KeyValue)
	return stream.Version == 0 && len(stream.KeyValue) == 32 && stream.Params != nil && stream.Params.DerivedKeySize == 32 && stream.Params.CiphertextSegmentSize == 1<<20 && stream.Params.HkdfHashType == commonpb.HashType_SHA256
}

func encrypt(a tink.StreamingAEAD, b, ad []byte) ([]byte, error) {
	var out bytes.Buffer
	w, err := a.NewEncryptingWriter(&out, ad)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(b); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decrypt(a tink.StreamingAEAD, b, ad []byte, limit int64) ([]byte, error) {
	r, err := a.NewDecryptingReader(bytes.NewReader(b), ad)
	if err != nil {
		return nil, artifact.ErrIntegrity
	}
	v, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(v)) > limit {
		clear(v)
		return nil, artifact.ErrIntegrity
	}
	return v, nil
}

func digest(b []byte) artifact.Digest { return artifact.Digest(sha256.Sum256(b)) }

func writeAll(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}
