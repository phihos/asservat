package framed

import (
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"bytes"
	"context"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	aesgcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

// CaptureReasonCipher receives the existing hub audit/control key ports only.
// Neither sealing nor outer audit verification opens the reason key.
type CaptureReasonCipher struct {
	Sealer evidence.KeySealer
	Opener evidence.KeyOpener
}

var _ app.CaptureReasonCipher = CaptureReasonCipher{}

func (c CaptureReasonCipher) SealCaptureReason(ctx context.Context, b app.CaptureReasonBinding, text string) (value.CaptureReasonEnvelope, error) {
	if ctx == nil || ctx.Err() != nil || c.Sealer == nil || !app.ValidCaptureReasonText(text) {
		return value.CaptureReasonEnvelope{}, artifact.ErrInvalid
	}
	ad, err := app.CaptureReasonAssociatedData(b)
	if err != nil {
		return value.CaptureReasonEnvelope{}, err
	}
	h, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return value.CaptureReasonEnvelope{}, err
	}
	var raw bytes.Buffer
	if err = insecurecleartextkeyset.Write(h, keyset.NewBinaryWriter(&raw)); err != nil {
		return value.CaptureReasonEnvelope{}, err
	}
	defer clear(raw.Bytes())
	sealed, err := c.Sealer.Seal(ctx, raw.Bytes(), ad)
	if err != nil {
		return value.CaptureReasonEnvelope{}, err
	}
	a, err := aead.New(h)
	if err != nil {
		return value.CaptureReasonEnvelope{}, err
	}
	plain := []byte(text)
	defer clear(plain)
	cipher, err := a.Encrypt(plain, ad)
	if err != nil {
		return value.CaptureReasonEnvelope{}, err
	}
	out := value.CaptureReasonEnvelope{Format: value.CaptureReasonEnvelopeFormat, KeyReference: []byte(sealed.Reference), WrappedKey: []byte(sealed.Ciphertext), Ciphertext: cipher}
	if !out.Valid() || ctx.Err() != nil {
		return value.CaptureReasonEnvelope{}, artifact.ErrInvalid
	}
	return out, nil
}
func (c CaptureReasonCipher) OpenCaptureReason(ctx context.Context, b app.CaptureReasonBinding, e value.CaptureReasonEnvelope) (string, error) {
	if ctx == nil || ctx.Err() != nil || c.Opener == nil || !e.Valid() {
		return "", artifact.ErrInvalid
	}
	ad, err := app.CaptureReasonAssociatedData(b)
	if err != nil {
		return "", err
	}
	raw, err := c.Opener.Open(ctx, artifact.SealedKey{Reference: string(e.KeyReference), Ciphertext: string(e.WrappedKey)}, ad)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	var ks tinkpb.Keyset
	if len(raw) > 4096 || proto.Unmarshal(raw, &ks) != nil || len(ks.Key) != 1 {
		return "", artifact.ErrIntegrity
	}
	k := ks.Key[0]
	if k.KeyId != ks.PrimaryKeyId || k.Status != tinkpb.KeyStatusType_ENABLED || k.OutputPrefixType != tinkpb.OutputPrefixType_TINK || k.KeyData == nil || k.KeyData.TypeUrl != "type.googleapis.com/google.crypto.tink.AesGcmKey" || k.KeyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
		return "", artifact.ErrIntegrity
	}
	var aesKey aesgcmpb.AesGcmKey
	if proto.Unmarshal(k.KeyData.Value, &aesKey) != nil || aesKey.Version != 0 || len(aesKey.KeyValue) != 32 {
		return "", artifact.ErrIntegrity
	}
	h, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(raw)))
	if err != nil {
		return "", artifact.ErrIntegrity
	}
	a, err := aead.New(h)
	if err != nil {
		return "", artifact.ErrIntegrity
	}
	plain, err := a.Decrypt(e.Ciphertext, ad)
	if err != nil {
		return "", artifact.ErrIntegrity
	}
	defer clear(plain)
	text := string(plain)
	if !app.ValidCaptureReasonText(text) || ctx.Err() != nil {
		return "", artifact.ErrIntegrity
	}
	return text, nil
}
