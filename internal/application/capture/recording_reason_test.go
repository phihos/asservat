package capture

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	auditapp "asservat.local/asservat/internal/application/audit"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/capture"
)

type reasonPreviewCipher struct {
	calls   int
	binding auditapp.CaptureReasonBinding
	text    string
	fail    bool
}

func (f *reasonPreviewCipher) SealCaptureReason(_ context.Context, b auditapp.CaptureReasonBinding, text string) (auditvalue.CaptureReasonEnvelope, error) {
	f.calls++
	f.binding = b
	f.text = text
	if f.fail {
		return auditvalue.CaptureReasonEnvelope{}, errors.New("synthetic unavailable")
	}
	return auditvalue.CaptureReasonEnvelope{Format: auditvalue.CaptureReasonEnvelopeFormat, KeyReference: []byte("synthetic/control"), WrappedKey: []byte("synthetic-wrapped-key"), Ciphertext: bytes.Repeat([]byte{1}, 2081)}, nil
}
func (*reasonPreviewCipher) OpenCaptureReason(context.Context, auditapp.CaptureReasonBinding, auditvalue.CaptureReasonEnvelope) (string, error) {
	panic("preview must not unwrap")
}
func TestRecordingReasonPreviewPreservesScopeAndLifetime(t *testing.T) {
	for _, n := range []int{2, 16} {
		p := recordingGroupSizePreview(t, n)
		scope := bytes.Clone(p.CanonicalScope)
		digest := p.ScopeDigest
		deadline, review := p.Deadline, p.SelectionUntil
		if !ValidContextPreview(p) {
			t.Fatal("valid complete reviewed selection required")
		}
		cipher := &reasonPreviewCipher{}
		s := ContextInvestigation{ReasonCipher: cipher}
		text := " \n" + strings.Repeat("\U0001f642", 509) + " " //512 scalars, preserve whitespace
		if err := s.preparePreviewReason(context.Background(), &p, &text); err != nil {
			t.Fatal(err)
		}
		if !ValidContextPreview(p) || cipher.calls != 1 || cipher.text != text || cipher.binding.RootID != p.RootID || cipher.binding.CaptureID != p.CaptureID || cipher.binding.Requester != p.Actor || cipher.binding.ScopeDigest != digest {
			t.Fatal("reason did not bind complete authorized selection")
		}
		if p.ScopeDigest != digest || !bytes.Equal(p.CanonicalScope, scope) || !p.Deadline.Equal(deadline) || !p.SelectionUntil.Equal(review) || !p.Intent.Reason.ExpiresAt.IsZero() {
			t.Fatal("descriptive reason changed collection/grant/review scope")
		}
		clone := p.Clone()
		clone.ReasonEnvelope[0] ^= 1
		if ValidContextPreview(clone) || !ValidContextPreview(p) {
			t.Fatal("changed ciphertext accepted or clone aliases original")
		}
		clone = p.Clone()
		clone.Intent.Reason.ID = clone.CaptureID
		if ValidContextPreview(clone) {
			t.Fatal("foreign preview reference accepted")
		}
		clone = p.Clone()
		clone.Intent.Reason.CiphertextDigest[0] ^= 1
		if ValidContextPreview(clone) {
			t.Fatal("changed ciphertext digest accepted")
		}
		clone = p.Clone()
		clone.ReasonEnvelope = nil
		if ValidContextPreview(clone) {
			t.Fatal("reference without protected body accepted")
		}
		if err := s.preparePreviewReason(context.Background(), &p, &text); err == nil || cipher.calls != 1 {
			t.Fatal("same immutable preview reencrypted reason")
		}
	}
}
func TestRecordingReasonInputBoundsAndAbsentCost(t *testing.T) {
	for _, text := range []string{"", strings.Repeat("x", 513), string([]byte{255})} {
		p := recordingGroupSizePreview(t, 2)
		c := &reasonPreviewCipher{}
		s := ContextInvestigation{ReasonCipher: c}
		if err := s.preparePreviewReason(context.Background(), &p, &text); err != value.ErrInvalid || c.calls != 0 || p.Intent.Reason != nil {
			t.Fatal("invalid canonical text reached wrap", err)
		}
	}
	p := recordingGroupSizePreview(t, 2)
	if err := (ContextInvestigation{}).preparePreviewReason(context.Background(), &p, nil); err != nil || p.Intent.Reason != nil || len(p.ReasonEnvelope) != 0 {
		t.Fatal("absent reason needs a new dependency")
	}
	text := "reason"
	if err := (ContextInvestigation{}).preparePreviewReason(context.Background(), &p, &text); err == nil || p.Intent.Reason != nil {
		t.Fatal("missing cipher silently lost reason")
	}
}
