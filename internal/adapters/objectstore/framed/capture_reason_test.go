package framed

import (
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

func reasonFramedIntent(t *testing.T) value.OperationIntent {
	t.Helper()
	in := captureFramedIntent(t)
	human := in.Actor
	in.Capture.Actor = authorization.PolicyPrincipal(in.RootID, strings.Repeat("p", 64))
	in.Capture.CaptureID = "00000000-0000-4000-8000-000000000003"
	in.ID = in.Capture.CaptureID
	in.Capture.Group = &value.CaptureGroupBinding{ParentCaptureID: in.RootID, SelectionDigest: in.Capture.ScopeDigest, ChildIndex: 15, ChildCount: 16}
	in.Capture.Initiator = &human
	inner := value.CaptureReasonEnvelope{Format: value.CaptureReasonEnvelopeFormat, KeyReference: bytes.Repeat([]byte{'\\'}, 256), WrappedKey: bytes.Repeat([]byte{'\\'}, 8192), Ciphertext: bytes.Repeat([]byte{1}, 2081)}
	raw, err := app.EncodeCaptureReasonEnvelope(inner)
	if err != nil {
		t.Fatal(err)
	}
	in.Capture.ReasonRef = &value.CaptureReasonRef{ID: in.ID, CiphertextDigest: sha256.Sum256(raw)}
	in.ReasonEnvelope = &inner
	in.InputFormat = value.CaptureReasonInputFormat
	if !in.Valid() {
		t.Fatal("reason operation structurally refused")
	}
	return in
}
func TestCaptureReasonBothPhasesOpaqueRoundTrip(t *testing.T) {
	in := reasonFramedIntent(t)
	out := value.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", CaptureIDs: []string{in.ID}, OutputDigest: artifact.Digest{1}, MetadataUntil: in.RequestUntil, RecordedAt: in.CreatedAt}
	k := &captureWideKeys{base: keys(t)}
	for _, phase := range []string{"intent", "outcome"} {
		var raw, plain []byte
		var err error
		if phase == "intent" {
			plain, err = app.EncodeCaptureOperationIntent(in)
			if err == nil {
				raw, err = SealOperationIntent(context.Background(), k, in)
			}
		} else {
			plain, err = app.EncodeCaptureOperationOutcome(out)
			if err == nil {
				raw, err = SealOperationOutcome(context.Background(), k, out)
			}
		}
		if err != nil || len(plain) > 32<<10 || len(raw) > value.OperationCipherLimit {
			t.Fatal(phase, len(plain), len(raw), err)
		}
		if phase == "intent" {
			err = VerifyOperationIntent(context.Background(), k, in, raw)
		} else {
			err = VerifyOperationOutcome(context.Background(), k, out, raw)
		}
		if err != nil {
			t.Fatal(phase, err)
		}
		t.Logf("phase=%s plain=%d object=%d", phase, len(plain), len(raw))
	}
	changed := in
	envelope := *in.ReasonEnvelope
	envelope.Ciphertext = bytes.Clone(envelope.Ciphertext)
	envelope.Ciphertext[0] ^= 1
	changed.ReasonEnvelope = &envelope
	if _, err := app.EncodeCaptureOperationIntent(changed); err == nil {
		t.Fatal("mismatched reference accepted")
	}
}
func TestCaptureReasonCipherVerbatimAndBoundToParent(t *testing.T) {
	in := captureFramedIntent(t)
	b := app.CaptureReasonBinding{RootID: in.RootID, CaptureID: in.ID, Requester: in.Actor, ScopeDigest: in.Capture.ScopeDigest}
	k := keys(t)
	c := CaptureReasonCipher{Sealer: k, Opener: k}
	for _, text := range []string{"  a\n\t<&>\u0000  ", strings.Repeat("🙂", 512)} {
		e, err := c.SealCaptureReason(context.Background(), b, text)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.OpenCaptureReason(context.Background(), b, e)
		if err != nil || got != text {
			t.Fatal("verbatim", err)
		}
		wrong := b
		wrong.ScopeDigest[0] ^= 1
		if _, err = c.OpenCaptureReason(context.Background(), wrong, e); err == nil {
			t.Fatal("different full selection opened reason")
		}
		raw, err := app.EncodeCaptureReasonEnvelope(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = app.DecodeCaptureReasonEnvelope(raw); err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		_ = json.Unmarshal(raw, &fields)
		fields["unknown"] = true
		raw, _ = json.Marshal(fields)
		if _, err = app.DecodeCaptureReasonEnvelope(raw); err == nil {
			t.Fatal("unknown fields accepted")
		}
	}
	for _, text := range []string{"", strings.Repeat("🙂", 513), string([]byte{255})} {
		if _, err := c.SealCaptureReason(context.Background(), b, text); err == nil {
			t.Fatal("invalid reason accepted")
		}
	}
}

func TestCaptureReasonOuterCeilingAndProviderBounds(t *testing.T) {
	ctx := context.Background()
	k := &captureWideKeys{base: keys(t)}
	ad := []byte("synthetic-ceiling-only")
	a, key, err := newKey(ctx, k, ad)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := encrypt(a, bytes.Repeat([]byte{'x'}, value.CaptureReasonPlainLimit), ad)
	if err != nil {
		t.Fatal(err)
	}
	outer := captureReasonOuter{"asservat-capture-reason-outcome/v1", []byte(key.Reference), []byte(key.Ciphertext), cipher}
	raw, err := captureReasonOuterEnvelope(outer)
	if err != nil || len(raw) != 55133 || 2*len(raw) > 128<<10 {
		t.Fatal("unchanged funded bounds", len(raw), err)
	}
	outer.WrappedKey = bytes.Repeat([]byte{'x'}, 8193)
	if _, err = captureReasonOuterEnvelope(outer); err == nil {
		t.Fatal("capture-specific8192 bound widened")
	}
	outer.WrappedKey = bytes.Repeat([]byte{'x'}, 16384)
	if _, err = captureReasonOuterEnvelope(outer); err == nil {
		t.Fatal("generic16384 wrap silently treated as capture-compatible")
	}
	t.Logf("32KiB ceiling object=%d pair=%d", len(raw), 2*len(raw))
}
