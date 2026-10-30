package framed

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
)

// No production format change: study the exact existing streaming-AEAD cipher
// and maximum generic key representation, using existing local testKeys only.
func TestRecordingReasonVersionedEnvelopeStudy(t *testing.T) {
	ctx := context.Background()
	plain := bytes.Repeat([]byte{'x'}, 24<<10)
	ad := controlAuditAAD("asservat-capture-reason-intent/v1", "root", "event", plain)
	k := keys(t)
	a, key, err := newKey(ctx, k, ad)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := encrypt(a, plain, ad)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := decrypt(a, cipher, ad, 24<<10)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatal("stream roundtrip", err)
	}
	key = artifact.SealedKey{Reference: strings.Repeat("\\", 256), Ciphertext: strings.Repeat("\\", 16384)}
	naive := authorityEnvelope{"asservat-capture-reason-intent/v1", key, cipher}
	raw, err := json.Marshal(naive)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= value.OperationCipherLimit {
		t.Fatal("expected full generic escape-heavy key to exceed old envelope")
	}
	// Byte representation avoids adversarial JSON string-escaping growth and
	// round-trips the EXACT opaque strings passed to the existing KeyOpener.
	proposed := struct {
		Format                               string `json:"format"`
		KeyReference, WrappedKey, Ciphertext []byte
	}{"asservat-capture-reason-intent/v1", []byte(key.Reference), []byte(key.Ciphertext), cipher}
	packed, err := json.Marshal(proposed)
	if err != nil || len(packed) > value.OperationCipherLimit {
		t.Fatal("new-format candidate does not fit64KiB", len(packed), err)
	}
	var decoded struct {
		Format                               string `json:"format"`
		KeyReference, WrappedKey, Ciphertext []byte
	}
	if err = json.Unmarshal(packed, &decoded); err != nil || string(decoded.KeyReference) != key.Reference || string(decoded.WrappedKey) != key.Ciphertext {
		t.Fatal("opaque key bytes changed", err)
	}
	t.Logf("plaintext=%d stream_cipher=%d max_key_string_envelope=%d candidate_byte_key_envelope=%d object_cap=%d pair_max=%d", len(plain), len(cipher), len(raw), len(packed), value.OperationCipherLimit, 2*len(packed))
}

func TestRecordingReasonFullPrivateFrameStudy(t *testing.T) {
	in := captureFramedIntent(t)
	c := *in.Capture
	human := c.Actor
	c.Actor = authorization.PolicyPrincipal(c.RootID, strings.Repeat("p", 64))
	c.Initiator = &human
	c.CaptureID = "00000000-0000-4000-8000-000000000003"
	c.Group = &value.CaptureGroupBinding{ParentCaptureID: c.RootID, SelectionDigest: c.ScopeDigest, ChildIndex: 15, ChildCount: 16}
	in.Capture = &c
	in.ID = c.CaptureID
	if !in.Valid() {
		t.Fatal("valid maximum-width source-save intent required")
	}
	out := value.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", OutputDigest: artifact.Digest{255}, CaptureIDs: []string{in.ID}, MetadataUntil: in.RequestUntil, RecordedAt: in.CreatedAt}
	for _, item := range []struct {
		phase  string
		record any
	}{{"intent", in}, {"outcome", out}} {
		var b bytes.Buffer
		e := json.NewEncoder(&b)
		e.SetEscapeHTML(false)
		if err := e.Encode(item.record); err != nil {
			t.Fatal(err)
		}
		var candidate map[string]any
		decoder := json.NewDecoder(bytes.NewReader(b.Bytes()))
		decoder.UseNumber()
		if err := decoder.Decode(&candidate); err != nil {
			t.Fatal(err)
		}
		candidate["ReasonBody"] = strings.Repeat("\U0001f642", 512)
		// A large fixed reference placeholder; no plaintext hash or new authority.
		candidate["ReasonRef"] = strings.Repeat("r", 256)
		b.Reset()
		if err := e.Encode(candidate); err != nil {
			t.Fatal(err)
		}
		if b.Len()-1 > 24<<10 {
			t.Fatal("candidate reason frame exceeds24KiB", item.phase, b.Len()-1)
		}
		t.Logf("phase=%s proposed_plaintext=%d reason_format_cap=24576", item.phase, b.Len()-1)
	}
	// Measure journal representation separately: SQL may retain only the
	// encrypted body. Outcome.Intent must equal the entire frozen intent.
	// This compact JSON is NOT a PostgreSQL heap/TOAST/index/WAL qualification.
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(in); err != nil {
		t.Fatal(err)
	}
	var sqlIntent map[string]any
	dec := json.NewDecoder(&raw)
	dec.UseNumber()
	if err := dec.Decode(&sqlIntent); err != nil {
		t.Fatal(err)
	}
	sqlIntent["ReasonRef"] = strings.Repeat("r", 256)
	sqlIntent["ReasonEnvelope"] = struct {
		Format                               string
		KeyReference, WrappedKey, Ciphertext []byte
	}{"asservat-recording-save-reason/v1", bytes.Repeat([]byte{'\\'}, 256), bytes.Repeat([]byte{'\\'}, 16384), make([]byte, 2081)}
	raw.Reset()
	if err := enc.Encode(sqlIntent); err != nil {
		t.Fatal(err)
	}
	intentSize := raw.Len() - 1
	sqlOutcome := map[string]any{"Intent": sqlIntent, "Status": "success", "Reason": "prepared", "Effect": "accepted", "ClientReceipt": "unknown", "CaptureIDs": []string{in.ID}, "OutputDigest": artifact.Digest{255}, "MetadataUntil": in.RequestUntil, "RecordedAt": in.CreatedAt}
	raw.Reset()
	if err := enc.Encode(sqlOutcome); err != nil {
		t.Fatal(err)
	}
	outcomeSize := raw.Len() - 1
	t.Logf("compact_SQL_intent_with_max_key_body=%d compact_SQL_outcome=%d combined_JSON=%d minimum_qualified_row_bound=131072 physical_SQL_WAL_unqualified=true", intentSize, outcomeSize, intentSize+outcomeSize)
	// Existing format remains independent and unchanged in this study.
	if _, err := app.EncodeCaptureOperationIntent(in); err == nil {
		t.Log("legacy private frame still admits this baseline")
	}
}

// Preferred follow-up candidate: preserve an opaque inner envelope through the
// existing journal and both audit phases. No reason unwrap during admission or
// child audit persistence, and no global SealedKey bound is changed.
func TestRecordingReasonOpaqueFrameStudy(t *testing.T) {
	ctx := context.Background()
	k := keys(t)
	text := []byte(strings.Repeat("\U0001f642", 512))
	body, err := k.a.Encrypt(text, []byte("synthetic-root-parent-requester-scope-binding"))
	if err != nil {
		t.Fatal(err)
	}
	type byteEnvelope struct {
		Format                               string `json:"format"`
		KeyReference, WrappedKey, Ciphertext []byte
	}
	inner := byteEnvelope{"asservat-recording-save-reason/v1", bytes.Repeat([]byte{'\\'}, 256), bytes.Repeat([]byte{'\\'}, 8192), body}
	innerBytes, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	in := captureFramedIntent(t)
	c := *in.Capture
	human := c.Actor
	c.Actor = authorization.PolicyPrincipal(c.RootID, strings.Repeat("p", 64))
	c.Initiator = &human
	c.CaptureID = "00000000-0000-4000-8000-000000000003"
	c.Group = &value.CaptureGroupBinding{ParentCaptureID: c.RootID, SelectionDigest: c.ScopeDigest, ChildIndex: 15, ChildCount: 16}
	in.Capture = &c
	in.ID = c.CaptureID
	if !in.Valid() {
		t.Fatal("valid bounded grouped source-save metadata required")
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err = enc.Encode(in); err != nil {
		t.Fatal(err)
	}
	var sqlIntent map[string]any
	dec := json.NewDecoder(&b)
	dec.UseNumber()
	if err = dec.Decode(&sqlIntent); err != nil {
		t.Fatal(err)
	}
	sqlIntent["ReasonRef"] = strings.Repeat("r", 512) // conservative fixed reference bound
	sqlIntent["ReasonEnvelope"] = inner
	sqlOutcome := map[string]any{"Intent": sqlIntent, "Status": "success", "Reason": "prepared", "Effect": "accepted", "ClientReceipt": "unknown", "CaptureIDs": []string{in.ID}, "OutputDigest": artifact.Digest{255}, "MetadataUntil": in.RequestUntil, "RecordedAt": in.CreatedAt}
	sum := 0
	whiteSum := 0
	for _, item := range []struct {
		phase  string
		record any
	}{{"intent", sqlIntent}, {"outcome", sqlOutcome}} {
		b.Reset()
		if err = enc.Encode(item.record); err != nil {
			t.Fatal(err)
		}
		plain := bytes.Clone(bytes.TrimSuffix(b.Bytes(), []byte{'\n'}))
		if len(plain) > 32<<10 {
			t.Fatal("opaque full metadata frame exceeds proposed32KiB", item.phase, len(plain))
		}
		sum += len(plain)
		var spaced bytes.Buffer
		if err = json.Indent(&spaced, plain, "", ""); err != nil {
			t.Fatal(err)
		}
		whiteSum += spaced.Len()
		ad := controlAuditAAD("asservat-capture-reason-"+item.phase+"/v1", in.RootID, in.ID, plain)
		a, _, err := newKey(ctx, k, ad)
		if err != nil {
			t.Fatal(err)
		}
		cipher, err := encrypt(a, plain, ad)
		if err != nil {
			t.Fatal(err)
		}
		proposed := byteEnvelope{"asservat-capture-reason-" + item.phase + "/v1", inner.KeyReference, inner.WrappedKey, cipher}
		packed, err := json.Marshal(proposed)
		if err != nil || len(packed) > value.OperationCipherLimit {
			t.Fatal("opaque audit object exceeds64KiB", item.phase, len(packed), err)
		}
		got, err := decrypt(a, cipher, ad, 32<<10)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal("outer local streaming roundtrip", err)
		}
		t.Logf("opaque_phase=%s inner_bytes=%d full_plaintext=%d outer_cipher=%d encoded_object=%d additional_reason_unwraps=0", item.phase, len(innerBytes), len(plain), len(cipher), len(packed))
	}
	t.Logf("opaque_SQL_combined_compact_JSON=%d whitespace_inflated_JSON=%d minimum_row_qualification=131072 physical_postgres_WAL_not_measured=true", sum, whiteSum)
	for _, n := range []int{32 << 10, 36 << 10} {
		plain := bytes.Repeat([]byte{'x'}, n)
		ad := controlAuditAAD("asservat-capture-reason-outcome/v1", in.RootID, in.ID, plain)
		a, _, err := newKey(ctx, k, ad)
		if err != nil {
			t.Fatal(err)
		}
		cipher, err := encrypt(a, plain, ad)
		if err != nil {
			t.Fatal(err)
		}
		packed, err := json.Marshal(byteEnvelope{"asservat-capture-reason-outcome/v1", inner.KeyReference, inner.WrappedKey, cipher})
		if err != nil || len(packed) > value.OperationCipherLimit {
			t.Fatal("ceiling envelope exceeds64KiB", n, len(packed), err)
		}
		t.Logf("candidate_plaintext_ceiling=%d actual_stream_cipher=%d maximum8KiB_wrap_encoded_object=%d pair=%d unchanged_pair_funding=131072", n, len(cipher), len(packed), 2*len(packed))
	}
}
