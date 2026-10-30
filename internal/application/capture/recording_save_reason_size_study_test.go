package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

// PREIMPLEMENTATION ONLY. This is the existing BrowserCipher Tink envelope
// algorithm with a distinct proposed reason format, not a production codec.
// The local key wrapper matches contextWriterTestKeys: base64 is NOT encryption
// or provider qualification. Only the payload AEAD is real crypto here.
type reasonStudyEnvelope struct {
	Format     string
	Key        artifact.SealedKey
	Ciphertext []byte
}

func reasonStudyEncode(t *testing.T, v any) []byte {
	t.Helper()
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}
func reasonStudySeal(t *testing.T, plain, ad []byte) reasonStudyEnvelope {
	t.Helper()
	h, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	if err = insecurecleartextkeyset.Write(h, keyset.NewBinaryWriter(&raw)); err != nil {
		t.Fatal(err)
	}
	defer clear(raw.Bytes())
	k := artifact.SealedKey{Reference: strings.Repeat("r", 256), Ciphertext: base64.StdEncoding.EncodeToString(raw.Bytes())}
	a, err := aead.New(h)
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.Encrypt(plain, ad)
	if err != nil {
		t.Fatal(err)
	}
	out, err := a.Decrypt(c, ad)
	if err != nil || !bytes.Equal(out, plain) {
		t.Fatal("local round trip", err)
	}
	wrong := bytes.Clone(ad)
	wrong[0] ^= 1
	if _, err = a.Decrypt(c, wrong); err == nil {
		t.Fatal("wrong binding accepted")
	}
	t.Logf("tink_keyset_bytes=%d fake_wrapped_key_bytes=%d ciphertext_bytes=%d", raw.Len(), len(k.Ciphertext), len(c))
	return reasonStudyEnvelope{"asservat-recording-save-reason/v1", k, c}
}
func reasonStudyIntent(t *testing.T, p value.ContextPreview, escaped bool) auditvalue.CaptureIntent {
	t.Helper()
	c := p.Group.Children[15]
	actor := p.Actor
	actor.ClientID = strings.Repeat("c", 256)
	text := func(n int) string { return strings.Repeat("x", n) }
	if escaped {
		text = func(n int) string { return strings.Repeat("\"", n) }
		actor.Issuer = text(2048)
		actor.Subject = text(256)
		actor.ClientID = text(256)
	}
	d := artifact.Digest{}
	for i := range d {
		d[i] = 255
	}
	r := auditvalue.CaptureIntent{Group: &auditvalue.CaptureGroupBinding{ParentCaptureID: p.CaptureID, SelectionDigest: d, ChildIndex: 15, ChildCount: 16}, Initiator: &actor, RootID: p.RootID, CaptureID: c.CaptureID, CaseID: p.CaseID, OccurrenceID: c.OccurrenceID, ArtifactID: c.ArtifactID, AttemptID: c.AttemptID, Actor: authorization.PolicyPrincipal(p.InstallationID, strings.Repeat("p", 64)), Target: authorization.Target{ClusterID: p.Target.ClusterID, NamespaceUID: text(64), WorkloadUID: text(64), PodUID: text(64)}, ScopeDigest: d, SubmissionDigest: d, ExpectationDigest: d, PermissionEpoch: p.IssuerEpoch, PermissionSequence: 9223372036854775807, IdentityRevision: identity.Revision{UID: text(64), Generation: 2147483647, Digest: d}, CreatedAt: p.CreatedAt, Deadline: p.Deadline, ExpiresAt: p.CreatedAt.Add(time.Hour), DeleteBy: p.CreatedAt.Add(2 * time.Hour), ReservedBytes: (16 << 20) - 1}
	if !r.Valid() {
		t.Fatal("study requires valid bounded CaptureIntent")
	}
	return r
}
func TestRecordingSaveReasonSizeStudy(t *testing.T) {
	plain := []byte(strings.Repeat("\U0001f642", 512))
	if utf8.RuneCount(plain) != 512 || len(plain) != 2048 {
		t.Fatal("canonical scalar bound")
	}
	ad := []byte("asservat-recording-save-reason/v1|root:11111111-1111-4111-8111-111111111111|capture:22222222-2222-4222-8222-222222222222|requester-sha256:" + strings.Repeat("f", 64) + "|scope-sha256:" + strings.Repeat("f", 64))
	e := reasonStudySeal(t, plain, ad)
	raw := reasonStudyEncode(t, e)
	p := recordingGroupSizePreview(t, 16)
	ref := value.ProtectedReasonRef{ID: p.AssessmentID, CiphertextDigest: sha256.Sum256(raw), ExpiresAt: p.CreatedAt.Add(time.Hour)}
	t.Logf("reason_scalars=512 reason_utf8_bytes=%d aad_bytes=%d envelope_json_bytes=%d", len(plain), len(ad), len(raw))
	for _, escaped := range []bool{false, true} {
		c := reasonStudyIntent(t, p, escaped)
		refOnly := struct {
			auditvalue.CaptureIntent
			ReasonRef value.ProtectedReasonRef
		}{c, ref}
		inline := struct {
			auditvalue.CaptureIntent
			ReasonRef value.ProtectedReasonRef
			Reason    reasonStudyEnvelope
		}{c, ref, e}
		rb, ib := reasonStudyEncode(t, refOnly), reasonStudyEncode(t, inline)
		if len(rb) > 8<<10 {
			t.Fatal("reference alone cannot fit existing capture bound", len(rb))
		}
		t.Logf("escape_heavy=%t capture_baseline=%d capture_with_ref=%d capture_with_inline_body=%d inline_fits_8192=%t", escaped, len(reasonStudyEncode(t, c)), len(rb), len(ib), len(ib) <= 8<<10)
	}
	journal := struct {
		value.ContextPreview
		ReasonRef value.ProtectedReasonRef
		Reason    reasonStudyEnvelope
	}{p, ref, e}
	if b := reasonStudyEncode(t, journal); len(b) > value.MaxContextPreviewBytes {
		t.Fatal("preview exceeds unchanged cap", len(b))
	} else {
		t.Logf("group16_preview_with_reason=%d cap=%d", len(b), value.MaxContextPreviewBytes)
	}
	e.Key.Ciphertext = strings.Repeat("x", 16384)
	journal.Reason = e
	maxPreview := reasonStudyEncode(t, journal)
	if len(maxPreview) > value.MaxContextPreviewBytes {
		t.Fatal("generic maximum key exceeds preview cap", len(maxPreview))
	}
	t.Logf("group16_preview_with_generic_max_key=%d cap=%d", len(maxPreview), value.MaxContextPreviewBytes)
	oversized := reasonStudyEncode(t, struct {
		auditvalue.CaptureIntent
		Reason reasonStudyEnvelope
	}{reasonStudyIntent(t, p, true), e})
	if len(oversized) <= 8<<10 {
		t.Fatal("expected generic maximum key to exceed capture bound")
	}
	t.Logf("generic_max_key_capture_bytes=%d inline_capture_candidate_does_not_fit=true; no provider timing measured", len(oversized))
}
