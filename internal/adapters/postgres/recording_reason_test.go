package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/contracts"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/capture"
)

func TestReasonPreviewBodyIsSeparateAndCannotSubstituteReference(t *testing.T) {
	p := previewTestValue(t)
	env := auditvalue.CaptureReasonEnvelope{Format: auditvalue.CaptureReasonEnvelopeFormat, KeyReference: []byte("synthetic-key"), WrappedKey: []byte("synthetic-wrapper"), Ciphertext: bytes.Repeat([]byte{1}, 34)}
	raw, err := auditapp.EncodeCaptureReasonEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	p.Intent.Reason = &value.ProtectedReasonRef{ID: p.ID, CiphertextDigest: sha256.Sum256(raw), ExpiresAt: p.CreatedAt.Add(-time.Second)}
	// Exact stored shape: immutable blueprint contains only the ref; the separate
	// ciphertext column can be erased once all mandatory journals own their copy.
	row := previewTestRow(t, p)
	row.ReasonEnvelope = raw
	if bytes.Contains(row.BlueprintJson, []byte("ReasonEnvelope")) {
		t.Fatal("blueprint retains a second non-erasable body")
	}
	expected := p.Clone()
	expected.ReasonEnvelope = bytes.Clone(raw)
	got, err := previewRecord(row)
	if err != nil || !reflect.DeepEqual(got, expected) {
		t.Fatal("expiry changed reviewed authority or opaque body lost", err)
	}
	got.ReasonEnvelope[0] ^= 1
	if !bytes.Equal(row.ReasonEnvelope, raw) {
		t.Fatal("read aliases erasable stored ciphertext")
	}
	corrupt := row
	corrupt.ReasonEnvelope = bytes.Clone(raw)
	corrupt.ReasonEnvelope[len(raw)-3] ^= 1
	if _, err = previewRecord(corrupt); err == nil {
		t.Fatal("body column substitution bypassed immutable ref")
	}
	erased := row
	erased.ReasonEnvelope = nil
	if _, err = previewRecord(erased); err == nil {
		t.Fatal("erased accepted preview can create a new reason admission")
	}
	// Absent reason compatibility: persisted bytes remain the original encoding.
	legacy := previewTestValue(t)
	baseline := previewTestRow(t, legacy)
	encoded, err := json.Marshal(legacy)
	if err != nil || !bytes.Equal(encoded, baseline.BlueprintJson) {
		t.Fatal("nil reason changed original blueprint bytes")
	}
	if _, err = previewRecord(baseline); err != nil {
		t.Fatal("legacy preview rejected", err)
	}
}

func TestCaptureReasonReadHasOneExactExistingPurposeGrant(t *testing.T) {
	for _, purpose := range contracts.PublicRuntimeRolePurposes() {
		grants, ok := publicRuntimeRoleGrants(purpose)
		if !ok {
			t.Fatal("unknown configured purpose", purpose)
		}
		count := 0
		for _, g := range grants {
			if g.object == "read_capture_reason(uuid,uuid)" {
				count++
				if g.kind != "function" || g.column != "" || g.privilege != "EXECUTE" {
					t.Fatal("reason lookup widened privilege", purpose, g)
				}
			}
		}
		want := 0
		if purpose == "capture-journal" {
			want = 1
		}
		if count != want {
			t.Fatal("reason lookup escaped its existing journal credential", purpose, count, want)
		}
	}
}
