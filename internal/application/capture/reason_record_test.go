package capture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type reasonRecordsFunc func(context.Context, string) (CaptureReasonRecord, error)

func (f reasonRecordsFunc) ReadCaptureReasonRecord(ctx context.Context, id string) (CaptureReasonRecord, error) {
	return f(ctx, id)
}

type reasonReadCipher struct {
	opens   int
	binding auditapp.CaptureReasonBinding
	until   time.Time
}

func (f *reasonReadCipher) SealCaptureReason(context.Context, auditapp.CaptureReasonBinding, string) (auditvalue.CaptureReasonEnvelope, error) {
	panic("display cannot wrap")
}
func (f *reasonReadCipher) OpenCaptureReason(ctx context.Context, b auditapp.CaptureReasonBinding, _ auditvalue.CaptureReasonEnvelope) (string, error) {
	f.opens++
	f.binding = b
	f.until, _ = ctx.Deadline()
	return "  original reason\n", nil
}
func TestReasonHistoricalRecordRetainsOriginalBindingWithoutWriteAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	root, parent, child := fixtureID(1), fixtureID(2), fixtureID(3)
	user := identity.Principal{Issuer: "https://synthetic.invalid", Subject: "initiator", ClientID: "console", Kind: identity.Human}
	envelope := auditvalue.CaptureReasonEnvelope{Format: auditvalue.CaptureReasonEnvelopeFormat, KeyReference: []byte("synthetic/control"), WrappedKey: []byte("wrapped"), Ciphertext: bytes.Repeat([]byte{1}, 34)}
	encoded, err := auditapp.EncodeCaptureReasonEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	ref := auditvalue.CaptureReasonRef{ID: fixtureID(4), CiphertextDigest: sha256.Sum256(encoded)}
	c := auditvalue.CaptureIntent{ReasonRef: &ref, RootID: root, CaptureID: child, CaseID: fixtureID(5), OccurrenceID: fixtureID(6), ArtifactID: fixtureID(7), AttemptID: fixtureID(8), Actor: authorization.PolicyPrincipal(root, "policy"), Initiator: &user, Target: authorization.Target{ClusterID: root, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "original-pod"}, ScopeDigest: artifact.Digest{1}, SubmissionDigest: artifact.Digest{2}, ExpectationDigest: artifact.Digest{3}, PermissionEpoch: fixtureID(9), PermissionSequence: 1, IdentityRevision: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{4}}, CreatedAt: now.Add(-time.Hour), Deadline: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour), ReservedBytes: 4096, Group: &auditvalue.CaptureGroupBinding{ParentCaptureID: parent, SelectionDigest: artifact.Digest{1}, ChildIndex: 1, ChildCount: 2}}
	if !c.Valid() {
		t.Fatal("valid historical original capture required")
	}
	metadata := value.CaptureReasonMetadata{RootID: root, CaptureID: parent, AuditCaptureID: child, Requester: user, Reference: value.ProtectedReasonRef{ID: ref.ID, CiphertextDigest: ref.CiphertextDigest}, ScopeDigest: c.ScopeDigest}
	for _, mode := range []string{"historical", "foreign-parent", "changed-requester", "changed-ref", "changed-body", "expired-read"} {
		t.Run(mode, func(t *testing.T) {
			m := metadata
			record := CaptureReasonRecord{Capture: c, Envelope: envelope, ValidUntil: now.Add(time.Second)}
			switch mode {
			case "foreign-parent":
				m.CaptureID = fixtureID(10)
			case "changed-requester":
				m.Requester.ClientID = "other-client"
			case "changed-ref":
				m.Reference.CiphertextDigest[0] ^= 1
			case "changed-body":
				record.Envelope.Ciphertext = bytes.Clone(record.Envelope.Ciphertext)
				record.Envelope.Ciphertext[0] ^= 1
			case "expired-read":
				record.ValidUntil = now.Add(-time.Second)
			}
			cipher := &reasonReadCipher{}
			s := StoredCaptureReasons{Records: reasonRecordsFunc(func(_ context.Context, id string) (CaptureReasonRecord, error) {
				if id != child {
					t.Fatal("public parent substituted for real audit child")
				}
				return record, nil
			}), Cipher: cipher}
			text, err := s.ReadCaptureReason(context.Background(), m)
			if mode != "historical" {
				if err == nil || cipher.opens != 0 {
					t.Fatal("invalid record reached inner unwrap", err)
				}
				return
			}
			if err != nil || text != "  original reason\n" || cipher.opens != 1 || cipher.binding.CaptureID != parent || cipher.binding.Requester != user || cipher.binding.ScopeDigest != c.ScopeDigest || cipher.until.After(record.ValidUntil) {
				t.Fatal("historical metadata borrowed/renewed collection write authority", err)
			}
		})
	}
}
