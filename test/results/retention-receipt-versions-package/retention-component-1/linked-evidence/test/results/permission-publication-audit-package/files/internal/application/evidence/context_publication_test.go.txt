package evidence

import (
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"errors"
	"testing"
	"time"
)

type publicationFixture struct {
	e       artifact.ContextExpectation
	copies  artifact.Copies
	now     time.Time
	calls   []string
	failure string
	record  audit.ContextVerification
	change  func(string, *publicationFixture)
}

func (f *publicationFixture) step(name string) error {
	f.calls = append(f.calls, name)
	if f.change != nil {
		f.change(name, f)
	}
	if f.failure == name {
		return privacy.ErrUnavailable
	}
	return nil
}
func (f *publicationFixture) AcceptedContextForPublication(context.Context, string) (artifact.ContextExpectation, error) {
	return f.e, f.step("accepted")
}
func (f *publicationFixture) CheckContextPublication(context.Context, artifact.ContextExpectation) (artifact.PublicationAuthority, error) {
	err := f.step("authority")
	return artifact.PublicationAuthority{RootID: f.e.CaseID, CaptureID: f.e.CaptureUID, PermissionEpoch: f.e.OccurrenceID, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, ExpectationDigest: ContextExpectationDigest(f.e), AuthorityDigest: artifact.Digest{2}, CheckedAt: f.now, ValidUntil: f.now.Add(time.Second)}, err
}
func (f *publicationFixture) VerifyContext(context.Context, artifact.ContextExpectation, artifact.Copies) error {
	return f.step("verify")
}
func (f *publicationFixture) RecordContextVerification(_ context.Context, e artifact.ContextExpectation, c artifact.Copies, a artifact.PublicationAuthority) (audit.ContextVerification, error) {
	err := f.step("record")
	f.record = audit.ContextVerification{RootID: a.RootID, CaptureID: e.CaptureUID, ArtifactID: e.Registration.Location.ArtifactID, AttemptID: e.Registration.Location.AttemptID, PermissionEpoch: a.PermissionEpoch, PermissionSequence: a.PermissionSequence, ScopeDigest: e.PlanDigest, ExpectationDigest: ContextExpectationDigest(e), CopiesDigest: ContextCopiesDigest(c), IntentDigest: artifact.Digest{3}, AuthorityDigest: a.AuthorityDigest, VerifiedAt: f.now, WriteUntil: e.Registration.WriteUntil, ExpiresAt: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy}
	return f.record, err
}
func (f *publicationFixture) WriteContextVerification(context.Context, audit.ContextVerification) (audit.Receipt, error) {
	err := f.step("audit")
	return audit.Receipt{Key: audit.ContextVerificationKey(f.record.RootID, f.record.CaptureID), Version: "synthetic-version", ETag: "synthetic", Bytes: 128, SHA256: artifact.Digest{4}}, err
}
func (f *publicationFixture) AcknowledgeContextVerification(context.Context, audit.ContextVerification, audit.Receipt) error {
	return f.step("ack")
}
func (f *publicationFixture) PublishContext(_ context.Context, e artifact.ContextExpectation, c artifact.Copies, _ artifact.PublicationAuthority) (artifact.PublishedContext, error) {
	err := f.step("publish")
	return artifact.PublishedContext{RootID: f.record.RootID, CaptureID: e.CaptureUID, Expectation: e, Copies: c, VerifiedAt: f.record.VerifiedAt, PublishedAt: f.now}, err
}
func publicationTest(t *testing.T) (*publicationFixture, ContextPublisher) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "11111111-1111-4111-8111-111111111111"
	f := &publicationFixture{now: now, e: artifact.ContextExpectation{Registration: artifact.Registration{Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, StoreID: id, AllocationID: id, PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: now, WriteUntil: now.Add(30 * time.Second), ExpiresAt: now.Add(time.Minute), DeleteBy: now.Add(90 * time.Second)}, CaseID: id, OccurrenceID: id, NodeUID: "node", NodeBootID: id, PodUID: "pod", Namespace: "app", NamespaceUID: "namespace", WorkloadUID: "workload", CollectorVersion: "test", CollectorImageDigest: artifact.Digest{1}, RecipeDigest: artifact.Digest{2}, PlanDigest: artifact.Digest{3}, CaptureUID: id, ActionID: "context", DataClass: "metadata", PurposeRef: "synthetic", Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://id.example.test", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: id, BasisDigest: artifact.Digest{4}}}, RequestedAgeSeconds: 60, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 30, RetentionRules: []artifact.RetentionRule{{UID: "retention", Generation: 1, Digest: artifact.Digest{5}}}, TriggeredAt: now}}
	for i := range f.copies {
		f.copies[i] = artifact.CopyReceipt{ETag: "synthetic", Bytes: 128, SHA256: artifact.Digest{byte(i + 1)}}
	}
	if f.e.Validate() != nil || f.copies.Validate(f.e.Registration) != nil {
		t.Fatal("invalid test fixture")
	}
	return f, ContextPublisher{Ledger: f, Authority: f, Verifier: f, Audit: f, Now: func() time.Time { return f.now }}
}
func TestContextPublicationEffectOrdering(t *testing.T) {
	f, p := publicationTest(t)
	if _, err := p.Publish(context.Background(), f.e.CaptureUID, f.copies); err != nil {
		t.Fatal(err)
	}
	want := []string{"accepted", "authority", "verify", "authority", "record", "audit", "ack", "authority", "publish"}
	if len(f.calls) != len(want) {
		t.Fatal(f.calls)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Fatal(f.calls)
		}
	}
	for _, failure := range []string{"accepted", "authority", "verify", "record", "audit", "ack"} {
		t.Run(failure, func(t *testing.T) {
			f, p := publicationTest(t)
			f.failure = failure
			if _, err := p.Publish(context.Background(), f.e.CaptureUID, f.copies); !errors.Is(err, privacy.ErrUnavailable) {
				t.Fatal(err)
			}
			for _, c := range f.calls {
				if c == "publish" {
					t.Fatal("failure published evidence")
				}
			}
		})
	}
}
func TestContextPublicationRechecksAfterBlockingWork(t *testing.T) {
	for _, point := range []string{"verify", "audit", "ack"} {
		t.Run(point, func(t *testing.T) {
			f, p := publicationTest(t)
			f.change = func(name string, f *publicationFixture) {
				if name == point {
					f.now = f.e.Registration.WriteUntil
				}
			}
			if _, err := p.Publish(context.Background(), f.e.CaptureUID, f.copies); err == nil {
				t.Fatal("deadline extended after I/O")
			}
			for _, c := range f.calls {
				if c == "publish" {
					t.Fatal("expired authority published")
				}
			}
		})
	}
	f, p := publicationTest(t)
	f.change = func(name string, f *publicationFixture) {
		if name == "verify" {
			f.e.Audience[0].SubjectID = "replacement"
		}
	}
	if _, err := p.Publish(context.Background(), f.e.CaptureUID, f.copies); err == nil {
		t.Fatal("changed accepted audience published")
	}
}
