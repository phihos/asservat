package fleet

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
)

type bootstrapCalls struct{ log []string }

func (c *bootstrapCalls) add(s string) { c.log = append(c.log, s) }

type fakeClaims struct {
	c *bootstrapCalls
	e value.Enrollment
}

func (f fakeClaims) ClaimConnector(context.Context, value.EnrollmentClaim) (value.Enrollment, error) {
	f.c.add("claim")
	return f.e, nil
}

type fakeClaimAudits struct {
	c *bootstrapCalls
	r audit.EnrollmentClaim
}

func (f fakeClaimAudits) ReadEnrollmentClaim(context.Context, string, string) (audit.EnrollmentClaim, error) {
	f.c.add("claim-read")
	return f.r, nil
}
func (f fakeClaimAudits) PendingEnrollmentClaims(context.Context) ([]audit.EnrollmentClaim, error) {
	return nil, nil
}
func (f fakeClaimAudits) AcknowledgeEnrollmentClaim(context.Context, audit.EnrollmentClaim, audit.Receipt) error {
	f.c.add("claim-ack")
	return nil
}

type fakeClaimObjects struct{ c *bootstrapCalls }

func (f fakeClaimObjects) WriteEnrollmentClaim(_ context.Context, r audit.EnrollmentClaim) (audit.Receipt, error) {
	f.c.add("claim-write")
	return audit.Receipt{Key: "enrollment-claim/v1/" + r.Binding.InstallationID + "/" + r.BootstrapID + "/record", Version: "1", ETag: "e", Bytes: 1, SHA256: artifact.Digest{1}}, nil
}

type fakeBootstraps struct {
	c            *bootstrapCalls
	acknowledged bool
	fenced       bool
	key          artifact.Digest
}

func (f *fakeBootstraps) Reserve(context.Context, string, string, []byte, value.ClusterBootstrapSource, value.ClusterCredentialPolicy) (string, error) {
	f.c.add("reserve")
	return "10000000-0000-4000-8000-000000000099", nil
}
func (f *fakeBootstraps) Acknowledge(context.Context, audit.ClusterBootstrap, audit.Receipt) error {
	f.c.add("audit-ack")
	f.acknowledged = true
	return nil
}
func (f *fakeBootstraps) Activate(context.Context, string, artifact.Digest, []byte) (value.ClusterBootstrapResult, error) {
	f.c.add("activate")
	if f.fenced {
		return value.ClusterBootstrapResult{}, value.ErrClusterCredentialFenced
	}
	if !f.acknowledged {
		return value.ClusterBootstrapResult{}, value.ErrClusterCredentialDenied
	}
	now := time.Now()
	return value.ClusterBootstrapResult{LineageID: "10000000-0000-4000-8000-000000000099", Generation: 1, KeyDigest: f.key, IssuedAt: now, ValidUntil: now.Add(time.Hour)}, nil
}

type fakeBootstrapAudit struct{ c *bootstrapCalls }

func (f fakeBootstrapAudit) WriteClusterBootstrap(_ context.Context, r audit.ClusterBootstrap) (audit.Receipt, error) {
	f.c.add("audit-write")
	return audit.Receipt{Key: audit.ClusterBootstrapAuditKey(r), Version: "1", ETag: "e", Bytes: 1, SHA256: artifact.Digest{2}}, nil
}

// ADR-193: one conversation probes replay first, then claims and audits the
// claim, stages the source, reserves, writes and acknowledges the
// generation-1 audit, and only then activates.
func TestClusterBootstrapActivationOrder(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	e := bootstrapEnvelopeFixture(now)
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 3
	key := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	digest := ClusterBootstrapKeyDigest(key)
	b := e.Binding
	r := value.ClusterBootstrapRequest{InstallationID: b.InstallationID, BootstrapID: e.BootstrapID, RootID: "10000000-0000-4000-8000-000000000001", ClusterID: b.ClusterID, PeerID: b.PeerID, IssuerEpoch: b.IssuerEpoch, KeyDigest: digest, SecretDigest: artifact.Digest{4}, RequestedAt: now}
	enrollment := value.Enrollment{BootstrapID: e.BootstrapID, Binding: b, PublicKeyDigest: digest, ClaimedAt: now, NotAfter: now.Add(4 * time.Minute)}
	claim := audit.EnrollmentClaim{BootstrapID: e.BootstrapID, Binding: b, PublicKeyDigest: digest, IssueAuthorityDigest: artifact.Digest{5}, IssueAuditDigest: artifact.Digest{6}, IssueAuditID: "10000000-0000-4000-8000-000000000013", IssuedAt: now.Add(-time.Second), ClaimedAt: now, NotAfter: now.Add(4 * time.Minute)}
	calls := &bootstrapCalls{}
	ledger := &fakeBootstraps{c: calls, key: digest}
	s := ClusterBootstrapActivation{Claims: fakeClaims{calls, enrollment}, ClaimAudits: fakeClaimAudits{calls, claim}, ClaimObjects: fakeClaimObjects{calls}, Bootstraps: ledger, Audit: fakeBootstrapAudit{calls},
		Policy: value.DefaultClusterCredentialPolicy(), Now: time.Now}
	stage := func(context.Context, value.Enrollment) (value.ClusterBootstrapSource, error) {
		calls.add("stage")
		return value.ClusterBootstrapSource{UID: "10000000-0000-4000-8000-000000000014", Generation: 1, ProtectionDigest: artifact.Digest{7}}, nil
	}
	result, err := s.Activate(context.Background(), r, key, stage)
	if err != nil || result.Generation != 1 {
		t.Fatal(err)
	}
	if got := strings.Join(calls.log, ","); got != "activate,claim,claim-read,claim-write,claim-ack,stage,reserve,audit-write,audit-ack,activate" {
		t.Fatal("unexpected order", got)
	}
	calls.log = nil
	if again, err := s.Activate(context.Background(), r, key, stage); err != nil || len(calls.log) != 1 || again.LineageID != result.LineageID {
		t.Fatal("replay did not return the original result alone", calls.log, err)
	}
	ledger.fenced = true
	if _, err = s.Activate(context.Background(), r, key, stage); !errors.Is(err, value.ErrClusterCredentialFenced) {
		t.Fatal("fence not passed through", err)
	}
	other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, err = s.Activate(context.Background(), r, other, stage); !errors.Is(err, value.ErrDenied) {
		t.Fatal("key other than the signed digest accepted", err)
	}
}
