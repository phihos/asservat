package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func ownerReceiptVersionFacts(t *testing.T) (value.OwnerConfiguration, value.OwnerEnrollment, OwnerCertificate) {
	t.Helper()
	const id = "11111111-1111-4111-8111-111111111111"
	start := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	pool := value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "hub", ServiceUID: id, Deployment: "hub", DeploymentUID: id, ServiceAccount: "hub", AccountUID: id, Port: 8443}
	binding := value.OwnerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}
	c := value.OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{{3}}}
	epoch, until, err := value.OwnerCertificateWindow(start)
	if err != nil {
		t.Fatal(err)
	}
	e := value.OwnerEnrollment{ID: id, Binding: binding, Usage: "server", Pool: pool, SourceUID: id, Pod: "hub-pod", ReplicaSet: "hub-rs", ReplicaSetUID: id, PublicKeyDigest: artifact.Digest{4}, InitialTokenDigest: artifact.Digest{5}, InitialWorkloadDigest: artifact.Digest{6}, InitialProtectionDigest: artifact.Digest{7}, ClaimedAt: start, InitialHoldUntil: until.Add(value.OwnerRegistrationGrace)}
	p := value.OwnerCertificatePermit{ID: id, Binding: binding, Usage: e.Usage, PublicKeyDigest: e.PublicKeyDigest, EnrollmentAudit: artifact.Digest{8}, Configuration: value.OwnerConfigurationObservation{Configuration: c, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}, Recovery: value.RecoveryState{InstallationID: id, IssuerEpoch: id, Revision: c.Revision, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}, Epoch: epoch, Ordinal: 1, CheckedAt: start, SignBefore: start.Add(5 * time.Second), CertificateNotAfter: until}
	a := value.OwnerCertificateAttempt{Enrollment: e, Permit: p, TokenDigest: e.InitialTokenDigest, WorkloadDigest: e.InitialWorkloadDigest, ProtectionDigest: e.InitialProtectionDigest, ProofObservedAt: start, ProofFreshUntil: start.Add(5 * time.Second)}
	cert := OwnerCertificate{Attempt: a, Certificate: value.OwnerCertificate{Binding: binding, Usage: "server", Digest: artifact.Digest{9}, NotBefore: start, NotAfter: until}}
	if !c.Valid() || !e.Valid() || !cert.Valid() {
		t.Fatal("invalid synthetic owner history fixture")
	}
	return c, e, cert
}

func TestOwnerCurrentAuditReceiptsRequireImmutableVersions(t *testing.T) {
	c, e, cert := ownerReceiptVersionFacts(t)
	for _, purpose := range []struct {
		name, key string
		valid     func(Receipt) bool
	}{
		{"configuration", OwnerConfigurationAuditKey(c), func(r Receipt) bool { return r.ValidOwnerConfiguration(c) }},
		{"enrollment", OwnerEnrollmentKey(e), func(r Receipt) bool { return r.ValidOwnerEnrollment(e) }},
		{"certificate", OwnerCertificateKey(cert), func(r Receipt) bool { return r.ValidOwnerCertificate(cert) }},
	} {
		for _, tc := range []struct {
			name, version string
			want          bool
		}{
			{"immutable", "original-version", true}, {"empty", "", false}, {"null", "null", false}, {"maximum", strings.Repeat("v", 1024), true}, {"oversize", strings.Repeat("v", 1025), false},
		} {
			t.Run(purpose.name+"/"+tc.name, func(t *testing.T) {
				r := Receipt{Key: purpose.key, Version: tc.version, ETag: "original", Bytes: 17, SHA256: artifact.Digest{10}}
				raw, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				var retained Receipt
				if err = json.Unmarshal(raw, &retained); err != nil {
					t.Fatal("historical bytes stopped decoding", err)
				}
				if got := purpose.valid(retained); got != tc.want {
					t.Fatalf("current authority=%v, want %v for retained version %q", got, tc.want, tc.version)
				}
				again, err := json.Marshal(retained)
				if err != nil || !bytes.Equal(raw, again) || retained != r {
					t.Fatal("checking current authority changed historical receipt bytes", err)
				}
			})
		}
	}
}

func TestOwnerVersionRequirementDoesNotReinterpretOtherReceiptFormats(t *testing.T) {
	// The owner-specific change is not a migration of acquisition-worker or
	// operation history. Their separate active-store/authority decisions are
	// outside this component; the shared helper remains structurally unchanged.
	for _, version := range []string{"", "null", "original-version"} {
		r := Receipt{Key: "historical-worker", Version: version, ETag: "original", Bytes: 17, SHA256: artifact.Digest{10}}
		if !r.workerReceipt(r.Key) {
			t.Fatal("owner rule changed shared worker history", version)
		}
	}
}
