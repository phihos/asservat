package fleet

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func TestOwnerBootstrapLegacyBytesAndRetainedRowBounds(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	pool := OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: strings.Repeat("n", 63), NamespaceUID: id, Service: strings.Repeat("s", 63), ServiceUID: id, Deployment: strings.Repeat("d", 253), DeploymentUID: id, ServiceAccount: strings.Repeat("a", 253), AccountUID: id, Port: 65534, NativePort: 65535}
	// The historical struct deliberately has no capability field. Its JSON is
	// what existing signed/encrypted configuration and enrollment records retain.
	historical := struct {
		InstallationID, ClusterID, IssuerEpoch                string
		Namespace, NamespaceUID, Service, ServiceUID          string
		Deployment, DeploymentUID, ServiceAccount, AccountUID string
		Port                                                  int
		NativePort                                            int `json:",omitzero"`
	}{pool.InstallationID, pool.ClusterID, pool.IssuerEpoch, pool.Namespace, pool.NamespaceUID, pool.Service, pool.ServiceUID, pool.Deployment, pool.DeploymentUID, pool.ServiceAccount, pool.AccountUID, pool.Port, pool.NativePort}
	old, e := json.Marshal(historical)
	if e != nil {
		t.Fatal(e)
	}
	current, e := json.Marshal(pool)
	if e != nil || !bytes.Equal(old, current) {
		t.Fatal("omitted profile changed historical bytes", e)
	}
	var decoded OwnerPool
	if e = json.Unmarshal(old, &decoded); e != nil || decoded != pool {
		t.Fatal("historical pool no longer decodes", e)
	}
	pool.NativeBootstrap = OwnerBootstrapProfile
	if !pool.Valid() {
		t.Fatal("valid bounded opted pool rejected")
	}
	// Public root bytes here exercise only structural envelope maxima, not X.509
	// authority. DER and actual chains are independently checked in adapter tests.
	roots := [][]byte{bytes.Repeat([]byte{1}, 16<<10), bytes.Repeat([]byte{2}, 16<<10)}
	now := time.Date(2026, 10, 12, 12, 0, 1, 999999000, time.UTC)
	epoch, until, _ := OwnerCertificateWindow(now)
	config := OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: id, Generation: 2147483647, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: roots}
	enrollment := OwnerEnrollment{ID: id, Binding: OwnerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}, Usage: "server", Pool: pool, SourceUID: id, Pod: strings.Repeat("p", 253), ReplicaSet: strings.Repeat("r", 253), ReplicaSetUID: id, PublicKeyDigest: artifact.Digest{3}, InitialTokenDigest: artifact.Digest{4}, InitialWorkloadDigest: artifact.Digest{5}, InitialProtectionDigest: artifact.Digest{6}, ClaimedAt: now, InitialHoldUntil: until.Add(OwnerRegistrationGrace)}
	permit := OwnerCertificatePermit{ID: id, Binding: enrollment.Binding, Usage: "server", PublicKeyDigest: enrollment.PublicKeyDigest, EnrollmentAudit: artifact.Digest{7}, Configuration: OwnerConfigurationObservation{Configuration: config, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Recovery: RecoveryState{InstallationID: id, IssuerEpoch: id, Revision: identity.Revision{UID: id, Generation: 2147483647, Digest: artifact.Digest{8}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Epoch: epoch, Ordinal: 2, CheckedAt: now, SignBefore: now.Add(5 * time.Second), CertificateNotAfter: until}
	attempt := OwnerCertificateAttempt{Enrollment: enrollment, Permit: permit, TokenDigest: artifact.Digest{4}, WorkloadDigest: artifact.Digest{5}, ProtectionDigest: artifact.Digest{6}, ProofObservedAt: now, ProofFreshUntil: now.Add(5 * time.Second)}
	if !config.Valid() || !enrollment.Valid() || !attempt.Valid(now) {
		t.Fatal("maximum envelope fixture invalid")
	}
	for _, test := range []struct {
		name    string
		value   any
		maximum int
	}{{"source", config, 64 << 10}, {"enrollment", enrollment, 16 << 10}, {"attempt", attempt, 64 << 10}} {
		encoded, e := json.Marshal(test.value)
		if e != nil || len(encoded) > test.maximum {
			t.Fatalf("%s size=%d maximum=%d error=%v", test.name, len(encoded), test.maximum, e)
		}
		t.Logf("%s maximum structural envelope=%d bound=%d", test.name, len(encoded), test.maximum)
	}
}
