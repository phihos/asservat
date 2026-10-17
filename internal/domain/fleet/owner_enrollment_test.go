package fleet

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func TestOwnerCertificateAttemptSurvivesJSONClockRepresentation(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	start := time.Now() // Includes the process-local monotonic clock.
	pool := OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "hub", ServiceUID: id, Deployment: "hub", DeploymentUID: id, ServiceAccount: "hub", AccountUID: id, Port: 8443}
	b := OwnerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}
	c := OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{{3}}}
	epoch, until, _ := OwnerCertificateWindow(start)
	e := OwnerEnrollment{ID: id, Binding: b, Usage: "server", Pool: pool, SourceUID: id, Pod: "hub-pod", ReplicaSet: "hub-rs", ReplicaSetUID: id, PublicKeyDigest: artifact.Digest{4}, InitialTokenDigest: artifact.Digest{5}, InitialWorkloadDigest: artifact.Digest{6}, InitialProtectionDigest: artifact.Digest{7}, ClaimedAt: start.UTC(), InitialHoldUntil: until.Add(OwnerRegistrationGrace)}
	p := OwnerCertificatePermit{ID: id, Binding: b, Usage: e.Usage, PublicKeyDigest: e.PublicKeyDigest, EnrollmentAudit: artifact.Digest{8}, Configuration: OwnerConfigurationObservation{Configuration: c, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}, Recovery: RecoveryState{InstallationID: id, IssuerEpoch: id, Revision: c.Revision, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}, Epoch: epoch, Ordinal: 1, CheckedAt: start.UTC(), SignBefore: start.Add(5 * time.Second), CertificateNotAfter: until}
	a := OwnerCertificateAttempt{Enrollment: e, Permit: p, TokenDigest: e.InitialTokenDigest, WorkloadDigest: e.InitialWorkloadDigest, ProtectionDigest: e.InitialProtectionDigest, ProofObservedAt: start, ProofFreshUntil: start.Add(5 * time.Second)}
	if !a.Valid(start) {
		t.Fatal("invalid original attempt")
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var stored OwnerCertificateAttempt
	if json.Unmarshal(raw, &stored) != nil || !stored.Valid(start) {
		t.Fatal("invalid stored attempt")
	}
	if !a.Equal(stored) || !stored.Equal(a) {
		t.Fatal("durable round trip changed equality despite identical identity and wall-clock deadlines")
	}
	for _, mode := range []string{"installation", "issuer", "revision", "observed", "until"} {
		changed := stored.Clone()
		switch mode {
		case "installation":
			changed.Permit.Recovery.InstallationID = "22222222-2222-4222-8222-222222222222"
		case "issuer":
			changed.Permit.Recovery.IssuerEpoch = "22222222-2222-4222-8222-222222222222"
		case "revision":
			changed.Permit.Recovery.Revision.Generation++
		case "observed":
			changed.Permit.Recovery.ObservedAt = changed.Permit.Recovery.ObservedAt.Add(time.Nanosecond)
		case "until":
			changed.Permit.Recovery.FreshUntil = changed.Permit.Recovery.FreshUntil.Add(time.Nanosecond)
		}
		if a.Equal(changed) {
			t.Fatal("changed recovery accepted", mode)
		}
	}
}

func TestOwnerEnrollmentMatchesConfigurationObservedDuringProof(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	start := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	pool := OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "hub", ServiceUID: id, Deployment: "hub", DeploymentUID: id, ServiceAccount: "hub", AccountUID: id, Port: 8443}
	binding := OwnerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}
	c := OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{{3}}}
	for _, mode := range []string{"same-time", "observed-during-proof", "cached", "nonoverlapping", "extended-proof", "extended-configuration"} {
		t.Run(mode, func(t *testing.T) {
			p := OwnerEnrollmentProof{Binding: binding, Usage: "server", Configuration: OwnerConfigurationObservation{Configuration: c, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}, Pod: "hub-pod", ReplicaSet: "hub-rs", ReplicaSetUID: id, PublicKeyDigest: artifact.Digest{4}, TokenDigest: artifact.Digest{5}, WorkloadDigest: artifact.Digest{6}, ProtectionDigest: artifact.Digest{7}, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}
			valid := true
			switch mode {
			case "observed-during-proof":
				p.Configuration.ObservedAt = start.Add(time.Second)
				p.Configuration.FreshUntil = start.Add(6 * time.Second)
			case "cached":
				p.Configuration.ObservedAt = start.Add(-time.Second)
				p.Configuration.FreshUntil = start.Add(4 * time.Second)
				p.FreshUntil = p.Configuration.FreshUntil
			case "nonoverlapping":
				p.Configuration.ObservedAt = p.FreshUntil
				p.Configuration.FreshUntil = start.Add(10 * time.Second)
				valid = false
			case "extended-proof":
				p.FreshUntil = p.FreshUntil.Add(time.Nanosecond)
				valid = false
			case "extended-configuration":
				p.Configuration.FreshUntil = p.Configuration.FreshUntil.Add(time.Nanosecond)
				valid = false
			}
			claimed := start.Add(2 * time.Second)
			_, until, _ := OwnerCertificateWindow(claimed)
			e := OwnerEnrollment{ID: id, Binding: binding, Usage: p.Usage, Pool: pool, SourceUID: id, Pod: p.Pod, ReplicaSet: p.ReplicaSet, ReplicaSetUID: id, PublicKeyDigest: p.PublicKeyDigest, InitialTokenDigest: p.TokenDigest, InitialWorkloadDigest: p.WorkloadDigest, InitialProtectionDigest: p.ProtectionDigest, ClaimedAt: claimed, InitialHoldUntil: until.Add(OwnerRegistrationGrace)}
			if got := e.Matches(p); got != valid {
				t.Fatalf("match=%v want=%v; a configuration read may finish after the original proof start", got, valid)
			}
			if valid && (!p.Valid(claimed) || p.Valid(p.FreshUntil)) {
				t.Fatal("original freshness interval changed")
			}
		})
	}
}
