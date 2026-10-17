package audit_test

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func versionWorkerFixture(t *testing.T) value.DownloadWorker {
	t.Helper()
	now := time.Date(2026, 10, 10, 12, 0, 0, 500000000, time.UTC)
	id := "10000000-0000-4000-8000-000000000001"
	rev := identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}
	principal := identity.Principal{Issuer: "https://synthetic.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}
	scope := artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, Principal: principal}
	a := artifact.DownloadAuthority{Scope: scope, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: rev, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), AccessUntil: now.Add(8 * time.Hour)}
	a.Environment = artifact.DownloadEnvironment{RootID: id, InstallationID: id, Region: "synthetic", StoreID: id, RecoveryEpoch: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, Principal: principal, Revision: rev, RecoveryRevision: rev, ObservedAt: now, ValidUntil: a.ValidUntil}
	p := value.DownloadWorkerProfile{Configuration: rev, InstallationID: id, ClusterID: id, Namespace: "workers", NamespaceUID: "ns", ServiceAccount: "acquisition", ServiceAccountUID: "sa", Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", ControlConfigUID: "config", PriorityClass: "workers", PriorityClassUID: "priority", ControlDigest: artifact.Digest{1}, CPUMillis: 100, MemoryBytes: 64 << 20, MaxRuntime: 8 * time.Hour}
	i := value.DownloadWorkerIntent{ID: id, SessionID: id, Generation: 1, Profile: p, Authority: a, CreatedAt: now, RunUntil: a.AccessUntil}
	j := value.DownloadWorkerJob{IntentID: id, UID: "job", Spec: artifact.Digest{1}}
	b := value.KeyWorkerBinding{InstallationID: id, DownloadID: id, ClusterID: id, Namespace: p.Namespace, NamespaceUID: p.NamespaceUID, ServiceAccount: p.ServiceAccount, ServiceAccountUID: p.ServiceAccountUID, Job: i.JobName(), JobUID: j.UID, JobSpec: j.Spec, Pod: "worker", PodUID: id, PodSpec: artifact.Digest{2}}
	w := value.DownloadWorker{Intent: i, Job: j, Binding: b}
	if !w.Valid() {
		t.Fatal("invalid enrollment fixture")
	}
	return w
}

func TestReachableAuditReceiptsRequireImmutableVersions(t *testing.T) {
	w := versionWorkerFixture(t)
	n := w.Intent.CreatedAt
	id := w.Intent.ID
	c := value.DownloadWorkerConfiguration{Profile: w.Intent.Profile, RecoveryEpoch: id, ProtectionDigest: artifact.Digest{3}}
	en := value.WorkerEnrollment{Worker: w, PublicKeyDigest: artifact.Digest{4}, ClaimedAt: n}
	epoch, end, err := value.WorkerCertificateEpoch(w, n)
	if err != nil {
		t.Fatal(err)
	}
	proof := value.WorkerEnrollmentProof{Worker: w, PublicKeyDigest: en.PublicKeyDigest, TokenDigest: artifact.Digest{5}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
	attempt := value.WorkerCertificateAttempt{ID: id, Epoch: epoch, Ordinal: 1, Enrollment: en, Proof: proof, RecoveryEpoch: id, EnrollmentAudit: artifact.Digest{6}, CheckedAt: n, SignBefore: proof.FreshUntil, CertificateNotAfter: end}
	cert := audit.WorkerCertificate{Attempt: attempt, Peer: value.KeyPeer{InstallationID: w.Binding.InstallationID, PeerID: w.Binding.PodUID, Role: "acquisition", Certificate: artifact.Digest{7}, NotBefore: n, NotAfter: end}}
	window := windowAuditFixture()
	if !c.Valid() || !en.Valid() || !cert.Valid() || !window.Valid() {
		t.Fatal("invalid public synthetic audit facts")
	}
	for _, purpose := range []struct {
		name, key string
		valid     func(audit.Receipt) bool
	}{
		{"worker-configuration", audit.WorkerConfigurationAuditKey(c), func(r audit.Receipt) bool { return r.ValidWorkerConfiguration(c) }},
		{"worker-intent", audit.DownloadWorkerAuditKey(w.Intent), func(r audit.Receipt) bool { return r.ValidDownloadWorker(w.Intent) }},
		{"worker-enrollment", audit.WorkerEnrollmentKey(en), func(r audit.Receipt) bool { return r.ValidWorkerEnrollment(en) }},
		{"worker-certificate", audit.WorkerCertificateKey(cert), func(r audit.Receipt) bool { return r.ValidWorkerCertificate(cert) }},
		{"connector-enrollment", audit.EnrollmentClaimKey(id, id), func(r audit.Receipt) bool { return r.ValidEnrollmentClaim(id, id) }},
		{"connector-certificate", audit.EnrollmentCertificateKey(id, id), func(r audit.Receipt) bool { return r.ValidEnrollmentCertificate(id, id) }},
		{"batch-intent", audit.DownloadAuditKey(id, id, id, "intent"), func(r audit.Receipt) bool { return r.ValidDownload(id, id, id, "intent") }},
		{"batch-outcome", audit.DownloadAuditKey(id, id, id, "outcome"), func(r audit.Receipt) bool { return r.ValidDownload(id, id, id, "outcome") }},
		{"window-intent", audit.DownloadWindowAuditKey(window.Window.Authority.Scope.RootID, window.Response.ID, window.Window.ID, "intent"), func(r audit.Receipt) bool { return r.ValidDownloadWindow(window, "intent") }},
		{"window-outcome", audit.DownloadWindowAuditKey(window.Window.Authority.Scope.RootID, window.Response.ID, window.Window.ID, "outcome"), func(r audit.Receipt) bool { return r.ValidDownloadWindow(window, "outcome") }},
	} {
		for _, tc := range []struct {
			name, version string
			want          bool
		}{{"immutable", "original", true}, {"empty", "", false}, {"null", "null", false}, {"maximum", strings.Repeat("v", 1024), true}, {"oversize", strings.Repeat("v", 1025), false}} {
			t.Run(purpose.name+"/"+tc.name, func(t *testing.T) {
				r := audit.Receipt{Key: purpose.key, Version: tc.version, ETag: "original", Bytes: 17, SHA256: artifact.Digest{9}}
				raw, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				var retained audit.Receipt
				if json.Unmarshal(raw, &retained) != nil {
					t.Fatal("history stopped decoding")
				}
				if purpose.valid(retained) != tc.want {
					t.Fatalf("current authority does not match immutable-version requirement for %q", tc.version)
				}
				after, err := json.Marshal(retained)
				if err != nil || !bytes.Equal(after, raw) {
					t.Fatal("validation changed historical bytes")
				}
			})
		}
	}
}
