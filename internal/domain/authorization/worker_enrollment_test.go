package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"strings"
	"testing"
	"time"
)

func enrollmentWorkerFixture(t *testing.T) DownloadWorker {
	t.Helper()
	now := time.Date(2026, 10, 10, 12, 0, 0, 500000000, time.UTC)
	id := "10000000-0000-4000-8000-000000000001"
	rev := identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}
	principal := identity.Principal{Issuer: "https://synthetic.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}
	scope := artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, Principal: principal}
	a := artifact.DownloadAuthority{Scope: scope, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: rev, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), AccessUntil: now.Add(8 * time.Hour)}
	a.Environment = artifact.DownloadEnvironment{RootID: id, InstallationID: id, Region: "synthetic", StoreID: id, RecoveryEpoch: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, Principal: principal, Revision: rev, RecoveryRevision: rev, ObservedAt: now, ValidUntil: a.ValidUntil}
	p := DownloadWorkerProfile{Configuration: rev, InstallationID: id, ClusterID: id, Namespace: "workers", NamespaceUID: "ns", ServiceAccount: "acquisition", ServiceAccountUID: "sa", Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", ControlConfigUID: "config", PriorityClass: "workers", PriorityClassUID: "priority", ControlDigest: artifact.Digest{1}, CPUMillis: 100, MemoryBytes: 64 << 20, MaxRuntime: 8 * time.Hour}
	i := DownloadWorkerIntent{ID: id, SessionID: id, Generation: 1, Profile: p, Authority: a, CreatedAt: now, RunUntil: a.AccessUntil}
	j := DownloadWorkerJob{IntentID: id, UID: "job", Spec: artifact.Digest{1}}
	b := KeyWorkerBinding{InstallationID: id, DownloadID: id, ClusterID: id, Namespace: p.Namespace, NamespaceUID: p.NamespaceUID, ServiceAccount: p.ServiceAccount, ServiceAccountUID: p.ServiceAccountUID, Job: i.JobName(), JobUID: j.UID, JobSpec: j.Spec, Pod: "worker", PodUID: id, PodSpec: artifact.Digest{2}}
	w := DownloadWorker{Intent: i, Job: j, Binding: b}
	if !w.Valid() {
		t.Fatal("invalid enrollment fixture")
	}
	return w
}
func TestWorkerCertificatePeriodsBoundRenewalWithoutExtendingWorker(t *testing.T) {
	w := enrollmentWorkerFixture(t)
	start := w.Intent.CreatedAt
	periods := map[int]bool{}
	for n := time.Duration(0); n < 8*time.Hour-time.Second; n += time.Second {
		epoch, until, e := WorkerCertificateEpoch(w, start.Add(n))
		if e != nil || epoch < 0 || epoch >= 24 || !start.Add(n).Before(until) || until.After(w.Intent.RunUntil) || until.Sub(start.Add(n)) > 21*time.Minute {
			t.Fatal("unbounded renewal", n, epoch, until, e)
		}
		periods[epoch] = true
	}
	if len(periods) != 24 {
		t.Fatal("unexpected renewal budget", len(periods))
	}
	for _, tc := range []struct {
		offset time.Duration
		epoch  int
		until  time.Duration
	}{{0, 0, 20 * time.Minute}, {19*time.Minute - time.Nanosecond, 0, 20 * time.Minute}, {19 * time.Minute, 1, 40 * time.Minute}, {39 * time.Minute, 2, 60 * time.Minute}, {7*time.Hour + 59*time.Minute, 23, 8 * time.Hour}} {
		epoch, until, e := WorkerCertificateEpoch(w, start.Add(tc.offset))
		if e != nil || epoch != tc.epoch || !until.Equal(start.Add(tc.until).Truncate(time.Second)) {
			t.Fatal("period or absolute deadline moved", tc, epoch, until, e)
		}
	}
	if _, _, e := WorkerCertificateEpoch(w, w.Intent.RunUntil); e == nil {
		t.Fatal("renewed expired worker")
	}
	if _, _, e := WorkerCertificateEpoch(w, start.Add(-time.Second)); e == nil {
		t.Fatal("renewed future worker")
	}
	w.Intent.RunUntil = start.Add(10 * time.Second)
	epoch, until, e := WorkerCertificateEpoch(w, start)
	if e != nil || epoch != 0 || !until.Equal(w.Intent.RunUntil.Truncate(time.Second)) {
		t.Fatal("short worker cutoff", epoch, until, e)
	}
}
func TestWorkerCertificateAttemptCannotChangeKeyOrRenewOriginalProof(t *testing.T) {
	w := enrollmentWorkerFixture(t)
	now := w.Intent.CreatedAt
	key := artifact.Digest{3}
	proof := WorkerEnrollmentProof{Worker: w, PublicKeyDigest: key, TokenDigest: artifact.Digest{4}, ObservedAt: now, FreshUntil: now.Add(time.Second)}
	e := WorkerEnrollment{Worker: w, PublicKeyDigest: key, ClaimedAt: now}
	epoch, until, err := WorkerCertificateEpoch(w, now)
	if err != nil {
		t.Fatal(err)
	}
	a := WorkerCertificateAttempt{ID: w.Intent.ID, Epoch: epoch, Ordinal: 1, Enrollment: e, Proof: proof, RecoveryEpoch: w.Intent.Profile.InstallationID, EnrollmentAudit: artifact.Digest{5}, CheckedAt: now, SignBefore: proof.FreshUntil, CertificateNotAfter: until}
	if !a.Valid(now) {
		t.Fatal("invalid attempt")
	}
	for _, mutate := range []func(*WorkerCertificateAttempt){func(a *WorkerCertificateAttempt) { a.Enrollment.PublicKeyDigest[0]++ }, func(a *WorkerCertificateAttempt) { a.SignBefore = a.SignBefore.Add(time.Second) }, func(a *WorkerCertificateAttempt) { a.Ordinal = 3 }, func(a *WorkerCertificateAttempt) { a.Epoch++ }, func(a *WorkerCertificateAttempt) { a.CertificateNotAfter = a.CertificateNotAfter.Add(time.Second) }, func(a *WorkerCertificateAttempt) { a.EnrollmentAudit = artifact.Digest{} }} {
		bad := a
		mutate(&bad)
		if bad.Valid(now) {
			t.Fatal("invalid signing attempt accepted")
		}
	}
	if a.Valid(a.SignBefore) {
		t.Fatal("signing permit renewed after expiry")
	}
}
