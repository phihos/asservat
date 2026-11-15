package mtls

import (
	"context"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type forwardRoutes func(context.Context, fleet.OwnerBinding) (fleet.OwnerRoute, error)

func (f forwardRoutes) CurrentOwnerRoute(c context.Context, b fleet.OwnerBinding) (fleet.OwnerRoute, error) {
	return f(c, b)
}

type forwardRegistry func(context.Context, fleet.OwnerCertificate) (fleet.OwnerRegistrationObservation, error)

func (f forwardRegistry) ReadOwnerRegistration(c context.Context, b fleet.OwnerCertificate) (fleet.OwnerRegistrationObservation, error) {
	return f(c, b)
}

type forwardGuard func(context.Context, fleet.OwnerPool) (fleet.OwnerProtection, error)

func (f forwardGuard) ReadOwnerProtection(c context.Context, p fleet.OwnerPool) (fleet.OwnerProtection, error) {
	return f(c, p)
}

func forwardTestWorker(t *testing.T) value.DownloadWorker {
	t.Helper()
	id := ownerTestID
	now := time.Now().UTC().Truncate(time.Second)
	rev := identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}
	profile := value.DownloadWorkerProfile{Configuration: rev, InstallationID: id, ClusterID: id, Namespace: "workers", NamespaceUID: "namespace", ServiceAccount: "acquisition", ServiceAccountUID: "account", Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", ControlConfigUID: "config", PriorityClass: "workers", PriorityClassUID: "priority", CPUMillis: 100, MemoryBytes: 64 << 20, MaxRuntime: time.Minute}
	scope := artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{2}, Principal: identity.Principal{Issuer: "https://synthetic.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}}
	a := artifact.DownloadAuthority{Scope: scope, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{3}, DecisionDigest: artifact.Digest{4}, IdentityRevision: rev, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), AccessUntil: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}
	a.Environment = artifact.DownloadEnvironment{RootID: id, InstallationID: id, Region: "test", StoreID: id, RecoveryEpoch: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, Principal: scope.Principal, Revision: rev, ObservedAt: now, ValidUntil: a.ValidUntil}
	intent := value.DownloadWorkerIntent{ID: id, SessionID: id, Generation: 1, Profile: profile, Authority: a, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	job := value.DownloadWorkerJob{IntentID: id, UID: "job", Spec: artifact.Digest{5}}
	w := value.DownloadWorker{Intent: intent, Job: job, Binding: value.KeyWorkerBinding{InstallationID: id, DownloadID: id, ClusterID: id, Namespace: profile.Namespace, NamespaceUID: profile.NamespaceUID, ServiceAccount: profile.ServiceAccount, ServiceAccountUID: profile.ServiceAccountUID, Job: intent.JobName(), JobUID: job.UID, JobSpec: job.Spec, Pod: "worker", PodUID: id, PodSpec: artifact.Digest{6}}}
	if !w.Valid() {
		t.Fatal("invalid synthetic worker")
	}
	return w
}
