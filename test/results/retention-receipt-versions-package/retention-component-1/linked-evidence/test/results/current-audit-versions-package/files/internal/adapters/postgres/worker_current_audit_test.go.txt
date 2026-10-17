package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
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

func TestCurrentWorkerChecksExactRetainedReceiptWithoutBlockingHistoricalDecode(t *testing.T) {
	w := versionWorkerFixture(t)
	encode := func(v any) []byte {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	receipt := audit.Receipt{Key: audit.DownloadWorkerAuditKey(w.Intent), Version: "original", ETag: "original", Bytes: 17, SHA256: artifact.Digest{8}}
	row := custodydb.DownloadWorker{ID: id(w.Intent.ID), SessionID: id(w.Intent.SessionID), RootID: id(w.Intent.Authority.Scope.RootID), InstallationID: id(w.Binding.InstallationID), Generation: w.Intent.Generation, RunUntil: ts(w.Intent.RunUntil), ClaimedAt: ts(w.Intent.CreatedAt), IntentJson: encode(w.Intent), JobJson: encode(w.Job), BindingJson: encode(w.Binding)}
	for _, mode := range []string{"valid", "missing", "empty", "null", "wrong-key", "missing-digest", "malformed", "unclaimed"} {
		t.Run(mode, func(t *testing.T) {
			candidate := row
			r := receipt
			switch mode {
			case "empty":
				r.Version = ""
			case "null":
				r.Version = "null"
			case "wrong-key":
				r.Key += "/replacement"
			case "missing-digest":
				r.SHA256 = artifact.Digest{}
			case "unclaimed":
				candidate.ClaimedAt.Valid = false
			}
			candidate.AuditReceiptJson = encode(r)
			if mode == "missing" {
				candidate.AuditReceiptJson = nil
			}
			if mode == "malformed" {
				candidate.AuditReceiptJson = []byte("{")
			}
			before := bytes.Clone(candidate.AuditReceiptJson)
			got, e := currentAuditedWorker(candidate)
			if mode == "valid" {
				if e != nil || got != w {
					t.Fatal("original current worker denied", e)
				}
			} else if e == nil {
				t.Fatal("invalid retained acknowledgement became current")
			}
			historical, e := decodeWorker(candidate)
			if e != nil || historical != w {
				t.Fatal("historical cleanup identity became unavailable", e)
			}
			if !bytes.Equal(before, candidate.AuditReceiptJson) {
				t.Fatal("current check repaired history")
			}
		})
	}
}
