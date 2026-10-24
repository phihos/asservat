package bootstrap

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

type installedAuditRecords struct {
	bootstrap   audit.BootstrapIssue
	worker      authorization.DownloadWorker
	enrollment  authorization.WorkerEnrollment
	certificate audit.WorkerCertificate
	download    audit.DownloadIntent
	window      audit.DownloadWindowIntent
	stop        artifact.DownloadStopDecision
	stopBinding audit.DownloadStopLifecycleBinding
}

func providerAuditRecords(t *testing.T) installedAuditRecords {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "10000000-0000-4000-8000-000000000001"
	rev := identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}
	principal := identity.Principal{Issuer: "https://synthetic.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}
	scope := artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, Principal: principal}
	authority := artifact.DownloadAuthority{Scope: scope, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: rev, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), AccessUntil: now.Add(8 * time.Hour)}
	authority.Environment = artifact.DownloadEnvironment{RootID: id, InstallationID: id, Region: "synthetic", StoreID: id, RecoveryEpoch: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, Principal: principal, Revision: rev, RecoveryRevision: rev, ObservedAt: now, ValidUntil: authority.ValidUntil}
	p := authorization.DownloadWorkerProfile{Configuration: rev, InstallationID: id, ClusterID: id, Namespace: "workers", NamespaceUID: "ns", ServiceAccount: "acquisition", ServiceAccountUID: "sa", Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", ControlConfigUID: "config", PriorityClass: "workers", PriorityClassUID: "priority", ControlDigest: artifact.Digest{1}, CPUMillis: 100, MemoryBytes: 64 << 20, MaxRuntime: 8 * time.Hour}
	i := authorization.DownloadWorkerIntent{ID: id, SessionID: id, Generation: 1, Profile: p, Authority: authority, CreatedAt: now, RunUntil: authority.AccessUntil}
	job := authorization.DownloadWorkerJob{IntentID: id, UID: "job", Spec: artifact.Digest{1}}
	binding := authorization.KeyWorkerBinding{InstallationID: id, DownloadID: id, ClusterID: id, Namespace: p.Namespace, NamespaceUID: p.NamespaceUID, ServiceAccount: p.ServiceAccount, ServiceAccountUID: p.ServiceAccountUID, Job: i.JobName(), JobUID: job.UID, JobSpec: job.Spec, Pod: "worker", PodUID: id, PodSpec: artifact.Digest{2}}
	worker := authorization.DownloadWorker{Intent: i, Job: job, Binding: binding}
	enrollment := authorization.WorkerEnrollment{Worker: worker, PublicKeyDigest: artifact.Digest{3}, ClaimedAt: now}
	proof := authorization.WorkerEnrollmentProof{Worker: worker, PublicKeyDigest: enrollment.PublicKeyDigest, TokenDigest: artifact.Digest{4}, ObservedAt: now, FreshUntil: now.Add(time.Second)}
	epoch, leaf, e := authorization.WorkerCertificateEpoch(worker, now)
	if e != nil {
		t.Fatal(e)
	}
	attempt := authorization.WorkerCertificateAttempt{ID: id, Epoch: epoch, Ordinal: 1, Enrollment: enrollment, Proof: proof, RecoveryEpoch: id, EnrollmentAudit: artifact.Digest{5}, CheckedAt: now, SignBefore: proof.FreshUntil, CertificateNotAfter: leaf}
	certificate := audit.WorkerCertificate{Attempt: attempt, Peer: authorization.KeyPeer{InstallationID: id, PeerID: id, Role: "acquisition", Certificate: artifact.Digest{6}, NotBefore: now, NotAfter: leaf}}
	bootstrap := audit.BootstrapIssue{ID: id, Binding: fleet.PeerBinding{InstallationID: id, ClusterID: id, PeerID: id, IssuerEpoch: id, Role: fleet.ConnectorPeer}, RequestDigest: artifact.Digest{1}, Actor: principal, IdentityRevision: rev, AdministrationRevision: rev, DisplayName: "synthetic cluster", Region: "eu-test", DeliveryProfile: "channel", NotBefore: now, NotAfter: now.Add(5 * time.Minute), Credential: fleet.BootstrapCredential{SlotID: id, DeliveryProfile: "channel", SecretDigest: artifact.Digest{4}, Version: 1}}
	download := audit.DownloadIntent{SessionID: id, Batch: artifact.DownloadBatch{ID: id, Generation: 1, Purpose: artifact.DownloadMetadata, ReadBytes: 4096, StartedAt: now, LeaseUntil: now.Add(time.Second), Authority: authority}}
	response := artifact.DownloadResponse{ID: id, SessionID: id, OwnerID: id, Generation: 2, Plan: artifact.DownloadResponsePlan{Version: 1, Selection: artifact.DownloadSelection{Length: 100}, WholeFile: true, WindowReadLimit: 1024}, StartedAt: now, Until: now.Add(time.Minute), WindowCount: 1, ActiveWindowID: id}
	window := audit.DownloadWindowIntent{Response: response, Window: artifact.DownloadWindow{ID: id, ResponseID: id, SessionID: id, OwnerID: id, AuditStoreID: id, Generation: 2, Ordinal: 1, Length: 100, ReadLimit: 1024, StartedAt: now, WriteUntil: now.Add(2 * time.Minute), Authority: authority}}
	stop := artifact.DownloadStopDecision{Protocol: artifact.DownloadStopProtocol, RootID: id, DownloadID: id, RequestID: id, StoreID: id, Actor: principal, KeyDigest: artifact.Digest{3}, State: "Cancelled", RequestedAt: now, WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Hour)}
	policy := audit.DownloadStopLifecyclePolicy{RootID: id, InstallationID: id, StoreID: id, PolicyID: id, BackupProfileID: id, QualificationID: id, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, QualificationDigest: artifact.Digest{3}, Layout: audit.DownloadStopHistoryLayout, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1, MaxPurgeLeases: 4}
	d := stop.RetainUntil
	stopBinding := audit.DownloadStopLifecycleBinding{Protocol: audit.DownloadStopWriterProtocol, RootID: id, DownloadID: id, AllocationID: id, IssuerEpoch: id, Policy: policy, ReservedAt: now, TransferUntil: now.Add(time.Minute), HardDeleteBy: d, OriginalPurgeAt: d.Add(-4 * time.Minute), CertificatePurgeAt: d.Add(-2 * time.Minute), LiveRetireBy: d.Add(-time.Minute), HistoryReleaseAt: d.Add(-time.Minute), HistoryDeleteBy: d}
	if !bootstrap.Valid() || !worker.Valid() || !enrollment.Valid() || !certificate.Valid() || !download.Valid() || !window.Valid() || !stop.Valid() || !stopBinding.Valid() {
		t.Fatal("invalid synthetic audit records")
	}
	return installedAuditRecords{bootstrap, worker, enrollment, certificate, download, window, stop, stopBinding}
}

func TestInstalledProviderAuditFamiliesOwnCredentialAndJoinedIO(t *testing.T) {
	for _, purpose := range []string{"bootstrap", "dispatch", "enrollment", "certificate", "download-intent", "download-outcome", "window-intent", "window-outcome", "stop", "closed-stop"} {
		for _, mode := range []string{"success", "blocked-put", "blocked-get", "blocked-body", "blocked-open", "blocked-original-write", "lookup", "lookup-after-write"} {
			if (mode == "lookup" || mode == "lookup-after-write" || mode == "blocked-original-write") && !strings.HasPrefix(purpose, "window-") && purpose != "stop" && purpose != "closed-stop" {
				continue
			}
			if mode == "lookup-after-write" && strings.HasPrefix(purpose, "window-") {
				continue
			}
			t.Run(purpose+"/"+mode, func(t *testing.T) {
				records := providerAuditRecords(t)
				if mode == "blocked-original-write" {
					until := time.Now().Add(100 * time.Millisecond).UTC().Truncate(time.Microsecond)
					records.window.Window.WriteUntil = until
					records.stop.WriteUntil = until
				}
				if mode == "lookup-after-write" {
					records.stop.WriteUntil = time.Now().Add(75 * time.Millisecond).UTC().Truncate(time.Microsecond)
				}
				var puts, gets atomic.Int32
				var cipher []byte
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == "PUT" {
						puts.Add(1)
						cipher, _ = io.ReadAll(r.Body)
						if r.Header.Get("If-None-Match") != "*" {
							t.Error("unconditional write")
						}
					} else if r.Method == "GET" {
						gets.Add(1)
					} else {
						t.Error("unexpected audit method", r.Method)
						w.WriteHeader(400)
						return
					}
					if (mode == "blocked-put" || mode == "blocked-original-write") && r.Method == "PUT" || mode == "blocked-get" && r.Method == "GET" {
						<-r.Context().Done()
						return
					}
					w.Header().Set("ETag", "\"synthetic\"")
					w.Header().Set("x-amz-version-id", "v1")
					if r.Method == "GET" {
						w.Header().Set("Content-Length", strconv.Itoa(len(cipher)))
						if mode == "blocked-body" {
							w.Write(cipher[:1])
							w.(http.Flusher).Flush()
							<-r.Context().Done()
							return
						}
						w.Write(bytes.Clone(cipher))
					}
				}))
				defer server.Close()
				key, e := keyset.NewHandle(aead.AES256GCMKeyTemplate())
				if e != nil {
					t.Fatal(e)
				}
				a, e := aead.New(key)
				if e != nil {
					t.Fatal(e)
				}
				keys := &operationAuditKeys{a: a, waitOpen: mode == "blocked-open"}
				creds := &operationCredentialFixture{until: time.Now().Add(2 * time.Second)}
				if mode != "success" && mode != "blocked-original-write" && mode != "lookup" && mode != "lookup-after-write" {
					creds.until = time.Now().Add(100 * time.Millisecond)
				}
				var in contracts.OwnerDeployment
				in.AuditStore = contracts.OwnerAuditStore{Endpoint: server.URL, Region: "us-east-1", Bucket: "synthetic"}
				s := &installedOperationAudit{input: in, providers: creds, http: server.Client(), seal: keys, open: keys, storeID: records.stop.StoreID, slots: make(chan struct{}, 1)}
				layout := publicAuditStore{operation: s} // No shared static/dynamic store exists in this layout.
				ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
				defer cancel()
				start := time.Now()
				var receipt audit.Receipt
				var original audit.Receipt
				lookup := mode == "lookup" || mode == "lookup-after-write"
				if lookup {
					if strings.HasPrefix(purpose, "window-") {
						var r audit.DownloadWindowWriteResult
						if purpose == "window-intent" {
							r, e = s.CreateDownloadWindowIntent(ctx, records.window)
						} else {
							r, e = s.CreateDownloadWindowOutcome(ctx, audit.DownloadWindowAuditOutcome{Intent: records.window, Outcome: artifact.DownloadWindowOutcome{EmittedBytes: 100, Success: true, VerifiedFinal: true, RecordedAt: records.window.Window.StartedAt}})
						}
						original = r.Receipt
					} else {
						original, e = s.CreateDownloadStop(ctx, records.stop)
					}
					if e != nil {
						t.Fatal("could not prepare immutable lookup fixture", e)
					}
					if mode == "lookup-after-write" {
						time.Sleep(time.Until(records.stop.WriteUntil) + 5*time.Millisecond)
					}
					puts.Store(0)
					gets.Store(0)
					creds.reads.Store(0)
					keys.wraps = 0
					keys.unwraps = 0
				}
				var completed bool
				switch purpose {
				case "bootstrap":
					receipt, e = layout.bootstrapObjects().WriteBootstrapIssue(ctx, records.bootstrap)
				case "dispatch":
					receipt, e = layout.workerObjects().WriteDownloadWorkerIntent(ctx, records.worker.Intent)
				case "enrollment":
					receipt, e = layout.enrollmentObjects().WriteWorkerEnrollment(ctx, records.enrollment)
				case "certificate":
					receipt, e = layout.enrollmentObjects().WriteWorkerCertificate(ctx, records.certificate)
				case "download-intent":
					receipt, e = layout.downloadObjects().WriteDownloadIntent(ctx, records.download)
				case "download-outcome":
					receipt, e = layout.downloadObjects().WriteDownloadOutcome(ctx, audit.DownloadOutcome{Intent: records.download, Success: true, RecordedAt: records.download.Batch.StartedAt})
				case "window-intent", "window-outcome":
					writer, err := layout.windowObjects(s.storeID)
					if err != nil {
						t.Fatal(err)
					}
					var result audit.DownloadWindowWriteResult
					if lookup {
						if purpose == "window-intent" {
							result.Receipt, e = writer.FindDownloadWindowIntent(ctx, records.window)
						} else {
							result.Receipt, e = writer.FindDownloadWindowOutcome(ctx, audit.DownloadWindowAuditOutcome{Intent: records.window, Outcome: artifact.DownloadWindowOutcome{EmittedBytes: 100, Success: true, VerifiedFinal: true, RecordedAt: records.window.Window.StartedAt}})
						}
					} else if purpose == "window-intent" {
						result, e = writer.CreateDownloadWindowIntent(ctx, records.window)
					} else {
						result, e = writer.CreateDownloadWindowOutcome(ctx, audit.DownloadWindowAuditOutcome{Intent: records.window, Outcome: artifact.DownloadWindowOutcome{EmittedBytes: 100, Success: true, VerifiedFinal: true, RecordedAt: records.window.Window.StartedAt}})
					}
					receipt, completed = result.Receipt, result.Completion != nil
				case "stop", "closed-stop":
					legacy, closed, err := layout.stopObjects(s.storeID)
					if err != nil {
						t.Fatal(err)
					}
					if lookup {
						receipt, e = legacy.FindDownloadStop(ctx, records.stop)
					} else if purpose == "stop" {
						receipt, e = legacy.CreateDownloadStop(ctx, records.stop)
					} else {
						var result audit.DownloadStopWriteCompletion
						result, e = closed.CreateClosedDownloadStop(ctx, records.stopBinding, records.stop)
						receipt = result.Receipt
						completed = result.Valid(records.stopBinding, "decision", records.stop.RequestedAt, records.stop.WriteUntil)
					}
				}
				if lookup {
					if e != nil || receipt != original || completed || puts.Load() != 0 || gets.Load() != 1 || keys.wraps != 0 || keys.unwraps != 1 {
						t.Fatal("lookup replayed write, changed record or produced closure", e)
					}
				} else if mode == "success" {
					if e != nil || receipt.Bytes == 0 || puts.Load() != 1 || gets.Load() != 1 || keys.wraps != 1 || keys.unwraps != 1 {
						t.Fatal("complete exact audit operation missing", e, puts.Load(), gets.Load(), keys.wraps, keys.unwraps)
					}
					if (strings.HasPrefix(purpose, "window-") || purpose == "closed-stop") && !completed {
						t.Fatal("joined completion missing")
					}
				} else {
					if e == nil || receipt != (audit.Receipt{}) || completed {
						t.Fatal("expired I/O emitted receipt or completion")
					}
					if time.Since(start) > 350*time.Millisecond {
						t.Fatal("credential deadline discarded", time.Since(start))
					}
				}
				if creds.reads.Load() != 1 {
					t.Fatal("credential observation repeated", creds.reads.Load())
				}
			})
		}
	}
}

func TestInstalledAuditSlotsRemainOwnedUntilVerificationJoins(t *testing.T) {
	var cipher []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			cipher, _ = io.ReadAll(r.Body)
		}
		w.Header().Set("ETag", "\"synthetic\"")
		w.Header().Set("x-amz-version-id", "v1")
		if r.Method == "GET" {
			w.Header().Set("Content-Length", strconv.Itoa(len(cipher)))
			w.Write(bytes.Clone(cipher))
		}
	}))
	defer server.Close()
	h, e := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if e != nil {
		t.Fatal(e)
	}
	a, e := aead.New(h)
	if e != nil {
		t.Fatal(e)
	}
	release := make(chan struct{})
	joined := make(chan error, 1)
	keys := &operationAuditKeys{a: a, enteredOpen: make(chan struct{}), releaseOpen: release}
	creds := &operationCredentialFixture{until: time.Now().Add(100 * time.Millisecond)}
	var in contracts.OwnerDeployment
	in.AuditStore = contracts.OwnerAuditStore{Endpoint: server.URL, Region: "us-east-1", Bucket: "synthetic"}
	s := &installedOperationAudit{input: in, providers: creds, http: server.Client(), seal: keys, open: keys, slots: make(chan struct{}, 1)}
	records := providerAuditRecords(t)
	go func() { _, err := s.WriteBootstrapIssue(context.Background(), records.bootstrap); joined <- err }()
	select {
	case <-keys.enteredOpen:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("verification never entered")
	}
	// Cancellation/expiry does not prove that a provider returned or its buffers
	// closed. The first call deliberately ignores cancellation until released.
	time.Sleep(time.Until(creds.until) + 5*time.Millisecond)
	waiting, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	clone := *s // Every typed port shares the same owner, including policy copies.
	if _, err := clone.WriteBootstrapIssue(waiting, records.bootstrap); err == nil || creds.reads.Load() != 1 || len(s.slots) != 1 {
		close(release)
		<-joined
		t.Fatal("expired unjoined owner released capacity")
	}
	close(release)
	if err := <-joined; err == nil || len(s.slots) != 0 {
		t.Fatal("late verification emitted receipt or retained completed slot")
	}
	keys.enteredOpen = nil
	creds.until = time.Now().Add(time.Second)
	if _, err := clone.WriteBootstrapIssue(context.Background(), records.bootstrap); err != nil || len(s.slots) != 0 || creds.reads.Load() != 2 {
		t.Fatal("joined owner prevented independent bounded operation", err)
	}
}
