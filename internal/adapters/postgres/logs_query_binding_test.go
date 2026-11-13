package postgres

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	authorization "asservat.local/asservat/internal/domain/authorization"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogQueryCompleteBindingKeeps16KiBBound(t *testing.T) {
	q, a := packetQueryLedgerValue(t)
	a.Scope.NativeType = artifact.LogsArtifact
	a.Scope.SourceFormat = artifact.LogFormat
	a.Scope.DisplayVersion = query.LogQueryDisplayVersion
	a.Scope.PacketQuery = query.PacketQueryWindow{}
	for _, maximum := range []bool{false, true} {
		a.Scope.Logs = query.LogWindow{Limit: 100}
		if maximum {
			a.Scope.Logs = query.LogWindow{Fragment: uint64(artifact.LogNativeLimit - 1), Offset: artifact.LogMaxFragmentBytes - 1, Limit: 100, Binding: strings.Repeat("f", 32)}
		}
		var err error
		q, err = query.NewContextQuery(q.ID, q.OperationID, q.WorkerID, a, q.Plan, q.CreatedAt, q.InvocationKey)
		if err != nil {
			t.Fatal("complete rawquery", err)
		}
		now := a.CheckedAt
		digest := artifact.Digest{1}
		w := query.ContextQueryWorker{QueryID: q.ID, WorkerID: q.WorkerID, PeerID: q.ID, PodUID: q.ID, ProcessEpoch: q.ID, Certificate: digest, Configuration: q.Plan.Profile.Path.WorkerConfiguration}
		request := query.ContextQueryRequest{Call: query.ContextQueryCall{ID: q.OperationID, RootID: q.Scope.RootID, Tool: "get_logs", InputFormat: "context-query-input/v1", MACVersion: "v1", InputDigest: digest, PrincipalDigest: digest, Principal: q.Scope.Principal, StartedAt: now, Until: a.ValidUntil, WriteUntil: now.Add(30 * time.Second)}, OwnerID: q.ID, HubProcessEpoch: q.ID}
		b := query.ContextReadBatch{QueryID: q.ID, ID: q.ID, OperationID: q.OperationID, Generation: 1, Worker: w, Request: request, StartedAt: now, Until: a.ValidUntil, CleanupUntil: q.CleanupUntil}
		proof := query.ContextProjectionWorkerProof{Binding: query.ContextProjectionWorkerBinding{QueryID: q.ID, WorkerID: w.WorkerID, InstallationID: q.Plan.InstallationID, ClusterID: q.Plan.Profile.Path.AcquisitionClusterID, Namespace: strings.Repeat("n", 63), NamespaceUID: strings.Repeat("u", 64), ServiceAccount: strings.Repeat("s", 253), ServiceAccountUID: strings.Repeat("u", 64), Job: strings.Repeat("j", 63), JobUID: strings.Repeat("u", 64), Pod: strings.Repeat("p", 253), PodUID: w.PodUID, JobSpec: digest, PodSpec: digest, Configuration: w.Configuration}, Peer: authorization.KeyPeer{InstallationID: q.Plan.InstallationID, PeerID: w.PeerID, Role: "acquisition", Certificate: w.Certificate, NotBefore: q.CreatedAt, NotAfter: q.CredentialUntil}, ProcessEpoch: w.ProcessEpoch, PublicKey: digest, TokenDigest: digest, Protection: a.IdentityRevision, ObservedAt: now, ValidUntil: a.ValidUntil}
		key := query.ContextProjectionKeyBinding{Purpose: query.ContextProjectionPurpose, ClaimID: b.ID, Batch: b, SourceVersion: q.Scope.Version, Scope: authorization.KeyScope{InstallationID: q.Plan.InstallationID, Purpose: "artifact", KeyID: strings.Repeat("k", 128)}, Worker: proof, Authority: a, CreatedAt: now, Until: a.ValidUntil}
		if !key.Valid(q, now) {
			t.Fatal("complete typed binding invalid")
		}
		op := authorization.NativeOperation{Path: a.Environment.Path.AcquisitionPath(), Processing: a.Environment.Processing, Reference: authorization.NativeReference{InstallationID: q.Plan.InstallationID, QueryID: q.ID, WorkerID: q.WorkerID, OperationID: b.ID, Fence: b.Generation}, Kind: authorization.NativeProjection, HubPodUID: q.ID, HubProcessEpoch: q.ID, WorkerPodUID: w.PodUID, WorkerPublicKey: digest, SourceVersion: q.Scope.Version, ParentID: b.ID, Generation: b.Generation, StartedAt: now, Until: a.ValidUntil}
		if !op.CurrentValid(now) {
			t.Fatal("native operation invalid")
		}
		profile := authorization.DownloadWorkerProfile{Configuration: q.Plan.Profile.Path.WorkerConfiguration, InstallationID: q.Plan.InstallationID, ClusterID: q.Plan.Profile.Path.AcquisitionClusterID, Namespace: "workers", NamespaceUID: "namespace", ServiceAccount: "acquisition", ServiceAccountUID: "account", Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", ControlConfigUID: "config", PriorityClass: "workers", PriorityClassUID: "priority", CPUMillis: q.Plan.Profile.Worker.CPUMilli, MemoryBytes: q.Plan.Profile.Worker.MemoryBytes, MaxRuntime: 8 * time.Hour}
		intent := query.ContextProjectionWorkerIntent{Query: q, Worker: authorization.AcquisitionWorkerIntent{ID: q.WorkerID, Parent: authorization.AcquisitionParent{Purpose: authorization.AcquisitionProjection, ID: q.ID}, Profile: profile, CreatedAt: q.CreatedAt, RunUntil: q.WorkerUntil}}
		if !intent.Valid() {
			t.Fatal("worker intent invalid")
		}
		values := map[string]any{"scope": q.Scope, "query": q, "authority": a, "batch": b, "key-binding": key, "native-operation": op, "worker-intent": intent, "initial-request": request, "worker-binding": w, "worker-proof": proof}

		bounds := map[string]int{"query": 64 << 10, "authority": 64 << 10, "batch": 16 << 10, "key-binding": 16 << 10, "native-operation": 16 << 10, "worker-intent": 64 << 10, "initial-request": 8 << 10, "worker-binding": 16 << 10, "worker-proof": 16 << 10, "scope": 64 << 10}
		for name, value := range values {
			encoded := comparisonJSON(t, value)
			if len(encoded) > bounds[name] {
				t.Fatal("complete typed encoding exceeds originalbound", maximum, name, len(encoded), bounds[name])
			}
			if projectionKeyBindingBytes(key) != 16<<10 {
				t.Fatal("logs binding cap changed")
			}
			t.Logf("complete validrawquery maximum=%t kind=%s compactBytes=%d bound=%d", maximum, name, len(encoded), bounds[name])
			if dir := os.Getenv("ASSERVAT_LOG_QUERY_SIZE_FIXTURES"); dir != "" {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("maximum-%t-%s.json", maximum, name)), encoded, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
