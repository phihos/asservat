package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	access "asservat.local/asservat/internal/application/authorization"
	app "asservat.local/asservat/internal/application/capture"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/presentation"
)

func reserveID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

// Only the facts and effects are synthetic. The HTTP/2 socket, MCP SDK,
// audited presentation, request identity, evaluator and C09 use case are real.
// No SQL, Kubernetes, collector or installed-workflow qualification is claimed.
type reserveFacts struct {
	app.ContextAdmissionReplay
	app.ContextPreviewStore
	thin                                                          bool
	ids, stores, admissions, demands, storageReads, storageActive atomic.Int64
}

func (f *reserveFacts) ResolveWorkload(ctx context.Context, in targets.WorkloadRequest) (targets.PodResolution, error) {
	return f.ResolvePod(ctx, targets.Request{ClusterID: in.ClusterID, Namespace: configuration.NamespaceRef{Name: in.Namespace, UID: "ns"}, Workload: configuration.WorkloadRef{Kind: in.Kind, Name: in.Name, UID: "deployment"}, PodName: "api-a", PodUID: "pod"})
}
func (f *reserveFacts) ResolvePod(_ context.Context, in targets.Request) (targets.PodResolution, error) {
	now := time.Now()
	return targets.PodResolution{Request: in, Pin: artifact.PinnedPod{Namespace: in.Namespace.Name, NamespaceUID: in.Namespace.UID, Name: in.PodName, UID: in.PodUID, NodeName: "worker", ControllerUID: "rs"}, NodeUID: "node", NodeBootID: reserveID(5), PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}
func (f *reserveFacts) Permissions(_ context.Context, target authorization.Target) (authorization.Projection, error) {
	now := time.Now()
	rev := identity.Revision{UID: "permissions", Generation: 1, Digest: [32]byte{5}}
	actor := testIdentity().Principal
	audience := artifact.AudienceAssignment{Kind: "User", Issuer: actor.Issuer, SubjectID: actor.Subject, Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: reserveID(6), BasisDigest: artifact.Digest{1}}
	return authorization.Projection{Target: target, Revision: rev, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: now.Add(5 * time.Second), Allows: []authorization.CurrentAssignment{{Audience: audience, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}}, nil
}
func (f *reserveFacts) ContextCapability(context.Context, authorization.Target) (planning.ContextCapability, error) {
	now := time.Now()
	return planning.ContextCapability{Enabled: true, Revision: identity.Revision{UID: "capability", Generation: 1, Digest: [32]byte{2}}, CollectorVersion: "test-1", CollectorImageDigest: artifact.Digest{3}, ProjectionDigest: compiler.ProjectionDigest(), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}
func (f *reserveFacts) ContextStorage(ctx context.Context, target authorization.Target) (app.ContextStorageObservation, error) {
	f.storageReads.Add(1)
	f.storageActive.Add(1)
	defer f.storageActive.Add(-1)
	if err := ctx.Err(); err != nil {
		return app.ContextStorageObservation{}, err
	}
	now := time.Now()
	until := now.Add(5 * time.Second)
	if f.thin {
		until = now.Add(50 * time.Millisecond)
	}
	revision := identity.Revision{UID: "binding", Generation: 1, Digest: [32]byte{4}}
	return app.ContextStorageObservation{Selection: value.ContextStorageSelection{StoreID: reserveID(7), AllocationID: reserveID(8), PoolRevision: 1, AllocationRevision: 1, BindingRevision: revision}, Binding: value.StorageBinding{RootID: reserveID(1), ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, AllocationID: reserveID(8), Revision: revision, ObservedAt: now, FreshUntil: until}}, nil
}
func (f *reserveFacts) DemandCapacityRefresh(ctx context.Context, _ targets.Request) error {
	f.demands.Add(1)
	return ctx.Err()
}
func (f *reserveFacts) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	now := time.Now()
	return artifact.RecoveryProof{InstallationID: reserveID(2), IssuerEpoch: reserveID(3), Revision: identity.Revision{UID: "recovery", Generation: 1, Digest: [32]byte{6}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}
func (f *reserveFacts) Resolve(_ context.Context, in privacy.Input) (privacy.Resolution, error) {
	now := time.Now()
	revision := identity.Revision{UID: reserveID(9), Generation: 1, Digest: [32]byte{7}}
	set := privacy.PolicySet{Target: in.Target, Revision: revision, Complete: true, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{8}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 60, MaximumSeconds: 3600, DeletionBudgetSeconds: 10}}}
	set.Proof = artifact.RetentionProof{RootID: reserveID(1), ClusterID: in.Target.ClusterID, NamespaceUID: in.Target.NamespaceUID, WorkloadUID: in.Target.WorkloadUID, PodUID: in.Target.PodUID, Topology: revision, Policy: revision, Selectors: revision, ObservedAt: now, ValidUntil: set.FreshUntil, SourceCount: 1, Sources: [2]artifact.RetentionSourceVersion{{ClusterID: in.Target.ClusterID, ControlNamespaceUID: "control", Epoch: reserveID(3), Hub: true, ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: revision}}}
	return privacy.Resolve(set, in, now)
}
func (f *reserveFacts) ContextProcessingCoverage(ctx context.Context, in value.ProcessingCoverageRequest, _ artifact.RecoveryProof) (value.ProcessingCoverage, error) {
	now := time.Now()
	until := now.Add(5 * time.Second)
	if deadline, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, deadline)
	}
	return value.ProcessingCoverage{Request: in, ObservedAt: now, FreshUntil: until}, nil
}
func (f *reserveFacts) CreateContextPreview(context.Context, value.ContextPreview) error {
	f.stores.Add(1)
	return nil
}
func (f *reserveFacts) AdmitReviewedContext(context.Context, string, value.Admission) (value.Accepted, error) {
	f.admissions.Add(1)
	return value.Accepted{}, value.ErrUnavailable
}

type reserveAudit struct{ begins, finishes atomic.Int64 }

func (*reserveAudit) Configured() bool { return true }
func (a *reserveAudit) Begin(ctx context.Context, _ audit.OperationIntent) error {
	a.begins.Add(1)
	return ctx.Err()
}
func (a *reserveAudit) Finish(ctx context.Context, _ audit.OperationOutcome) error {
	a.finishes.Add(1)
	// A finite audit acknowledgement still needs live original request time.
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func TestStorageReadinessReserveDeliversAuditedHTTP2Preview(t *testing.T) {
	for _, mode := range []string{"thin", "short-parent-fresh"} {
		t.Run(mode, func(t *testing.T) {
			facts := &reserveFacts{thin: mode == "thin"}
			gate := &reserveAudit{}
			var handler *Handler
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 {
					t.Error("fixture did not negotiate HTTP/2")
				}
				if mode == "short-parent-fresh" {
					ctx, cancel := context.WithTimeout(r.Context(), 750*time.Millisecond)
					defer cancel()
					r = r.WithContext(ctx)
				}
				handler.ServeHTTP(w, r)
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			service := app.ContextInvestigation{RootID: reserveID(1), InstallationID: reserveID(2), Previews: facts, Replay: facts, Admission: facts, Targets: facts, Eligibility: access.Evaluator{Permissions: facts, Now: time.Now}, Capabilities: facts, Retention: facts, Storage: facts, Refresh: facts, Processing: facts, Recovery: facts, Lifetime: time.Minute, Now: time.Now, NewID: func() string { return reserveID(100 + int(facts.ids.Add(1))) }}
			ops, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, CollectionEnabled: true, Now: time.Now, NewID: func() string { return reserveID(500) }}, service, &mcpCaptureFixture{})
			if err != nil {
				t.Fatal(err)
			}
			combined, err := presentation.NewInvestigationOperations(ops, nil)
			if err != nil {
				t.Fatal(err)
			}
			mac, err := auditapp.NewOperationMAC("audit-v1", bytes.Repeat([]byte{1}, 32), "accounts-v1", bytes.Repeat([]byte{2}, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer mac.Close()
			audited, err := presentation.NewHealthyAuditedOperations(presentation.AuditedOperationsConfig{RootID: reserveID(1), Retention: time.Hour, NormalConcurrency: 1, ResolutionConcurrency: 1, PerPrincipalConcurrency: 1, NormalPerSecond: 10, ResolutionPerSecond: 10, Now: time.Now, NewID: func() string { return reserveID(501) }}, combined, gate, gate, mac)
			if err != nil {
				t.Fatal(err)
			}
			handler, err = NewAuditedContextHandler(Config{PublicOrigin: server.URL, Issuer: testIdentity().Principal.Issuer, Version: "test", MaxConcurrent: 2, MaxPerIdentity: 1}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
				i := testIdentity()
				i.Scopes = append(i.Scopes, "evidence:capture")
				return i, nil
			}), audited)
			if err != nil {
				t.Fatal(err)
			}
			request := rpcRequest(t, server, "2026-07-28", "tools/call", map[string]any{"name": "preview_capture", "arguments": map[string]any{"target_ref": map[string]any{"cluster_id": reserveID(4), "namespace": "payments", "kind": "Deployment", "name": "api"}, "preset_ref": map[string]any{"name": "pod-status", "version": "v1"}, "requested_retention_seconds": 60}})
			started := time.Now()
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatalf("no audited typed response before original socket deadline: %v (elapsed %s, reads %d demands %d Begin/Finish %d/%d)", err, time.Since(started), facts.storageReads.Load(), facts.demands.Load(), gate.begins.Load(), gate.finishes.Load())
			}
			defer response.Body.Close()
			body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
			if err != nil {
				t.Fatal(err)
			}
			var rpc struct {
				Result struct {
					StructuredContent json.RawMessage `json:"structuredContent"`
				} `json:"result"`
			}
			if response.ProtoMajor != 2 || response.StatusCode != http.StatusOK || json.Unmarshal(body, &rpc) != nil || len(rpc.Result.StructuredContent) == 0 {
				t.Fatalf("missing structured HTTP/2 result: %d %s", response.StatusCode, body)
			}
			var result presentation.OperationEnvelope
			if json.Unmarshal(rpc.Result.StructuredContent, &result) != nil {
				t.Fatal(string(body))
			}
			if mode == "thin" {
				if result.Status != "error" || !strings.Contains(string(rpc.Result.StructuredContent), `"code":"NotAvailable"`) || !strings.Contains(string(rpc.Result.StructuredContent), `"retryable":true`) || facts.stores.Load() != 0 || facts.demands.Load() != 1 || facts.storageReads.Load() < 3 {
					t.Fatalf("thin binding was not a typed retryable refusal: %s stores=%d reads=%d demands=%d", body, facts.stores.Load(), facts.storageReads.Load(), facts.demands.Load())
				}
			} else if result.Status != "ok" || facts.stores.Load() != 1 || facts.demands.Load() != 0 || (facts.storageReads.Load() < 1 || facts.storageReads.Load() > 2) {
				t.Fatalf("short live parent lost fast fresh result: %s stores=%d reads=%d demands=%d", body, facts.stores.Load(), facts.storageReads.Load(), facts.demands.Load())
			}
			if gate.begins.Load() != 1 || gate.finishes.Load() != 1 || facts.admissions.Load() != 0 || facts.storageActive.Load() != 0 {
				t.Fatalf("audit/effect/owned I/O mismatch: Begin/Finish %d/%d admission=%d active=%d", gate.begins.Load(), gate.finishes.Load(), facts.admissions.Load(), facts.storageActive.Load())
			}
			t.Logf("HTTP/2 original request remains live for audited %s response: %s; storage reads=%d demand=%d", mode, time.Since(started), facts.storageReads.Load(), facts.demands.Load())
		})
	}
}
