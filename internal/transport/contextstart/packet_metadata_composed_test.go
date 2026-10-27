package contextstart

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	auth "asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	planning "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"k8s.io/client-go/rest"
)

// This fixture composes real C09 preview/request, C03 eligibility evaluation,
// Router/Standby, both frame streams and the real regional Kubernetes resolver.
// Kubernetes replies, node availability, identity/recovery/grant authority and
// admission are explicitly synthetic. No collector, BPF, external service or
// production grant authorization is established by this regression.
type packetMetadataFixture struct {
	channel                                                      fleet.APIContextChannel
	api                                                          *kube.PodTargets
	svc                                                          captureapp.ContextInvestigation
	preview                                                      capture.ContextPreview
	ids                                                          atomic.Int64
	admission                                                    atomic.Int64
	apiReads                                                     atomic.Int64
	denied                                                       atomic.Bool
	mu                                                           sync.Mutex
	hubUntil, regionUntil, humanUntil, recoveryUntil, grantUntil time.Time
	storageDelay, apiDelay                                       time.Duration
	afterStorage                                                 func()
	lastLocal                                                    targets.PodResolution
	stages                                                       []string
	sourceUnavailable                                            atomic.Bool
}

var metadataAdmitted = errors.New("composed test reached admission")

func metadataID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func (f *packetMetadataFixture) actor() identity.Principal {
	return identity.Principal{Issuer: "https://identity.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}
}
func (f *packetMetadataFixture) bounds() (time.Time, time.Time, time.Time, time.Time, time.Time, time.Duration, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hubUntil, f.regionUntil, f.humanUntil, f.recoveryUntil, f.grantUntil, f.storageDelay, f.apiDelay
}
func originalBound(bound, fallback time.Time) time.Time {
	if bound.IsZero() {
		return fallback
	}
	return bound
}
func (f *packetMetadataFixture) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	_, _, human, _, _, _, _ := f.bounds()
	now := time.Now()
	until := originalBound(human, now.Add(5*time.Second))
	if ctx.Err() != nil || !now.Before(until) {
		return identity.Identity{}, identity.ErrDenied
	}
	return identity.Identity{Principal: f.actor(), Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, Scopes: []string{"evidence:capture", "evidence:read"}, Groups: []string{"developers"}, VerifiedAt: now, ValidUntil: until}, nil
}
func (f *packetMetadataFixture) Permissions(_ context.Context, t auth.Target) (auth.Projection, error) {
	now := time.Now()
	rev := identity.Revision{UID: "permission", Generation: 1, Digest: artifact.Digest{2}}
	p := auth.Projection{Target: t, Revision: rev, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: now.Add(5 * time.Second)}
	a := auth.CurrentAssignment{Audience: artifact.AudienceAssignment{Kind: "User", Issuer: f.actor().Issuer, SubjectID: f.actor().Subject, Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: metadataID(41), BasisDigest: artifact.Digest{2}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	p.Allows = []auth.CurrentAssignment{a}
	if f.denied.Load() {
		p.Denies = []auth.CurrentAssignment{a}
	}
	return p, nil
}
func (f *packetMetadataFixture) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	_, _, _, bound, _, _, _ := f.bounds()
	now := time.Now()
	until := originalBound(bound, now.Add(5*time.Second))
	if ctx.Err() != nil || !now.Before(until) {
		return artifact.RecoveryProof{}, capture.ErrUnavailable
	}
	return artifact.RecoveryProof{InstallationID: f.channel.Hub.InstallationID, IssuerEpoch: f.channel.Hub.IssuerEpoch, Revision: identity.Revision{UID: "recovery", Generation: 1, Digest: artifact.Digest{3}}, ObservedAt: now, FreshUntil: until}, nil
}
func (f *packetMetadataFixture) ContextCapability(_ context.Context, _ auth.Target) (planning.ContextCapability, error) {
	now := time.Now()
	return planning.ContextCapability{ExecutionClass: artifact.ContextAPIExecution, Enabled: true, Revision: identity.Revision{UID: "capability", Generation: 1, Digest: artifact.Digest{4}}, CollectorVersion: "synthetic-node", CollectorImageDigest: artifact.Digest{5}, ProjectionDigest: compiler.ProjectionDigest(), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}
func (f *packetMetadataFixture) Resolve(_ context.Context, in privacy.Input) (privacy.Resolution, error) {
	now := time.Now()
	r := identity.Revision{UID: metadataID(40), Generation: 1, Digest: artifact.Digest{6}}
	set := privacy.PolicySet{Target: in.Target, Revision: r, Complete: true, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: artifact.Digest{7}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 60, MaximumSeconds: 3600, DeletionBudgetSeconds: 10}}}
	set.Proof = artifact.RetentionProof{RootID: f.channel.RootID, ClusterID: in.Target.ClusterID, NamespaceUID: in.Target.NamespaceUID, WorkloadUID: in.Target.WorkloadUID, PodUID: in.Target.PodUID, Topology: r, Policy: r, Selectors: r, ObservedAt: now, ValidUntil: set.FreshUntil, SourceCount: 1, Sources: [2]artifact.RetentionSourceVersion{{ClusterID: in.Target.ClusterID, ControlNamespaceUID: "control", Epoch: f.channel.Hub.IssuerEpoch, Hub: true, ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: r}}}
	return privacy.Resolve(set, in, now)
}
func (f *packetMetadataFixture) ContextStorage(ctx context.Context, t auth.Target) (captureapp.ContextStorageObservation, error) {
	_, _, _, _, _, delay, _ := f.bounds()
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return captureapp.ContextStorageObservation{}, ctx.Err()
		}
	}
	if f.afterStorage != nil {
		f.afterStorage()
	}
	now := time.Now()
	rev := identity.Revision{UID: "binding", Generation: 1, Digest: artifact.Digest{8}}
	return captureapp.ContextStorageObservation{Selection: capture.ContextStorageSelection{StoreID: metadataID(42), AllocationID: metadataID(43), PoolRevision: 1, AllocationRevision: 1, BindingRevision: rev}, Binding: capture.StorageBinding{RootID: f.channel.RootID, ClusterID: t.ClusterID, NamespaceUID: t.NamespaceUID, WorkloadUID: t.WorkloadUID, AllocationID: metadataID(43), Revision: rev, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}, nil
}
func (f *packetMetadataFixture) ContextProcessingCoverage(ctx context.Context, r capture.ProcessingCoverageRequest, recovery artifact.RecoveryProof) (capture.ProcessingCoverage, error) {
	now := time.Now()
	until := recovery.FreshUntil
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	return capture.ProcessingCoverage{Request: r, ObservedAt: now, FreshUntil: until}, nil
}
func (f *packetMetadataFixture) CreateContextPreview(_ context.Context, p capture.ContextPreview) error {
	f.preview = p.Clone()
	return nil
}
func (f *packetMetadataFixture) ReadContextPreview(_ context.Context, root, id string, actor identity.Principal) (capture.ContextPreview, error) {
	if f.preview.RootID != root || f.preview.ID != id || f.preview.Actor != actor {
		return capture.ContextPreview{}, capture.ErrDenied
	}
	return f.preview.Clone(), nil
}
func (f *packetMetadataFixture) LookupContextAdmission(context.Context, capture.ReplayQuery) (capture.Accepted, bool, error) {
	return capture.Accepted{}, false, nil
}
func (f *packetMetadataFixture) AdmitReviewedContext(context.Context, string, capture.Admission) (capture.Accepted, error) {
	f.admission.Add(1)
	return capture.Accepted{}, metadataAdmitted
}
func (f *packetMetadataFixture) IdentityPolicy(_ context.Context, issuer string) (identity.Policy, error) {
	now := time.Now()
	return identity.Policy{Revision: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, Issuer: issuer, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Clients: []identity.Client{{ID: "console", Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"developers"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute, RequireRecordingApproval: true}, nil
}
func (f *packetMetadataFixture) Request(context.Context, identities.CurrentIdentity, authapp.GrantRequestInput) (auth.Grant, bool, error) {
	return auth.Grant{}, false, errors.New("test must use its existing covering grant")
}
func (f *packetMetadataFixture) Covering(ctx context.Context, _ identities.CurrentIdentity, _ string, _ artifact.Digest, _ auth.Target) (auth.Grant, time.Time, error) {
	_, _, _, _, bound, _, _ := f.bounds()
	until := originalBound(bound, time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute))
	if ctx.Err() != nil || !time.Now().Before(until) {
		return auth.Grant{}, time.Time{}, auth.ErrGrantExpired
	}
	return auth.Grant{ID: metadataID(44), ExpiresAt: until}, until, nil
}
func (f *packetMetadataFixture) ReadConnectorIdentitySource(ctx context.Context) (fleet.ConnectorIdentitySource, error) {
	if ctx.Err() != nil || f.sourceUnavailable.Load() {
		return fleet.ConnectorIdentitySource{}, fleet.ErrUnavailable
	}
	now := time.Now()
	return fleet.ConnectorIdentitySource{Observation: fleet.ConnectorCredentialObservation{ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}, nil
}
func (f *packetMetadataFixture) ResolvePod(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	return f.api.ResolvePod(ctx, r)
}
func (f *packetMetadataFixture) ResolveWorkload(ctx context.Context, r targets.WorkloadRequest) (targets.PodResolution, error) {
	return f.api.ResolveWorkload(ctx, r)
}
func (f *packetMetadataFixture) PacketRecorder(context.Context, targets.RecorderRequest) (targets.RecorderAnswer, error) {
	return targets.RecorderAnswer{Outcome: targets.RecorderAvailable}, nil
}
func (f *packetMetadataFixture) ResolvePacketRecorder(ctx context.Context, r targets.Request) (targets.RecorderResolution, error) {
	p, node, e := f.api.ResolvePacketPod(ctx, r)
	if e != nil {
		return targets.RecorderResolution{}, e
	}
	if node != "worker" {
		return targets.RecorderResolution{}, targets.ErrUnsupported
	}
	f.mu.Lock()
	f.lastLocal = p
	f.mu.Unlock()
	return targets.RecorderResolution{Target: p, Recorder: targets.RecorderAnswer{Outcome: targets.RecorderAvailable}}, nil
}

func newPacketMetadataFixture(t *testing.T) *packetMetadataFixture {
	t.Helper()
	f := &packetMetadataFixture{channel: workFixture().Work.Channel}
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.apiReads.Add(1)
		_, _, _, _, _, _, delay := f.bounds()
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-r.Context().Done():
				return
			}
		}
		meta := func(kind, name, uid string) map[string]any {
			version := "apps/v1"
			if kind == "Namespace" || kind == "Pod" {
				version = "v1"
			}
			m := map[string]any{"name": name, "uid": uid, "resourceVersion": "1"}
			if kind != "Namespace" {
				m["namespace"] = "app"
			}
			return map[string]any{"apiVersion": version, "kind": kind, "metadata": m}
		}
		owner := func(kind, name, uid string) []any {
			return []any{map[string]any{"apiVersion": "apps/v1", "kind": kind, "name": name, "uid": uid, "controller": true}}
		}
		pod := func() map[string]any {
			o := meta("Pod", "app-0", "pod")
			o["metadata"].(map[string]any)["ownerReferences"] = owner("ReplicaSet", "rs", "replicaset")
			o["spec"] = map[string]any{"nodeName": "worker"}
			o["status"] = map[string]any{"phase": "Running"}
			return o
		}
		var out map[string]any
		switch r.URL.Path {
		case "/api/v1/namespaces/app":
			out = meta("Namespace", "app", "namespace")
		case "/api/v1/namespaces/app/pods/app-0":
			out = pod()
		case "/api/v1/namespaces/app/pods":
			out = map[string]any{"apiVersion": "v1", "kind": "PodList", "metadata": map[string]any{"resourceVersion": "1", "continue": ""}, "items": []any{pod()}}
		case "/apis/apps/v1/namespaces/app/replicasets/rs":
			out = meta("ReplicaSet", "rs", "replicaset")
			out["metadata"].(map[string]any)["ownerReferences"] = owner("Deployment", "app", "deployment")
		case "/apis/apps/v1/namespaces/app/deployments/app":
			out = meta("Deployment", "app", "deployment")
			out["metadata"].(map[string]any)["generation"] = 1
			out["spec"] = map[string]any{"selector": map[string]any{"matchLabels": map[string]string{"app": "workload"}}}
		default:
			t.Errorf("unexpected API read %s", r.URL.Path)
			w.WriteHeader(403)
			return
		}
		if r.URL.Path == "/api/v1/namespaces/app/pods" {
			out["items"].([]any)[0].(map[string]any)["metadata"].(map[string]any)["labels"] = map[string]string{"app": "workload"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(api.Close)
	client, e := kube.NewPermissionClient(&rest.Config{Host: api.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})}}, f.channel.Connector.Binding.ClusterID, cfg.NamespaceRef{Name: "control", UID: "control"}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	f.api, e = kube.NewAPIContextTargets(client)
	if e != nil {
		t.Fatal(e)
	}
	router, e := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{f.channel.Connector.Binding.ClusterID, 1, 1}}})
	if e != nil {
		t.Fatal(e)
	}
	parent, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	hubSocket, regionSocket := net.Pipe()
	check := func(hub bool) ReceiverCheck {
		return func(ctx context.Context) (fleet.APIContextReceiver, error) {
			h, r, _, _, _, _, _ := f.bounds()
			until := r
			if hub {
				until = h
			}
			now := time.Now()
			until = originalBound(until, now.Add(5*time.Second))
			if ctx.Err() != nil || !now.Before(until) {
				return fleet.APIContextReceiver{}, fleet.ErrUnavailable
			}
			return fleet.APIContextReceiver{Channel: f.channel, ObservedAt: now, ValidUntil: until}, nil
		}
	}
	stream := func(socket net.Conn, c ReceiverCheck) *frameStream {
		s, e := newFrameStream(parent, f.channel, c, socket, socket, socket.SetReadDeadline, socket.SetWriteDeadline, func() error { return nil }, func() { _ = socket.Close() })
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	hub, region := stream(hubSocket, check(true)), stream(regionSocket, check(false))
	hub.sources = NewSourceFeed(f.channel.ExchangeID, time.Now)
	region.local = f
	region.targets = f
	receiver, e := check(true)(parent)
	if e != nil {
		t.Fatal(e)
	}
	standby, e := router.RegisterStandby(parent, receiver, check(true))
	if e != nil {
		t.Fatal(e)
	}
	joined := make(chan struct{})
	go func() { defer close(joined); defer standby.Finish(); _ = standby.Serve(hub, time.Now) }()
	regionJoined := make(chan struct{})
	go func() { defer close(regionJoined); _, _, _ = region.AwaitWork(parent) }()
	t.Cleanup(func() {
		cancel()
		_ = hubSocket.Close()
		_ = regionSocket.Close()
		_ = hub.Close()
		_ = region.Close()
		<-joined
		<-regionJoined
		router.Close()
	})
	targetPort := Targets{Router: router, Now: time.Now}
	f.svc = captureapp.ContextInvestigation{RootID: f.channel.RootID, InstallationID: f.channel.Hub.InstallationID, Previews: f, Replay: f, Admission: f, Targets: targetPort, Recorders: targetPort, Eligibility: authapp.Evaluator{Permissions: f, Now: time.Now}, Capabilities: f, Retention: f, Storage: f, Processing: f, Recovery: f, Approvals: f, Grants: f, Lifetime: 120 * time.Second, Now: time.Now, NewID: func() string { return metadataID(100 + int(f.ids.Add(1))) }, ReportPreviewFailure: func(s string) { f.stages = append(f.stages, s) }}
	return f
}

func metadataIntent(f *packetMetadataFixture) capture.ContextIntent {
	return capture.ContextIntent{Target: targets.WorkloadRequest{ClusterID: f.channel.Connector.Binding.ClusterID, Namespace: "app", Kind: "Deployment", Name: "app"}, RequestedSeconds: 60, Composition: &planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "net", Profile: planning.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}}}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}}
}
func TestPacketMetadataTransportCompletionDoesNotExpireOwnedObservation(t *testing.T) {
	for _, mode := range []string{"hub-and-region", "hub-only", "region-only"} {
		t.Run(mode, func(t *testing.T) {
			f := newPacketMetadataFixture(t)
			p, e := f.svc.PreviewComposition(t.Context(), f, metadataIntent(f))
			if e != nil || !p.Recordable {
				t.Fatal("composed preview", e, f.stages)
			}
			f.mu.Lock()
			short := time.Now().Add(250 * time.Millisecond)
			if mode != "region-only" {
				f.hubUntil = short
			}
			if mode != "hub-only" {
				f.regionUntil = short
			}
			f.storageDelay = 400 * time.Millisecond
			f.mu.Unlock()
			_, e = f.svc.Request(t.Context(), f, p.Preview.ID, "one-intent")
			if !errors.Is(e, metadataAdmitted) || f.admission.Load() != 1 {
				t.Fatal("completed transport proof expired before independent admission", e, f.stages)
			}
			f.mu.Lock()
			observed := f.lastLocal
			f.mu.Unlock()
			if !time.Now().After(short) || !observed.FreshUntil.Equal(observed.ObservedAt.Add(5*time.Second)) || !observed.Valid(time.Now()) || observed.Pin.NodeName != "" {
				t.Fatal("snapshot window was inherited, restarted or node-authoritative", observed)
			}
		})
	}
}
func TestPacketMetadataComposedOriginalAuthorityAndIOBoundsRefuse(t *testing.T) {
	for _, mode := range []string{"source-unavailable", "regional-io-expiry", "hub-io-expiry", "caller-io-cancellation", "human-expiry", "recovery-expiry", "grant-expiry", "current-deny", "request-five-second-bound"} {
		t.Run(mode, func(t *testing.T) {
			f := newPacketMetadataFixture(t)
			p, e := f.svc.PreviewComposition(t.Context(), f, metadataIntent(f))
			if e != nil || !p.Recordable {
				t.Fatal("composed preview", e, f.stages)
			}
			ctx := t.Context()
			var stop context.CancelFunc
			f.mu.Lock()
			short := time.Now().UTC().Truncate(time.Microsecond).Add(100 * time.Millisecond)
			f.storageDelay = 250 * time.Millisecond
			switch mode {
			case "source-unavailable":
				f.sourceUnavailable.Store(true)
			case "regional-io-expiry":
				f.regionUntil = short
				f.apiDelay = 30 * time.Millisecond
			case "hub-io-expiry":
				f.hubUntil = short
				f.apiDelay = 30 * time.Millisecond
			case "caller-io-cancellation":
				ctx, stop = context.WithTimeout(ctx, 100*time.Millisecond)
				f.apiDelay = 30 * time.Millisecond
			case "human-expiry":
				f.humanUntil = short
			case "recovery-expiry":
				f.recoveryUntil = short
			case "grant-expiry":
				f.grantUntil = short
			case "current-deny":
				f.afterStorage = func() { f.denied.Store(true) }
			case "request-five-second-bound":
				ctx, stop = context.WithTimeout(ctx, 8*time.Second)
				f.storageDelay = 6 * time.Second
			}
			f.mu.Unlock()
			if stop != nil {
				defer stop()
			}
			started := time.Now()
			_, e = f.svc.Request(ctx, f, p.Preview.ID, "one-intent")
			if e == nil || errors.Is(e, metadataAdmitted) || f.admission.Load() != 0 {
				t.Fatal("expired/withdrawn authority reached admission", mode, e, f.stages)
			}
			if mode == "request-five-second-bound" && (time.Since(started) > 6*time.Second || time.Since(started) < 4500*time.Millisecond) {
				t.Fatal("original C09 five-second cap changed", time.Since(started))
			}
		})
	}
}
