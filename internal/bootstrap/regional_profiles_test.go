package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type profileQueue struct {
	fakeRecordingNodes
	node      collector.Identity
	profiles  []collector.Work
	available bool
}

func (q *profileQueue) NodeByName(name string) (delivery.NodeView, bool) {
	return delivery.NodeView{Identity: q.node, Current: q.available, Report: &collector.Report{Mechanisms: []collector.Availability{{Mechanism: collector.MechanismProfile, Prerequisites: true, Adapter: collector.AdapterAvailable}}}}, name == q.node.NodeName
}
func (q *profileQueue) EnqueueProfile(_ context.Context, p collector.ProfileCapture, until time.Time) (collector.Work, error) {
	w := collector.Work{ID: "33333333-3333-4333-8333-333333333333", Sequence: 1, Kind: collector.WorkProfileCapture, Profile: &p, NotAfter: until}
	q.profiles = append(q.profiles, w)
	return w, nil
}

type profilePlanReader struct{ plan planning.GoEndpointPlan }

type profilePodNodeFunc func(context.Context, artifact.PinnedPod) (string, error)

func (f profilePodNodeFunc) PodNode(ctx context.Context, pin artifact.PinnedPod) (string, error) {
	return f(ctx, pin)
}

func (p *profilePlanReader) ResolveProfilePlan(context.Context, targets.ProfileEndpointRequest) (planning.GoEndpointPlan, error) {
	return p.plan, nil
}

func profileHolderFixture(t *testing.T) (*ConnectorRecordings, *profileQueue, *profilePlanReader, artifact.ContextExpectation, targets.ProfileEndpointRequest, time.Time) {
	t.Helper()
	const id = "11111111-1111-4111-8111-111111111111"
	now := time.Now().UTC().Truncate(time.Microsecond)
	pin := artifact.PinnedPod{Namespace: "app", NamespaceUID: id, Name: "app-0", UID: id, NodeName: "node"}
	target := targets.Request{ClusterID: id, Namespace: configuration.NamespaceRef{Name: "app", UID: id}, Workload: configuration.WorkloadRef{Kind: "Pod", Name: "app-0", UID: id}, PodName: "app-0", PodUID: id}
	req := targets.ProfileEndpointRequest{Target: target, SourceRef: "pprof", Type: "heap", Mode: "snapshot", NativeLimit: 16 << 20}
	endpoint := targets.ProfileEndpointResolution{Request: req, SourceKind: targets.ProfileEndpointAdministratorProfile, SourceName: "pprof", AddressMode: "targetLoopback", Port: 6060, PathPolicy: planning.GoEndpointPathPolicy, DefinitionDigest: artifact.Digest{1}, EndpointDigest: artifact.Digest{2}, ResolvedAt: now}
	composition := planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "cpu", Profile: planning.ProfileRef{Catalog: "builtin", Name: "go-cpu", Version: "v1"}}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s"}
	frozen, _ := json.Marshal(planning.ProfileContext{Composition: composition, Endpoints: []targets.ProfileEndpointResolution{endpoint}})
	e := artifact.ContextExpectation{ExecutionClass: artifact.ContextAPIExecution, NativeType: artifact.PprofArtifact, DataClass: "raw", CaptureUID: id, PodUID: id, NamespaceUID: id, ActionID: "profile-cpu", Registration: artifact.Registration{Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, AnchorAt: now, WriteUntil: now.Add(time.Minute)}, Profile: &artifact.GoProfileAcquisition{SourceRef: "pprof", EndpointDigest: endpoint.EndpointDigest, Type: "heap", Mode: "snapshot", TimeoutMillis: 5000, MaxBytes: 16 << 20, Composition: frozen}}
	q := &profileQueue{node: collector.Identity{NodeUID: id, NodeName: "node", BootID: id, Epoch: id}, available: true}
	reader := &profilePlanReader{planning.GoEndpointPlan{SourceRef: "pprof", Definition: planning.GoEndpointDefinition{Host: "localhost"}, DefinitionDigest: endpoint.DefinitionDigest, EndpointDigest: endpoint.EndpointDigest, Target: target, Pin: pin, NodeUID: id, NodeBootID: id, AddressMode: "targetLoopback", RouteIP: netip.MustParseAddr("127.0.0.1"), Port: 6060, Parameters: execution.GoProfileParameters{Type: "heap", Mode: "snapshot"}, NativeLimit: 16 << 20, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}}
	h := NewConnectorRecordings(q, profilePodNodeFunc(func(context.Context, artifact.PinnedPod) (string, error) { return "node", nil }), func() time.Time { return now }, func(string) {})
	h.profileEndpoints = reader
	return h, q, reader, e, req, now
}

// Installed API-class endpoint plans intentionally carry no node identity.
// The private mechanism must resolve the same Pod's current node, as packet
// dispatch already does, while leaving the accepted API pin/digest untouched.
func TestConnectorProfileDispatchesAPIPlanThroughExactPodNode(t *testing.T) {
	for _, mode := range []string{"current", "pod-replaced", "unknown-node", "unavailable-node", "expired-route", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			h, q, reader, e, endpoint, now := profileHolderFixture(t)
			reader.plan.Pin.NodeName, reader.plan.NodeUID, reader.plan.NodeBootID = "", "", ""
			pin := reader.plan.Pin
			original := reader.plan
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			reads := 0
			h.pods = profilePodNodeFunc(func(call context.Context, got artifact.PinnedPod) (string, error) {
				reads++
				if call != ctx || got != pin {
					t.Fatal("node lookup changed original context or accepted API pin")
				}
				switch mode {
				case "pod-replaced":
					return "", errors.New("exact Pod changed")
				case "unknown-node":
					return "replacement", nil
				case "unavailable-node":
					q.available = false
				case "expired-route":
					h.now = func() time.Time { return original.ValidUntil }
				case "cancelled":
					cancel()
				}
				return "node", nil
			})
			_, err := h.PrepareProfile(&objectstore.PreparedArtifact{}, e).StartProfile(ctx, pin, now, now.Add(time.Second), endpoint)
			if reads != 1 {
				t.Fatalf("exact Pod node lookup count=%d error=%v", reads, err)
			}
			if mode != "current" {
				if err == nil || len(q.profiles) != 0 {
					t.Fatal("changed or expired target queued profile", err)
				}
				return
			}
			if err != nil || len(q.profiles) != 1 {
				t.Fatal("API endpoint plan did not reach its node", err)
			}
			work := q.profiles[0].Profile
			mechanismPin := pin
			mechanismPin.NodeName = "node"
			if !work.Valid() || work.Request.Pin != mechanismPin || work.Request.NodeUID != q.node.NodeUID || work.Request.NodeBootID != q.node.BootID || work.CollectorEpoch != q.node.Epoch || work.Request.EndpointDigest != original.EndpointDigest || reader.plan.Pin != pin || reader.plan.NodeUID != "" || reader.plan.NodeBootID != "" {
				t.Fatal("dispatch invented identity or changed accepted endpoint")
			}
		})
	}
}

func TestConnectorProfileQueuesOriginalDeadlineAndCollectsFailureOnce(t *testing.T) {
	h, q, reader, e, endpoint, now := profileHolderFixture(t)
	pin := reader.plan.Pin
	pin.NodeName = "" // public API pin has no node identity
	p := h.PrepareProfile(&objectstore.PreparedArtifact{}, e)
	if _, err := p.StartProfile(context.Background(), pin, now, now.Add(time.Second), endpoint); err != nil {
		t.Fatal(err)
	}
	if len(q.profiles) != 1 || !q.profiles[0].Profile.Request.Deadline.Equal(now.Add(5*time.Second)) || !q.profiles[0].NotAfter.Equal(now.Add(time.Second)) {
		t.Fatal(q.profiles)
	}
	if _, err := p.StartProfile(context.Background(), pin, now, now.Add(time.Second), endpoint); err == nil {
		t.Fatal("second start")
	}
	w := fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(e)}
	if c, err := h.Collect(w); err != nil || c.State != evidence.RecordingPending {
		t.Fatal(c, err)
	}
	result := collector.ProfileResult{WorkID: q.profiles[0].ID, CaptureID: e.CaptureUID, ExpectationDigest: w.ExpectationDigest, EndpointDigest: e.Profile.EndpointDigest, Failure: collector.ReasonCaptureFailed, Outcome: execution.GoProfileOutcome{Format: artifact.PprofFormat, CompletedAt: now}}
	wrong := q.node
	wrong.Epoch = "22222222-2222-4222-8222-222222222222"
	if err := h.DeliverProfile(context.Background(), wrong, result, bytes.NewReader(nil)); err == nil {
		t.Fatal("wrong process")
	}
	if err := h.DeliverProfile(context.Background(), q.node, result, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	if c, err := h.Collect(w); err != nil || c.State != evidence.RecordingFailed {
		t.Fatal(c, err)
	}
	if err := h.DeliverProfile(context.Background(), q.node, result, bytes.NewReader(nil)); err == nil {
		t.Fatal("second result")
	}
}

func TestConnectorProfileRefusesChangedOrExpiredRouteAndSharedCapacity(t *testing.T) {
	for _, change := range []string{"digest", "boot", "expiry", "capacity", "request"} {
		t.Run(change, func(t *testing.T) {
			h, q, r, e, endpoint, now := profileHolderFixture(t)
			switch change {
			case "digest":
				r.plan.EndpointDigest[0]++
			case "boot":
				q.node.BootID = "22222222-2222-4222-8222-222222222222"
			case "expiry":
				r.plan.ValidUntil = now
			case "capacity":
				for i := 0; i < maxHeldRecordings; i++ {
					h.held[string(rune(i))] = &heldRecording{expires: now.Add(time.Hour)}
				}
			case "request":
				endpoint.NativeLimit++
			}
			p := h.PrepareProfile(&objectstore.PreparedArtifact{}, e)
			if _, err := p.StartProfile(context.Background(), r.plan.Pin, now, now.Add(time.Second), endpoint); err == nil || len(q.profiles) != 0 {
				t.Fatal("invalid profile queued", change, err)
			}
		})
	}
}
