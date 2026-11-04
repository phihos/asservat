package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/planning"
)

type profileAuthorizationFunc func(context.Context, planning.GoEndpointSource) ([]byte, error)

func (f profileAuthorizationFunc) ReadProfileAuthorization(ctx context.Context, p planning.GoEndpointSource) ([]byte, error) {
	return f(ctx, p)
}

func TestProfileAuthorizationHeldAudienceAndOriginalWork(t *testing.T) {
	for _, mode := range []string{"current", "old-node", "wrong-audience", "replicaset-is-not-root", "wrong-work", "wrong-sequence", "changed-deadline", "changed-definition", "wrong-epoch", "stopped", "expired", "cancelled", "stopped-during-read", "expired-during-read", "provider-refused", "bad-value"} {
		t.Run(mode, func(t *testing.T) {
			h, q, plan, e, endpoint, now := profileHolderFixture(t)
			const id = "11111111-1111-4111-8111-111111111111"
			q.tls, q.auth = true, true
			e.WorkloadUID = endpoint.Target.Workload.UID
			// The audience is the resolved Deployment root, never its immediate
			// ReplicaSet controller. The existing fixture supplies synthetic pins.
			endpoint.Target.Workload.Kind = "Deployment"
			plan.plan.Target = endpoint.Target
			plan.plan.Pin.ControllerUID = "22222222-2222-4222-8222-222222222222"
			policy := planning.GoEndpointSource{ClusterID: id, ResourceUID: id, Name: "pprof", Digest: artifact.Digest{7}}
			plan.plan.Definition.TLS = &planning.GoEndpointTLS{Trust: policy, ServerName: "profile.internal"}
			material := execution.GoProfileTLSMaterial{RootsPEM: "bounded public fixture", ServerName: "profile.internal"}
			material.RootsDigest = artifact.Digest(sha256.Sum256([]byte(material.RootsPEM)))
			plan.plan.TLSMaterial = material
			plan.plan.Definition.TLS.Trust.Digest = material.RootsDigest
			plan.plan.Definition.Credential = &planning.GoEndpointCredential{Policy: policy, Audiences: []planning.GoEndpointAudience{{ClusterID: id, NamespaceUID: id, WorkloadKind: "Deployment", WorkloadUID: id}}}
			// Keep the frozen endpoint's exact request in the synthetic accepted
			// composition when changing only its workload-kind provenance.
			var frozen planning.ProfileContext
			if json.Unmarshal(e.Profile.Composition, &frozen) != nil {
				t.Fatal("fixture composition")
			}
			frozen.Endpoints[0].Request = endpoint
			e.Profile.Composition, _ = json.Marshal(frozen)
			reads := 0
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var returned []byte
			h.SetProfileAuthorizationReader(profileAuthorizationFunc(func(call context.Context, got planning.GoEndpointSource) ([]byte, error) {
				reads++
				if got != policy || call.Err() != nil {
					t.Error("provider received changed policy or cancelled call")
				}
				switch mode {
				case "stopped-during-read":
					h.mu.Lock()
					h.profiles[e.CaptureUID].stop = &collector.ProfileStop{}
					h.mu.Unlock()
				case "expired-during-read":
					h.now = func() time.Time { return now.Add(time.Minute) }
				case "provider-refused":
					return nil, errors.New("fixture private refusal")
				case "bad-value":
					return []byte("invalid\r\n"), nil
				}
				returned = []byte("Bearer synthetic-private-sentinel")
				return returned, nil
			}))
			if mode == "old-node" {
				q.auth = false
			}
			if mode == "wrong-audience" {
				plan.plan.Definition.Credential.Audiences[0].WorkloadUID = "33333333-3333-4333-8333-333333333333"
			}
			if mode == "replicaset-is-not-root" {
				plan.plan.Definition.Credential.Audiences[0].WorkloadUID = plan.plan.Pin.ControllerUID
			}
			_, err := h.PrepareProfile(&objectstore.PreparedArtifact{}, e).StartProfile(ctx, plan.plan.Pin, now, now.Add(time.Second), endpoint)
			if mode == "old-node" || mode == "wrong-audience" || mode == "replicaset-is-not-root" {
				if err == nil || len(q.profiles) != 0 || reads != 0 {
					t.Fatal("unapproved audience/old node reached queue or provider", err, reads)
				}
				return
			}
			if err != nil {
				t.Fatal("authenticated fixture start", err)
			}
			work := q.profiles[0]
			profile := *work.Profile
			work.Profile = &profile
			originalJSON, _ := json.Marshal(work)
			switch mode {
			case "wrong-work":
				work.ID = "44444444-4444-4444-8444-444444444444"
			case "wrong-sequence":
				work.Sequence++
			case "changed-deadline":
				work.NotAfter = work.NotAfter.Add(time.Millisecond)
			case "changed-definition":
				work.Profile.DefinitionDigest[0] ^= 1
			case "wrong-epoch":
				q.node.Epoch = "33333333-3333-4333-8333-333333333333"
			case "stopped":
				h.profiles[e.CaptureUID].stop = &collector.ProfileStop{}
			case "expired":
				h.now = func() time.Time { return work.NotAfter }
			case "cancelled":
				cancel()
			}
			value, err := h.ReadNodeProfileAuthorization(ctx, q.node, work)
			if mode == "current" {
				if err != nil || string(value) != "Bearer synthetic-private-sentinel" || reads != 1 {
					t.Fatal("selected credential not delivered", err, reads)
				}
			} else {
				if err == nil || len(value) != 0 {
					t.Fatal("changed work disclosed credential", mode)
				}
				if mode != "stopped-during-read" && mode != "expired-during-read" && mode != "provider-refused" && mode != "bad-value" && reads != 0 {
					t.Fatal("refused work read private material", mode, reads)
				}
				if returned != nil && !bytes.Equal(returned, make([]byte, len(returned))) {
					t.Fatal("failed read retained private result")
				}
			}
			if bytes.Contains(originalJSON, []byte("synthetic-private-sentinel")) {
				t.Fatal("public queue contains private material")
			}
		})
	}
}

func TestNodeProfileAuthorizationDeliveryOwnsItsPrivateCopy(t *testing.T) {
	h, q, plan, e, endpoint, now := profileHolderFixture(t)
	if _, err := h.PrepareProfile(&objectstore.PreparedArtifact{}, e).StartProfile(t.Context(), plan.plan.Pin, now, now.Add(time.Second), endpoint); err != nil {
		t.Fatal(err)
	}
	work := q.profiles[0]
	work.Profile.AuthorizationRequired = true
	work.Profile.TLS = execution.GoProfileTLSMaterial{RootsPEM: "public", RootsDigest: artifact.Digest(sha256.Sum256([]byte("public"))), ServerName: "profile.internal"}
	var budgetMu sync.Mutex
	budget, _ := collector.NewBudget(collector.Ceilings{FrozenBytes: 32 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, now)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var acquired []byte
	n := &nodeProfiles{identity: func() collector.Identity { return q.node }, now: func() time.Time { return now }, budget: func() *collector.Budget { return budget }, budgetMu: &budgetMu,
		acquire: func(_ context.Context, p collector.ProfileCapture, authorization []byte, w io.Writer) (execution.GoProfileOutcome, error) {
			calls.Add(1)
			close(entered)
			<-release
			if string(authorization) != "Bearer receive-only-sentinel" {
				t.Error("private material aliases caller poll buffer")
			}
			acquired = authorization
			_, _ = w.Write([]byte("native"))
			return execution.GoProfileOutcome{Format: artifact.PprofFormat, StartedAt: now, CompletedAt: now, MayHaveStarted: true, ResponseComplete: true, NativeBytes: 6}, nil
		}, upload: func(_ context.Context, _ string, result collector.ProfileResult, _ io.Reader) error {
			raw, _ := json.Marshal(result)
			if bytes.Contains(raw, []byte("receive-only-sentinel")) {
				t.Error("credential escaped into result provenance")
			}
			return nil
		}}
	private := []byte("Bearer receive-only-sentinel")
	if receipt := n.start(t.Context(), q.node.Epoch, work, private); receipt.Outcome != collector.OutcomeAccepted {
		t.Fatal("private work refused", receipt)
	}
	<-entered
	clear(private)
	close(release)
	n.wg.Wait()
	if calls.Load() != 1 || !bytes.Equal(acquired, make([]byte, len(acquired))) {
		t.Fatal("private acquisition copy was retained after completion")
	}
	if receipt := n.start(t.Context(), q.node.Epoch, work, []byte("Bearer receive-only-sentinel")); receipt.Outcome == collector.OutcomeAccepted || calls.Load() != 1 {
		t.Fatal("private replay started another acquisition")
	}
}
