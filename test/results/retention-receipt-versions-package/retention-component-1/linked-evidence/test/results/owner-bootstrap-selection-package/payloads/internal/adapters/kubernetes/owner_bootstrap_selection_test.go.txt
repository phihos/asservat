package kubernetes

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestOwnerBootstrapOriginalAllocationAndGeneratedInput(t *testing.T) {
	f := newOwnerIdentityOperationFixture(t)
	startOwnerIdentityOperationAcceptedObserver(t, f)
	api := installOwnerBootstrapAPI(t, f)
	plan := ownerBootstrapPlanFixture(f)
	producer, err := NewOwnerBootstrapSelectionProducer(f.root, plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(producer.Close)
	// Constructor copies the entire public root bundle; caller mutation cannot
	// alter the one original selection the producer is about to claim.
	plan.Peers[0].Roots[0] = []byte("caller replacement")
	var first contracts.OwnerBootstrapSelectionClaim
	for i, want := range []OwnerBootstrapAdvanceStatus{OwnerBootstrapIntentRecorded, OwnerBootstrapPending, OwnerBootstrapComplete} {
		out, err := producer.Advance(context.Background())
		if err != nil || out.Status != want {
			t.Fatal("phase", i, out.Status, err)
		}
		if i == 0 {
			first = *out.Snapshot.State.OwnerBootstrap
		}
		if out.Selection.PermissionRootID != first.PermissionRootID || out.Selection.Peers[0].PeerID != first.Peers[0].PeerID {
			t.Fatal("public allocation changed")
		}
		if i == 2 && (out.Input.PermissionRootID != first.PermissionRootID || out.Input.Observation.Peers[0].PeerID != first.Peers[0].PeerID || !ownerBootstrapDeploymentBound(out.Input, out.Snapshot.State)) {
			t.Fatal("generated input not bound to positive original selection")
		}
	}
	if api.creates.Load() != 1 || api.writes.Load() != 3 {
		t.Fatal("unexpected effects", api.creates.Load(), api.writes.Load())
	}
	out, err := producer.Inspect(context.Background())
	if err != nil || out.Status != OwnerBootstrapComplete || api.creates.Load() != 1 || api.writes.Load() != 3 {
		t.Fatal("completed replay wrote", err)
	}
	out.Selection.Peers[0].Roots[0][0] ^= 1
	if _, err = producer.Inspect(context.Background()); err != nil {
		t.Fatal("output alias altered retained source", err)
	}
	f.api.mu.Lock()
	rootCreated := f.api.objects[f.root.path()+"/"+f.root.name()] != nil
	f.api.mu.Unlock()
	if rootCreated {
		t.Fatal("public allocation created a SQL credential root")
	}
}

func TestOwnerBootstrapUnknownClaimCannotIssueCreate(t *testing.T) {
	for _, phase := range []int32{1, 2} {
		for _, committed := range []bool{false, true} {
			name := map[int32]string{1: "parent", 2: "child"}[phase] + map[bool]string{false: "-uncommitted", true: "-committed"}[committed]
			t.Run(name, func(t *testing.T) {
				f := newOwnerIdentityOperationFixture(t)
				startOwnerIdentityOperationAcceptedObserver(t, f)
				api := installOwnerBootstrapAPI(t, f)
				p, err := NewOwnerBootstrapSelectionProducer(f.root, ownerBootstrapPlanFixture(f))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				if phase == 2 {
					if _, err = p.Advance(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				api.failCAS.Store(phase)
				api.commitCAS.Store(committed)
				if _, err = p.Advance(context.Background()); err == nil {
					t.Fatal("unknown CAS reported success")
				}
				writes := api.writes.Load()
				out, readErr := p.Inspect(context.Background())
				if phase == 1 && committed || phase == 2 && !committed {
					if readErr != nil || out.Status != OwnerBootstrapIntentRecorded {
						t.Fatal("committed original intent not inspectable", readErr)
					}
				} else if readErr == nil {
					t.Fatal("absent/never-issued result accepted")
				}
				if api.creates.Load() != 0 || api.writes.Load() != writes {
					t.Fatal("lookup repeated effect")
				}
				if !committed {
					if _, err = p.Advance(context.Background()); err == nil || api.writes.Load() != writes {
						t.Fatal("same producer retried unknown CAS")
					}
				}
			})
		}
	}
}

func TestOwnerBootstrapLostCreateAndReceiptRemainExact(t *testing.T) {
	for _, receiptLost := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "receipt"}[receiptLost], func(t *testing.T) {
			f := newOwnerIdentityOperationFixture(t)
			startOwnerIdentityOperationAcceptedObserver(t, f)
			api := installOwnerBootstrapAPI(t, f)
			p, err := NewOwnerBootstrapSelectionProducer(f.root, ownerBootstrapPlanFixture(f))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			if _, err = p.Advance(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !receiptLost {
				api.loseCreate.Store(true)
			}
			_, err = p.Advance(context.Background())
			if !receiptLost && err == nil || receiptLost && err != nil {
				t.Fatal("create result", err)
			}
			pending, err := p.Inspect(context.Background())
			if err != nil || pending.Status != OwnerBootstrapPending {
				t.Fatal("exact created object unavailable", err)
			}
			original := *pending.Snapshot.State.OwnerBootstrap.Child
			if receiptLost {
				api.failCAS.Store(3)
				api.commitCAS.Store(true)
			}
			_, err = p.Advance(context.Background())
			if receiptLost && err == nil || !receiptLost && err != nil {
				t.Fatal("receipt result", err)
			}
			writes := api.writes.Load()
			out, err := p.Inspect(context.Background())
			if err != nil || out.Status != OwnerBootstrapComplete || api.creates.Load() != 1 || api.writes.Load() != writes {
				t.Fatal("receipt recovery repeated effects", err)
			}
			child := out.Snapshot.State.OwnerBootstrap.Child
			if child.OperationID != original.OperationID || !child.Until.Equal(original.Until) {
				t.Fatal("unknown child renewed")
			}
		})
	}
}

func TestOwnerBootstrapFinalGuardAndChildReplacementDeny(t *testing.T) {
	f := newOwnerIdentityOperationFixture(t)
	startOwnerIdentityOperationAcceptedObserver(t, f)
	api := installOwnerBootstrapAPI(t, f)
	p, err := NewOwnerBootstrapSelectionProducer(f.root, ownerBootstrapPlanFixture(f))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if _, err = p.Advance(context.Background()); err != nil {
		t.Fatal(err)
	}
	api.denyAfterCreate.Store(true)
	if _, err = p.Advance(context.Background()); err == nil {
		t.Fatal("lost current guard returned positive CREATE result")
	}
	f.fault.Store(0)
	api.denyAfterCreate.Store(false)
	original, err := p.Inspect(context.Background())
	if err != nil || original.Status != OwnerBootstrapPending {
		t.Fatal(err)
	}
	f.api.mu.Lock()
	path := "/api/v1/namespaces/" + f.root.input.Namespace.Name + "/configmaps/" + contracts.OwnerBootstrapSelectionName(f.root.input.InstallationID)
	f.api.objects[path]["metadata"].(map[string]any)["annotations"].(map[string]any)["asservat.io/owner-bootstrap-create"] = ownerID(19300)
	f.api.mu.Unlock()
	if _, err = p.Advance(context.Background()); err == nil {
		t.Fatal("foreign original attempt marker accepted")
	}
	if api.creates.Load() != 1 {
		t.Fatal("changed child recreated")
	}
}

func TestOwnerBootstrapCopiedAndClosedProducerHasNoEffect(t *testing.T) {
	f := newOwnerIdentityOperationFixture(t)
	api := installOwnerBootstrapAPI(t, f)
	p, err := NewOwnerBootstrapSelectionProducer(f.root, ownerBootstrapPlanFixture(f))
	if err != nil {
		t.Fatal(err)
	}
	// Deliberate outer value copy in this test; the original mutex is unlocked.
	copy := new(OwnerBootstrapSelectionProducer)
	reflect.ValueOf(copy).Elem().Set(reflect.ValueOf(p).Elem())
	if _, err = copy.Advance(context.Background()); err == nil {
		t.Fatal("copied producer admitted")
	}
	p.Close()
	if _, err = p.Advance(context.Background()); err == nil {
		t.Fatal("closed producer admitted")
	}
	if api.creates.Load() != 0 || api.writes.Load() != 0 {
		t.Fatal("invalid producer reached effect")
	}
}

func TestOwnerBootstrapChildIntentExpiryDoesNotBecomeNewCreateAuthority(t *testing.T) {
	installation, state, now := configurationWorkerInputStateFixture(t)
	state.CapacityProjection = nil
	state.CleanupProjection = nil
	state.OwnerBootstrap = &contracts.OwnerBootstrapSelectionClaim{IssuerEpoch: ownerID(19200), OperationID: ownerID(19201), PermissionRootID: ownerID(19202), PKIMount: "owner-pki", Connections: 4, Concurrency: 2, PublicDigest: ownerBootstrapDigest("test", true), ClaimedAt: now.Add(-time.Second), Until: now, Peers: []contracts.OwnerBootstrapPeerAllocation{{ClusterID: ownerID(19203), PeerID: ownerID(19204), RootsDigest: ownerBootstrapDigest("test-roots", true)}}, Child: &contracts.OwnerBootstrapObjectAttempt{OperationID: ownerID(19205), ClaimedAt: now, Until: now.Add(time.Second)}}
	raw, _ := json.Marshal(state)
	if !ownerBootstrapStateValid(installation, state, now.Add(time.Hour)) {
		t.Fatal("historical pending child became unreadable")
	}
	after, _ := json.Marshal(state)
	if string(raw) != string(after) {
		t.Fatal("validation extended original dates")
	}
}

func TestOwnerBootstrapPositiveCreatePinsIdentityBeforeReceipt(t *testing.T) {
	f := newOwnerIdentityOperationFixture(t)
	startOwnerIdentityOperationAcceptedObserver(t, f)
	api := installOwnerBootstrapAPI(t, f)
	p, err := NewOwnerBootstrapSelectionProducer(f.root, ownerBootstrapPlanFixture(f))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if _, err = p.Advance(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Advance(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.api.mu.Lock()
	path := "/api/v1/namespaces/" + f.root.input.Namespace.Name + "/configmaps/" + contracts.OwnerBootstrapSelectionName(f.root.input.InstallationID)
	f.api.objects[path]["metadata"].(map[string]any)["uid"] = ownerID(19600)
	f.api.mu.Unlock()
	if _, err = p.Advance(context.Background()); err == nil {
		t.Fatal("positively observed object replaced before receipt")
	}
	if api.creates.Load() != 1 || api.writes.Load() != 2 {
		t.Fatal("replacement changed effect disposition")
	}
}

func TestOwnerBootstrapUnknownParentPinsExactLocalAllocation(t *testing.T) {
	f := newOwnerIdentityOperationFixture(t)
	startOwnerIdentityOperationAcceptedObserver(t, f)
	api := installOwnerBootstrapAPI(t, f)
	p, err := NewOwnerBootstrapSelectionProducer(f.root, ownerBootstrapPlanFixture(f))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	api.failCAS.Store(1)
	api.commitCAS.Store(true)
	if _, err = p.Advance(context.Background()); err == nil {
		t.Fatal("unknown claim accepted")
	}
	if p.pendingParent == nil {
		t.Fatal("exact attempted allocation forgotten")
	}
	foreign := *p.pendingParent
	foreign.OperationID = ownerID(19601)
	if p.originalAttempt(&foreign) {
		t.Fatal("different valid-shaped selection replaced unknown allocation")
	}
	if !p.originalAttempt(p.pendingParent) {
		t.Fatal("original allocation rejected")
	}
	if api.creates.Load() != 0 {
		t.Fatal("unknown parent issued child")
	}
}

func TestOwnerBootstrapGeneratedBindingRejectsCallerAuthoritySubstitution(t *testing.T) {
	f := newOwnerIdentityOperationFixture(t)
	startOwnerIdentityOperationAcceptedObserver(t, f)
	installOwnerBootstrapAPI(t, f)
	p, err := NewOwnerBootstrapSelectionProducer(f.root, ownerBootstrapPlanFixture(f))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	completed, err := p.Complete(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(completed.Input)
	for name, change := range map[string]func(*contracts.OwnerDeployment){
		"permission-root": func(in *contracts.OwnerDeployment) { in.PermissionRootID = ownerID(19620) },
		"logical-peer":    func(in *contracts.OwnerDeployment) { in.Observation.Peers[0].PeerID = ownerID(19621) },
		"cluster":         func(in *contracts.OwnerDeployment) { in.Observation.Peers[0].ClusterID = ownerID(19622) },
		"issuer":          func(in *contracts.OwnerDeployment) { in.Observation.Peers[0].IssuerEpoch = ownerID(19623) },
		"trust":           func(in *contracts.OwnerDeployment) { in.Observation.Peers[0].Roots[0][0] ^= 1 },
		"pki-role":        func(in *contracts.OwnerDeployment) { in.KeyService.ServerRole = "caller-role" },
		"pool-budget":     func(in *contracts.OwnerDeployment) { in.Connections++ },
	} {
		t.Run(name, func(t *testing.T) {
			var changed contracts.OwnerDeployment
			if json.Unmarshal(raw, &changed) != nil {
				t.Fatal("fixture input")
			}
			change(&changed)
			if ownerBootstrapDeploymentBound(changed, completed.Snapshot.State) {
				t.Fatal("caller replaced original selection")
			}
		})
	}
	// Same complete scope is deterministic; a different original account/source
	// namespace cannot collide in provider-global signing role names.
	a, b := ownerBootstrapPKIRoles(completed.Input, f.root.input.ServiceAccount)
	changed := completed.Input
	changed.Namespace.UID = ownerID(19624)
	c, d := ownerBootstrapPKIRoles(changed, f.root.input.ServiceAccount)
	if a == b || a == c || b == d || len(a) > 128 || len(b) > 128 {
		t.Fatal("PKI recipe role scope/bounds")
	}
}

func TestOwnerBootstrapProjectionRejectsCallerPermissionRootBeforeClaim(t *testing.T) {
	f := newOwnerProjectionOperationFixture(t)
	raw, err := json.Marshal(f.projection.projection.input)
	if err != nil {
		t.Fatal(err)
	}
	var changed contracts.OwnerDeployment
	if json.Unmarshal(raw, &changed) != nil {
		t.Fatal("fixture input")
	}
	changed.PermissionRootID = ownerID(19625)
	p, err := NewProviderOwnerProjection(f.root, f.verification, changed, f.provider.reader)
	if err != nil {
		t.Fatal("pure constructor unexpectedly established current journal authority", err)
	}
	if _, err = p.Advance(context.Background()); err == nil {
		t.Fatal("caller permission root reached original projection claim")
	}
	if f.journalWrites.Load() != 0 || f.creates[0].Load() != 0 || f.verification.checks != 0 {
		t.Fatal("original selection check happened after claim/credential authority")
	}
}

func TestOwnerBootstrapSameClusterAllocatesDistinctLogicalPeers(t *testing.T) {
	f := newOwnerIdentityOperationFixture(t)
	startOwnerIdentityOperationAcceptedObserver(t, f)
	api := installOwnerBootstrapAPI(t, f)
	plan := ownerBootstrapPlanFixture(f)
	// Two original logical profiles can belong to the same cluster and trust
	// bundle. Their independently allocated identities must remain distinct.
	plan.Peers = append(plan.Peers, plan.Peers[0])
	p, err := NewOwnerBootstrapSelectionProducer(f.root, plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	out, err := p.Complete(context.Background())
	if err != nil || out.Status != OwnerBootstrapComplete {
		t.Fatal(out.Status, err)
	}
	peers := out.Input.Observation.Peers
	if len(peers) != 2 || peers[0].ClusterID != peers[1].ClusterID || peers[0].PeerID == peers[1].PeerID || !equalJSON(peers[0].Roots, plan.Peers[0].Roots) || !equalJSON(peers[1].Roots, plan.Peers[1].Roots) {
		t.Fatal("logical peers collapsed or original trust changed")
	}
	if !ownerBootstrapStateValid(f.root.input.InstallationID, out.Snapshot.State, time.Now()) || api.creates.Load() != 1 || api.writes.Load() != 3 {
		t.Fatal("same-cluster allocation invalid or repeated")
	}
	if out.Selection.InitialFormat != f.root.resources.initial.Format {
		t.Fatal("original installer format changed")
	}
}
