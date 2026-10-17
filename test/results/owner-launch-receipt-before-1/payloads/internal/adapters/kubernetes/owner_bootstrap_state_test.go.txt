package kubernetes

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func ownerBootstrapStateFixture(t *testing.T) (string, contracts.InitialRuntimeResourceState, time.Time) {
	t.Helper()
	installation, state, now := configurationWorkerInputStateFixture(t)
	root := state.CapacityProjection.Setup.PermissionRootID
	state.OwnerBootstrap = &contracts.OwnerBootstrapSelectionClaim{IssuerEpoch: ownerID(19400), OperationID: ownerID(19401), PermissionRootID: root, PKIMount: "owner-pki", Connections: 4, Concurrency: 2, PublicDigest: strings.Repeat("a", 64), ClaimedAt: now.Add(-time.Second), Until: now.Add(time.Second), Peers: []contracts.OwnerBootstrapPeerAllocation{{ClusterID: ownerID(19402), PeerID: ownerID(19403), RootsDigest: strings.Repeat("b", 64)}}, Child: &contracts.OwnerBootstrapObjectAttempt{OperationID: ownerID(19404), ClaimedAt: now.Add(-time.Second), Until: now.Add(time.Second), Receipt: &contracts.OwnerBootstrapObjectReceipt{Object: contracts.WorkerObjectReference{Name: contracts.OwnerBootstrapSelectionName(installation), UID: ownerID(19405)}, ResourceVersion: "52", ObservedAt: now}}}
	return installation, state, now
}
func TestOwnerBootstrapStateRetainsOmissionAndHistoricalBytes(t *testing.T) {
	installation, state, now := ownerBootstrapStateFixture(t)
	raw, _ := json.Marshal(state)
	if !workerProjectionStateValid(installation, state, now) || !workerProjectionStateValid(installation, state, state.Until.Add(time.Hour)) {
		t.Fatal("closed original selection invalid")
	}
	decoded, err := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(decoded)
	if !bytes.Equal(raw, after) {
		t.Fatal("decode changed original state")
	}
	state.OwnerBootstrap = nil
	raw, _ = json.Marshal(state)
	if bytes.Contains(raw, []byte("ownerBootstrap")) {
		t.Fatal("legacy omission changed")
	}
}
func TestOwnerBootstrapStateRejectsAliasesAndUnboundedClaims(t *testing.T) {
	for name, change := range map[string]func(*contracts.InitialRuntimeResourceState){
		"original-operation": func(s *contracts.InitialRuntimeResourceState) {
			s.OwnerBootstrap.OperationID = s.Objects[0].OperationID
		},
		"child-operation": func(s *contracts.InitialRuntimeResourceState) {
			s.OwnerBootstrap.Child.OperationID = s.OwnerBootstrap.OperationID
		},
		"worker-operation": func(s *contracts.InitialRuntimeResourceState) {
			s.OwnerBootstrap.OperationID = s.WorkerInputs.OperationID
		},
		"capacity-operation": func(s *contracts.InitialRuntimeResourceState) {
			s.OwnerBootstrap.Child.OperationID = s.CapacityProjection.OperationID
		},
		"cleanup-object": func(s *contracts.InitialRuntimeResourceState) {
			s.OwnerBootstrap.Child.Receipt.Object.UID = s.CleanupProjection.Receipt.Secret.UID
		},
		"selected-provider": func(s *contracts.InitialRuntimeResourceState) {
			s.OwnerBootstrap.Child.Receipt.Object.UID = s.OwnerProvider.AuditCredentials.UID
		},
		"worker-sql": func(s *contracts.InitialRuntimeResourceState) {
			s.OwnerBootstrap.Child.Receipt.Object.UID = s.WorkerInputs.SQLProjection.UID
		},
		"peer-allocation": func(s *contracts.InitialRuntimeResourceState) {
			s.OwnerBootstrap.Peers[0].PeerID = s.OwnerBootstrap.PermissionRootID
		},
		"issuer-allocation": func(s *contracts.InitialRuntimeResourceState) {
			s.OwnerBootstrap.PermissionRootID = s.OwnerBootstrap.IssuerEpoch
		},
		"capacity-root": func(s *contracts.InitialRuntimeResourceState) {
			s.CapacityProjection.Setup.PermissionRootID = ownerID(19499)
		},
		"unfinished-original": func(s *contracts.InitialRuntimeResourceState) { s.Objects[18].Receipt = nil },
		"mixed-layout":        func(s *contracts.InitialRuntimeResourceState) { s.OwnerLayout = contracts.OwnerInstalledLayout },
		"zero-digest": func(s *contracts.InitialRuntimeResourceState) {
			s.OwnerBootstrap.PublicDigest = strings.Repeat("0", 64)
		},
		"root-window": func(s *contracts.InitialRuntimeResourceState) {
			s.OwnerBootstrap.Child.Until = s.Until.Add(time.Microsecond)
		},
		"long-child": func(s *contracts.InitialRuntimeResourceState) {
			s.OwnerBootstrap.Child.Until = s.OwnerBootstrap.Child.ClaimedAt.Add(6 * time.Second)
		},
		"late-receipt":          func(s *contracts.InitialRuntimeResourceState) { s.OwnerBootstrap.Child.Receipt.ObservedAt = s.Until },
		"path-mount":            func(s *contracts.InitialRuntimeResourceState) { s.OwnerBootstrap.PKIMount = "pki/roles" },
		"unbounded-connections": func(s *contracts.InitialRuntimeResourceState) { s.OwnerBootstrap.Connections = 65 },
		"duplicate-peer-allocation": func(s *contracts.InitialRuntimeResourceState) {
			s.OwnerBootstrap.Peers = append(s.OwnerBootstrap.Peers, s.OwnerBootstrap.Peers[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			installation, state, now := ownerBootstrapStateFixture(t)
			change(&state)
			if workerProjectionStateValid(installation, state, now) {
				t.Fatal("invalid original selection accepted")
			}
		})
	}
}
func TestOwnerBootstrapTransitionsPreserveSiblingsAndSingleAdmission(t *testing.T) {
	_, complete, _ := ownerBootstrapStateFixture(t)
	clone := func(v contracts.InitialRuntimeResourceState) contracts.InitialRuntimeResourceState {
		b, _ := json.Marshal(v)
		out, e := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	parent := clone(complete)
	parent.OwnerBootstrap.Child = nil
	empty := clone(parent)
	empty.OwnerBootstrap = nil
	pending := clone(complete)
	pending.OwnerBootstrap.Child.Receipt = nil
	if !ownerBootstrapTransition(empty, parent) || !ownerBootstrapTransition(parent, pending) || !ownerBootstrapTransition(pending, complete) {
		t.Fatal("fixed one-step transitions rejected")
	}
	if ownerBootstrapTransition(empty, pending) || ownerBootstrapTransition(parent, complete) || ownerBootstrapTransition(complete, complete) || ownerBootstrapTransition(complete, pending) {
		t.Fatal("combined/repeated/reset effect transition accepted")
	}
	changed := clone(complete)
	changed.WorkerInputs.PublicDigest = strings.Repeat("d", 64) + "x"
	if ownerBootstrapTransition(pending, changed) {
		t.Fatal("sibling mutation accepted")
	}
}
