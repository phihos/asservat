package kubernetes

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ownerBootstrapAPIFixture struct {
	writes, creates atomic.Int32
	failCAS         atomic.Int32 // 1 parent, 2 child, 3 receipt
	commitCAS       atomic.Bool
	loseCreate      atomic.Bool
	denyAfterCreate atomic.Bool
}

// Existing synthetic retained bridge, native denial and independent accepted
// observation are left intact. Only the fixed new object and resource CAS are
// modeled here. No permission/process SQL or real Kubernetes admission claim.
func installOwnerBootstrapAPI(t *testing.T, f *ownerIdentityOperationFixture) *ownerBootstrapAPIFixture {
	t.Helper()
	out := &ownerBootstrapAPIFixture{}
	f.api.mu.Lock()
	defer f.api.mu.Unlock()
	previous := f.api.extra
	collection := "/api/v1/namespaces/" + f.root.input.Namespace.Name + "/configmaps"
	name := contracts.OwnerBootstrapSelectionName(f.root.input.InstallationID)
	f.api.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Query().Get("dryRun") != "" {
			return previous(w, r)
		}
		journal := r.Method == http.MethodPut && r.URL.Path == f.resources.path()
		create := r.Method == http.MethodPost && r.URL.Path == collection
		if !journal && !create {
			return previous(w, r)
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Error(err)
			return true
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var object map[string]any
		if json.Unmarshal(raw, &object) != nil {
			t.Error("invalid fixture request")
			return true
		}
		metadata, _ := object["metadata"].(map[string]any)
		if create && metadata["name"] != name {
			return previous(w, r)
		}
		if r.URL.Query().Get("fieldValidation") != "Strict" {
			t.Error("missing strict validation")
		}
		object["apiVersion"] = "v1"
		full := r.URL.Path
		phase := int32(0)
		if journal {
			out.writes.Add(1)
			object["kind"] = "Secret"
			var secret core.Secret
			if json.Unmarshal(raw, &secret) != nil {
				t.Error("invalid journal")
				return true
			}
			state, err := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(secret.Data["state.json"]))
			if err != nil || state.OwnerBootstrap == nil {
				t.Error("invalid owner bootstrap CAS")
				return true
			}
			phase = 1
			if state.OwnerBootstrap.Child != nil {
				phase = 2
				if state.OwnerBootstrap.Child.Receipt != nil {
					phase = 3
				}
			}
			if out.failCAS.Load() == phase && !out.commitCAS.Load() {
				out.failCAS.Store(0)
				w.WriteHeader(503)
				return true
			}
			old := f.api.objects[full]
			if old == nil {
				t.Error("missing original journal")
				return true
			}
			oldMeta := old["metadata"].(map[string]any)
			if metadata["uid"] != oldMeta["uid"] || metadata["resourceVersion"] != oldMeta["resourceVersion"] {
				f.api.status(w, 409, meta.StatusReasonConflict, "secrets", "")
				return true
			}
			f.api.serial++
			metadata["resourceVersion"] = strconv.Itoa(f.api.serial)
			f.api.objects[full] = object
		} else {
			out.creates.Add(1)
			object["kind"] = "ConfigMap"
			full += "/" + name
			if f.api.objects[full] != nil {
				f.api.status(w, 409, meta.StatusReasonAlreadyExists, "configmaps", "")
				return true
			}
			encoded, _ := json.Marshal(object)
			f.api.store(full, encoded)
			if out.denyAfterCreate.Load() {
				f.fault.Store(1)
			}
			if out.loseCreate.Swap(false) {
				w.WriteHeader(503)
				return true
			}
		}
		if journal && out.failCAS.CompareAndSwap(phase, 0) {
			w.WriteHeader(503)
			return true
		}
		if create {
			w.WriteHeader(201)
		}
		permissionReply(w, f.api.objects[full])
		return true
	}
	return out
}
func ownerBootstrapPlanFixture(f *ownerIdentityOperationFixture) contracts.OwnerBootstrapPlan {
	roots := make([][]byte, len(f.resources.ownerRoots))
	for i, r := range f.resources.ownerRoots {
		roots[i] = append([]byte(nil), r...)
	}
	return contracts.OwnerBootstrapPlan{Format: contracts.OwnerBootstrapPlanFormat, PKIMount: "owner-pki", Connections: 4, Concurrency: 2, Peers: []contracts.OwnerBootstrapPeerPlan{{ClusterID: f.root.input.ClusterID, Roots: roots}}}
}

// Historical state for the existing runtime-reader component fixture only.
// This does not replace the real allocation/CAS producer in composed tests.
func ownerBootstrapRuntimeFixture(t *testing.T, in *contracts.OwnerDeployment, state *contracts.InitialRuntimeResourceState, account contracts.WorkerObjectReference) {
	t.Helper()
	at := state.OwnerIdentity.ClaimedAt
	p := &contracts.OwnerBootstrapSelectionClaim{IssuerEpoch: in.Observation.Peers[0].IssuerEpoch, OperationID: ownerID(19500), PermissionRootID: in.PermissionRootID, PKIMount: in.KeyService.PKIMount, Connections: in.Connections, Concurrency: in.Concurrency, PublicDigest: ownerBootstrapDigest("synthetic-runtime-selection", in.PermissionRootID), ClaimedAt: at, Until: at.Add(time.Second), Child: &contracts.OwnerBootstrapObjectAttempt{OperationID: ownerID(19501), ClaimedAt: at, Until: at.Add(time.Second), Receipt: &contracts.OwnerBootstrapObjectReceipt{Object: contracts.WorkerObjectReference{Name: contracts.OwnerBootstrapSelectionName(in.InstallationID), UID: ownerID(19502)}, ResourceVersion: "53", ObservedAt: at}}}
	for _, peer := range in.Observation.Peers {
		p.Peers = append(p.Peers, contracts.OwnerBootstrapPeerAllocation{ClusterID: peer.ClusterID, PeerID: peer.PeerID, RootsDigest: ownerBootstrapDigest("roots", peer.Roots)})
	}
	in.KeyService.ServerRole, in.KeyService.ClientRole = ownerBootstrapPKIRoles(*in, account)
	state.OwnerBootstrap = p
}
