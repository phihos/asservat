package kubernetes

import (
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectorIdentitySnapshotIsClosedPinnedAndNotAuthority(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	root := base64.StdEncoding.EncodeToString(ownerConfigurationTestRoot(t, now))
	binding := value.PeerBinding{InstallationID: ownerID(1), ClusterID: ownerID(2), IssuerEpoch: ownerID(3), PeerID: ownerID(4), Role: value.ConnectorPeer}
	for _, mode := range []string{"valid", "suspended", "retiring", "retiring-live", "missing-retiring", "missing-overdue", "missing-backing", "unknown-backing", "missing-budget", "public-layout", "short-backing", "unknown", "missing-suspended", "duplicate", "trailing", "foreign-root", "foreign-cluster", "foreign-peer", "invalid-role", "same-role", "empty-roots", "wrong-root", "wildcard", "ip-name", "mixed-case-name"} {
		t.Run(mode, func(t *testing.T) {
			roles := map[string]any{"source": "connector_source", "journal": "connector_journal", "acknowledgement": "connector_ack", "cleanup": "connector_cleanup", "verifier": "connector_verifier", "finalizer": "connector_finalizer"}
			wire := map[string]any{"format": "asservat-connector-identity/v1", "rootID": ownerID(5), "installationID": binding.InstallationID, "clusterID": binding.ClusterID, "issuerEpoch": binding.IssuerEpoch, "peerID": binding.PeerID, "revision": 1, "retiring": false, "suspended": false, "serverName": "connector.example.invalid", "clientIssuerRoots": []string{root}, "serverIssuerRoots": []string{root}, "roles": roles, "backing": connectorTestBacking(now, binding), "deployment": map[string]any{"namespace": "owners", "namespaceUID": ownerID(6), "serviceAccount": "connector", "accountUID": ownerID(12), "deployment": "connector", "deploymentUID": ownerID(13), "servingSlots": 2, "retainedProcesses": 8}}
			switch mode {
			case "retiring":
				wire["retiring"], wire["suspended"] = true, true
			case "retiring-live":
				wire["retiring"] = true
			case "missing-retiring":
				delete(wire, "retiring")
			case "missing-overdue":
				b := connectorTestBacking(now, binding)
				b.Policy.OverdueTerminal = ""
				wire["backing"] = b
			case "missing-backing":
				delete(wire, "backing")
			case "unknown-backing":
				b, _ := json.Marshal(wire["backing"])
				var m map[string]any
				_ = json.Unmarshal(b, &m)
				m["OperatorSaysEnough"] = true
				wire["backing"] = m
			case "missing-budget":
				b, _ := json.Marshal(wire["backing"])
				var m map[string]any
				_ = json.Unmarshal(b, &m)
				delete(m, "SourceWALReservedBytes")
				wire["backing"] = m
			case "public-layout":
				b := connectorTestBacking(now, binding)
				b.Policy.History.Layout = audit.OperationVerificationHistoryLayout
				wire["backing"] = b
			case "short-backing":
				b := connectorTestBacking(now, binding)
				b.SourceBackupReservedBytes--
				wire["backing"] = b
			case "suspended":
				wire["suspended"] = true
			case "unknown":
				wire["secretDSN"] = "forbidden"
			case "missing-suspended":
				delete(wire, "suspended")
			case "foreign-root":
				wire["rootID"] = ownerID(99)
			case "foreign-cluster":
				wire["clusterID"] = ownerID(99)
			case "foreign-peer":
				wire["peerID"] = ownerID(99)
			case "invalid-role":
				roles["source"] = "x; SET ROLE admin"
			case "same-role":
				roles["acknowledgement"] = roles["journal"]
			case "empty-roots":
				wire["serverIssuerRoots"] = []string{}
			case "wrong-root":
				wire["clientIssuerRoots"] = []string{"AQ=="}
			case "wildcard":
				wire["serverName"] = "*.example.invalid"
			case "ip-name":
				wire["serverName"] = "127.0.0.1"
			case "mixed-case-name":
				wire["serverName"] = "Connector.example.invalid"
			}
			raw, _ := json.Marshal(wire)
			text := string(raw)
			if mode == "duplicate" {
				text = strings.Replace(text, `"revision":1`, `"revision":1,"revision":1`, 1)
			}
			if mode == "trailing" {
				text += "{}"
			}
			fixture := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				switch r.URL.Path {
				case "/api/v1/namespaces/" + permissionControl.Name:
					permissionReply(w, permissionNamespace(permissionControl.Name, ownerID(6)))
					return true
				case "/api/v1/namespaces/" + permissionControl.Name + "/configmaps/connector-identity":
					permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "connector-identity", "namespace": permissionControl.Name, "uid": ownerID(7), "resourceVersion": "1"}, "data": map[string]string{"connector-identity.json": text}})
					return true
				}
				return false
			})
			fixture.client.control.UID = ownerID(6)
			source := &ConnectorIdentitySource{client: fixture.client, name: "connector-identity", uid: ownerID(7), installation: binding.InstallationID, root: ownerID(5), binding: binding}
			got, until, e := source.snapshot(context.Background())
			if mode != "valid" && mode != "suspended" && mode != "retiring" {
				if e == nil {
					t.Fatal("invalid source accepted")
				}
				return
			}
			if e != nil || !got.Observation.Profile.WellFormed() || !got.Roles.Valid() || !until.Equal(now.Add(time.Hour)) {
				t.Fatal("valid source failed", e)
			}
			if got.Observation.Profile.Valid() || got.Valid(now) {
				t.Fatal("syntax snapshot fabricated independent protection/freshness")
			}
			if got.Observation.Profile.Suspended != (mode == "suspended" || mode == "retiring") || got.Observation.Profile.Retiring != (mode == "retiring") {
				t.Fatal("negative source state lost")
			}
		})
	}
}

func connectorTestBacking(now time.Time, binding value.PeerBinding) app.ConnectorIdentityBacking {
	q := audit.OperationHistoryQualification{ID: ownerID(8), Digest: artifact.Digest{1}, Layout: audit.ConnectorOperationHistoryLayout, MaximumRowFootprintBytes: 1 << 20, MaximumTransitionWALBytes: 1 << 20, BackupCopies: 1, WALCopies: 1}
	p := audit.OperationLifecyclePolicy{RootID: ownerID(5), Lane: "identity", OverdueTerminal: audit.OperationOverdueTerminal, InstallationID: binding.InstallationID, StoreID: ownerID(9), PolicyID: ownerID(10), BackupProfileID: ownerID(11), PolicyDigest: artifact.Digest{2}, BackupProfileDigest: artifact.Digest{3}, BackingRevision: 1, MetadataSlots: 256, MaxPurgeLeases: 2, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, ValidUntil: now.Add(time.Hour), History: &q}
	b, w := q.SlotBacking(p.MaxPurgeLeases)
	p.BackupReservedBytes = 256 * b
	p.WALReservedBytes = 256 * w
	return app.ConnectorIdentityBacking{AccountVersion: "connector-accounts/v1", AccountLimit: 2, RecordsPerAccount: 128, RetainedSeconds: 10800, ProfileLimit: 2, SourceTransitionLimit: 10, SourceBackupReservedBytes: 6 << 20, SourceWALReservedBytes: 20 << 20, Policy: p}
}

func TestConnectorBackingOnlyEditPreservesBehavioralProcessIdentity(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	root := base64.StdEncoding.EncodeToString(ownerConfigurationTestRoot(t, now))
	binding := value.PeerBinding{InstallationID: ownerID(1), ClusterID: ownerID(2), IssuerEpoch: ownerID(3), PeerID: ownerID(4), Role: value.ConnectorPeer}
	backing := connectorTestBacking(now, binding)
	wire := map[string]any{"format": "asservat-connector-identity/v1", "rootID": ownerID(5), "installationID": binding.InstallationID, "clusterID": binding.ClusterID, "issuerEpoch": binding.IssuerEpoch, "peerID": binding.PeerID, "revision": 1, "retiring": false, "suspended": false, "serverName": "connector.example.invalid", "clientIssuerRoots": []string{root}, "serverIssuerRoots": []string{root}, "roles": map[string]any{"source": "connector_source", "journal": "connector_journal", "acknowledgement": "connector_ack", "cleanup": "connector_cleanup", "verifier": "connector_verifier", "finalizer": "connector_finalizer"}, "backing": backing, "deployment": map[string]any{"namespace": "owners", "namespaceUID": ownerID(6), "serviceAccount": "connector", "accountUID": ownerID(12), "deployment": "connector", "deploymentUID": ownerID(13), "servingSlots": 2, "retainedProcesses": 8}}
	var body atomic.Value
	var version atomic.Value
	version.Store("1")
	raw, _ := json.Marshal(wire)
	body.Store(string(raw))
	fixture := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v1/namespaces/" + permissionControl.Name:
			permissionReply(w, permissionNamespace(permissionControl.Name, ownerID(6)))
			return true
		case "/api/v1/namespaces/" + permissionControl.Name + "/configmaps/connector-identity":
			permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "connector-identity", "namespace": permissionControl.Name, "uid": ownerID(7), "resourceVersion": version.Load().(string)}, "data": map[string]string{"connector-identity.json": body.Load().(string)}})
			return true
		}
		return false
	})
	fixture.client.control.UID = ownerID(6)
	source := &ConnectorIdentitySource{client: fixture.client, name: "connector-identity", uid: ownerID(7), installation: binding.InstallationID, root: ownerID(5), binding: binding}
	first, _, err := source.snapshotConfiguration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	backing.Policy.BackingRevision++
	backing.Policy.ValidUntil = backing.Policy.ValidUntil.Add(time.Hour)
	backing.Policy.PolicyDigest[0]++
	wire["backing"] = backing
	version.Store("2")
	raw, _ = json.Marshal(wire)
	body.Store(string(raw))
	renewed, _, err := source.snapshotConfiguration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !first.Source.Observation.Profile.Equal(renewed.Source.Observation.Profile) {
		t.Fatal("backing-only renewal invalidated the live process and leaf identity")
	}
	if first.Source.Observation.Backing.SourceDigest == renewed.Source.Observation.Backing.SourceDigest || first.Source.Observation.Backing.Digest == renewed.Source.Observation.Backing.Digest {
		t.Fatal("complete current backing identity was dropped")
	}
	if connectorBackingEqual(first.Backing, renewed.Backing) {
		t.Fatal("complete protected backing change lost")
	}
	wire["roles"].(map[string]any)["verifier"] = "changed_verifier"
	version.Store("3")
	wire["serverName"] = "changed.example.invalid"
	raw, _ = json.Marshal(wire)
	body.Store(string(raw))
	changed, _, err := source.snapshotConfiguration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if changed.Source.Observation.Profile.Revision.Digest == first.Source.Observation.Profile.Revision.Digest {
		t.Fatal("behavioral mutation did not change the scope digest")
	}
}
