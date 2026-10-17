package kubernetes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	fleet "asservat.local/asservat/internal/domain/fleet"
)

func TestConfigurationWorkerOwnerDecoderKeepsCompleteBodyWithoutIO(t *testing.T) {
	now := time.Now().UTC()
	client := &PermissionClient{clusterID: ownerID(1), control: cfg.NamespaceRef{Name: "owners", UID: ownerID(2)}, now: func() time.Time { return now }}
	// A nil API makes any hidden network read fail this test. These values alone
	// establish neither native protection nor an authority interval.
	source := &OwnerConfigurationSource{client: client, installation: ownerID(3), name: "owner-source", uid: ownerID(4)}
	base := contracts.OwnerConfiguration{Format: contracts.OwnerConfigurationFormat, InstallationID: source.installation, ClusterID: client.clusterID,
		IssuerEpoch: ownerID(5), Revision: 1, Namespace: contracts.WorkerObjectReference{Name: client.control.Name, UID: client.control.UID},
		Service: contracts.WorkerObjectReference{Name: "owner", UID: ownerID(6)}, Deployment: contracts.WorkerObjectReference{Name: "owner", UID: ownerID(7)},
		ServiceAccount: contracts.WorkerObjectReference{Name: "owner", UID: ownerID(8)}, Port: 9443, NativePort: 9444,
		NativeBootstrap: fleet.OwnerBootstrapProfile, NativeCandidateLimit: 1024, IssuerRoots: [][]byte{ownerConfigurationTestRoot(t, now)}}
	for _, mode := range []string{"valid", "unknown", "case-alias", "duplicate", "trailing", "namespace", "cluster", "installation", "candidate-overflow", "unselected-candidates", "expired-roots", "missing-root"} {
		t.Run(mode, func(t *testing.T) {
			wire := base
			switch mode {
			case "namespace":
				wire.Namespace.UID = ownerID(99)
			case "cluster":
				wire.ClusterID = ownerID(99)
			case "installation":
				wire.InstallationID = ownerID(99)
			case "candidate-overflow":
				wire.NativeCandidateLimit = 1025
			case "unselected-candidates":
				wire.NativeBootstrap = ""
			case "missing-root":
				wire.IssuerRoots = nil
			}
			raw, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "unknown":
				raw = append(raw[:len(raw)-1], []byte(`,"secret":"forbidden"}`)...)
			case "case-alias":
				raw = []byte(strings.Replace(string(raw), `"revision"`, `"Revision"`, 1))
			case "duplicate":
				raw = []byte(strings.Replace(string(raw), `"revision":1`, `"revision":1,"revision":1`, 1))
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "expired-roots":
				client.now = func() time.Time { return now.Add(2 * time.Hour) }
			}
			defer func() { client.now = func() time.Time { return now } }()
			got, until, err := source.decodeOwnerConfiguration(map[string]string{"owner-pool.json": string(raw)})
			if mode != "valid" {
				if err == nil {
					t.Fatal("invalid complete owner body accepted")
				}
				return
			}
			if err != nil || got.Pool.NativeCandidateLimit != 1024 || got.Pool.NativeBootstrap != fleet.OwnerBootstrapProfile || got.Revision.UID != source.uid || !until.After(now) || got.ProtectionDigest != ([32]byte{}) {
				t.Fatalf("pure full owner decode lost original inputs or invented protection: %v", err)
			}
		})
	}
}

func TestConfigurationWorkerFleetDecoderCannotRenewOriginalInterval(t *testing.T) {
	start := time.Now().UTC()
	validator, err := newPermissionValidator()
	if err != nil {
		t.Fatal(err)
	}
	client := &PermissionClient{validator: validator, clusterID: ownerID(1), control: cfg.NamespaceRef{Name: "owners", UID: ownerID(2)}, now: func() time.Time { return start.Add(6 * time.Second) }}
	source := &FleetSettingsClient{client: client, name: "fleet", uid: ownerID(3), installation: ownerID(4)}
	wire := contracts.FleetSettings{SchemaVersion: "fleet-settings/v1", InstallationID: source.installation, IssuerEpoch: ownerID(5), Revision: 1,
		Issuer: "https://identity.example.test", Clients: []string{"console"}, Subjects: []contracts.IdentitySubject{}, Groups: []string{"operators"}, DeliveryProfiles: []string{"ops"}, MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	got, err := source.decodeFleetAdministration(map[string]string{"fleet.json": string(raw)}, cfg.Resource{UID: source.uid}, start)
	if err != nil || !got.ObservedAt.Equal(start) || !got.FreshUntil.Equal(start.Add(5*time.Second)) || got.Valid(client.now()) {
		t.Fatalf("body decoding refreshed an expired observation: %v", err)
	}
}
