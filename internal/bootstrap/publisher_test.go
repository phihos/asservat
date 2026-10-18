package bootstrap

import (
	"context"
	"os"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// ADR-181/203: the publisher's protected inputs are closed and bounded, its
// role manifest must belong to the same installation and namespace, its
// guard covers its own namespace and its provider roles are exactly the
// recipe of this input.
func TestPublisherInputsAreClosedAndBound(t *testing.T) {
	valid := map[string]bool{"valid": true, "empty-topology": true}
	for _, mode := range []string{"valid", "empty-topology", "format", "poll", "batch", "store", "http-evidence", "no-topology", "duplicate-topology", "foreign-manifest", "missing-manifest",
		"guard-namespace", "guard-endpoint", "owner-workload", "catalog", "catalog-guard", "issuer-roots", "provider-profile", "split-provider", "static-audit-key", "plain-verifier"} {
		t.Run(mode, func(t *testing.T) {
			_, dir, owner := ownerInputFixture(t)
			roots := owner.Kubernetes.Roots
			namespace := contracts.WorkerObjectReference{Name: "hub", UID: runtimeID}
			topology := contracts.OwnerNativeTopology{TargetClusterID: runtimeID, Name: "topology", UID: runtimeID, SHA256: strings.Repeat("1", 64)}
			c := contracts.PublisherDeployment{Format: contracts.PublisherDeploymentFormat, InstallationID: runtimeID, ClusterID: runtimeID, PermissionRootID: runtimeID, Namespace: namespace, Kubernetes: owner.Kubernetes, Postgres: owner.Postgres,
				RetentionTopologies: []contracts.OwnerNativeTopology{topology},
				ClusterCatalog:      contracts.OwnerPublicGuardedSource{Source: contracts.WorkerObjectReference{Name: "cluster-catalog", UID: runtimeID}, Guard: owner.WorkloadGuard},
				Owner:               owner.Guard(), OwnerWorkload: contracts.WorkerObjectReference{Name: "hub-api", UID: runtimeID},
				AuditStore: owner.AuditStore, AuditKeys: contracts.PublisherTransit{Endpoint: "https://keys.synthetic.invalid", Roots: roots, Mount: "audit", Key: providerconfig.PublisherAuditKey(runtimeID)},
				Evidence: contracts.PublisherEvidence{Endpoint: "https://evidence.synthetic.invalid", Roots: roots, Region: "local", Bucket: "evidence", StoreID: runtimeID},
				Artifact: contracts.PublisherArtifacts{Endpoint: "https://artifact-keys.synthetic.invalid", Roots: roots, KeyID: "artifact"},
				Verifier: contracts.PublisherVerifier{Endpoint: "https://keys.synthetic.invalid", Roots: roots, PKIMount: "worker-pki", Role: contracts.PublisherVerifierRole(runtimeID), IssuerRoots: roots}, PollSeconds: 5, Batch: 8}
			recipe, err := providerconfig.PublisherProviderRecipeFor(c, contracts.PublisherProviderAuthentication{AuthMount: "kubernetes", AuthMountAccessor: "auth_kubernetes_1", Namespace: namespace,
				ServiceAccount: contracts.WorkerObjectReference{Name: contracts.PublisherName(runtimeID), UID: "11111111-1111-4111-8111-1111111120a3"}})
			if err != nil {
				t.Fatal(err)
			}
			c.ProviderAuthentication = recipe.Profile
			m := contracts.PublicRuntimeCredentialManifest{Format: contracts.PublicRuntimeCredentialManifestFormat, Input: contracts.PublicRuntimeRoles{InstallationID: runtimeID, ClusterID: runtimeID, Namespace: c.Namespace}}
			switch mode {
			case "format":
				c.Format = "asservat-publisher-deployment/v0"
			case "poll":
				c.PollSeconds = 0
			case "batch":
				c.Batch = 65
			case "store":
				c.Evidence.StoreID = "evidence"
			case "http-evidence":
				c.Evidence.Endpoint = "http://evidence.synthetic.invalid"
			case "no-topology":
				c.RetentionTopologies = nil
			case "empty-topology":
				c.RetentionTopologies = []contracts.OwnerNativeTopology{}
			case "duplicate-topology":
				other := topology
				other.Name = "other-topology"
				c.RetentionTopologies = append(c.RetentionTopologies, other)
			case "foreign-manifest":
				m.Input.InstallationID = "10000000-0000-4000-8000-0000000000aa"
			case "guard-namespace":
				c.Owner.Namespace = contracts.WorkerObjectReference{Name: "other-hub", UID: "11111111-1111-4111-8111-1111111120a4"}
			case "guard-endpoint":
				c.Owner.Kubernetes.Endpoint = "https://other-api.synthetic.invalid"
			case "owner-workload":
				c.OwnerWorkload.UID = "hub-api"
			case "catalog":
				c.ClusterCatalog.Source.UID = ""
			case "catalog-guard":
				c.ClusterCatalog.Guard.Administrators = nil
			case "issuer-roots":
				c.Verifier.IssuerRoots = nil
			case "provider-profile":
				c.ProviderAuthentication.RecipeSHA256 = strings.Repeat("0", 64)
			case "split-provider":
				c.Verifier.Endpoint = "https://pki.synthetic.invalid"
			case "static-audit-key":
				c.AuditKeys.Key = "records"
			case "plain-verifier":
				c.Verifier.Endpoint = "http://keys.synthetic.invalid"
				c.AuditKeys.Endpoint = c.Verifier.Endpoint
			}
			writeOwnerJSON(t, dir, contracts.PublisherDeploymentFile, c)
			if mode != "missing-manifest" {
				writeOwnerJSON(t, dir, contracts.PublisherCredentialManifestFile, m)
			}
			files, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer files.Close()
			_, _, _, err = readPublisherInputs(context.Background(), files)
			if valid[mode] != (err == nil) {
				t.Fatal("publisher input decision", mode, err)
			}
		})
	}
}

// ADR-203 decision 6: the catalog's joined slots add their own topology pins
// to the fixed ones; either may be empty, and a slot naming another cluster
// or slot, or a cluster or topology named twice, is refused.
func TestPublisherTopologyPinsUnionCatalogSlots(t *testing.T) {
	const regional = "11111111-1111-4111-8111-1111111120b1"
	fixed := contracts.OwnerNativeTopology{TargetClusterID: runtimeID, Name: "hub-topology", UID: runtimeID, SHA256: strings.Repeat("1", 64)}
	slot := contracts.OwnerPublicCluster{ClusterID: regional, Topology: contracts.OwnerNativeTopology{TargetClusterID: regional, Name: contracts.OwnerClusterSourceName(runtimeID, 1, "topology"), UID: regional, SHA256: strings.Repeat("2", 64)}}
	c := contracts.PublisherDeployment{InstallationID: runtimeID, RetentionTopologies: []contracts.OwnerNativeTopology{}}
	pins, err := publisherTopologyPins(c, nil)
	if err != nil || pins == nil || len(pins) != 0 {
		t.Fatal("empty union", pins, err)
	}
	c.RetentionTopologies = []contracts.OwnerNativeTopology{fixed}
	pins, err = publisherTopologyPins(c, []contracts.OwnerPublicCluster{slot})
	if err != nil || len(pins) != 2 || pins[0].TargetClusterID != runtimeID || pins[1].TargetClusterID != regional || pins[1].Name != slot.Topology.Name || pins[1].ContentDigest[0] != 0x22 {
		t.Fatal("union", pins, err)
	}
	for name, mutate := range map[string]func(*contracts.OwnerPublicCluster){
		"other cluster": func(s *contracts.OwnerPublicCluster) { s.Topology.TargetClusterID = runtimeID },
		"other slot": func(s *contracts.OwnerPublicCluster) {
			s.Topology.Name = contracts.OwnerClusterSourceName(runtimeID, 2, "topology")
		},
		"empty digest":   func(s *contracts.OwnerPublicCluster) { s.Topology.SHA256 = strings.Repeat("0", 64) },
		"fixed cluster":  func(s *contracts.OwnerPublicCluster) { s.ClusterID, s.Topology.TargetClusterID = runtimeID, runtimeID },
		"fixed topology": func(s *contracts.OwnerPublicCluster) { s.Topology.Name = fixed.Name },
	} {
		changed := slot
		mutate(&changed)
		if _, err = publisherTopologyPins(c, []contracts.OwnerPublicCluster{changed}); err == nil {
			t.Fatal("accepted:", name)
		}
	}
}
