package bootstrap

import (
	"context"
	"os"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// ADR-181: the publisher's protected inputs are closed and bounded, and its
// role manifest must belong to the same installation and namespace.
func TestPublisherInputsAreClosedAndBound(t *testing.T) {
	for _, mode := range []string{"valid", "format", "poll", "batch", "store", "http-evidence", "no-topology", "foreign-manifest", "missing-manifest"} {
		t.Run(mode, func(t *testing.T) {
			_, dir, owner := ownerInputFixture(t)
			roots := owner.Kubernetes.Roots
			c := contracts.PublisherDeployment{Format: contracts.PublisherDeploymentFormat, InstallationID: runtimeID, ClusterID: runtimeID, PermissionRootID: runtimeID, Namespace: contracts.WorkerObjectReference{Name: "hub", UID: runtimeID}, Kubernetes: owner.Kubernetes, Postgres: owner.Postgres,
				RetentionTopologies: []contracts.OwnerNativeTopology{{TargetClusterID: runtimeID, Name: "topology", UID: runtimeID, SHA256: strings.Repeat("1", 64)}},
				AuditStore:          owner.AuditStore, AuditKeys: contracts.PublisherTransit{Endpoint: "https://keys.synthetic.invalid", Roots: roots, Mount: "audit", Key: "records"},
				Evidence: contracts.PublisherEvidence{Endpoint: "https://evidence.synthetic.invalid", Roots: roots, Region: "local", Bucket: "evidence", StoreID: runtimeID},
				Artifact: contracts.PublisherArtifacts{Endpoint: "https://artifact-keys.synthetic.invalid", Roots: roots, KeyID: "artifact"}, PollSeconds: 5, Batch: 8}
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
			case "foreign-manifest":
				m.Input.InstallationID = "10000000-0000-4000-8000-0000000000aa"
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
			if (mode == "valid") != (err == nil) {
				t.Fatal("publisher input decision", mode, err)
			}
		})
	}
}
