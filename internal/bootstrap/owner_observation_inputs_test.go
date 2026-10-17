package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

func TestOwnerObservationInputIsExplicitAndFinite(t *testing.T) {
	for _, mode := range []string{"valid", "legacy", "mixed", "format", "empty-peers", "duplicate-peer", "excess-peers", "missing-root", "zero-template", "upper-image", "guessed-process", "missing-activation", "wrong-activation-namespace", "wrong-activation-root"} {
		t.Run(mode, func(t *testing.T) {
			in, dir, c := ownerInputFixture(t)
			c.Observation = &contracts.OwnerObservationBootstrap{Format: contracts.OwnerObservationFormat, TemplateDigest: strings.Repeat("1", 64), ImageDigest: strings.Repeat("2", 64), ProtectionDigest: strings.Repeat("3", 64), Activation: ownerObservationTestActivation(c), Peers: []contracts.OwnerObservationPeer{{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, PeerID: runtimeID, Roots: c.Kubernetes.Roots}}}
			switch mode {
			case "missing-activation":
				c.Observation.Activation = nil
			case "wrong-activation-namespace":
				c.Observation.Activation.Input.Namespace.Name = "other"
			case "wrong-activation-root":
				c.Observation.Activation.RoleRoot.Name = "other"
			case "legacy":
				c.Observation = nil
			case "mixed":
				c.Native = &contracts.OwnerNativeDeployment{}
			case "format":
				c.Observation.Format = "unknown/v1"
			case "empty-peers":
				c.Observation.Peers = nil
			case "duplicate-peer":
				c.Observation.Peers = append(c.Observation.Peers, c.Observation.Peers[0])
			case "excess-peers":
				c.Observation.Peers = make([]contracts.OwnerObservationPeer, 17)
			case "missing-root":
				c.Observation.Peers[0].Roots = nil
			case "zero-template":
				c.Observation.TemplateDigest = strings.Repeat("0", 64)
			case "upper-image":
				c.Observation.ImageDigest = strings.Repeat("A", 64)
			}
			writeOwnerJSON(t, dir, "deployment.json", c)
			if mode == "guessed-process" {
				raw, e := os.ReadFile(filepath.Join(dir, "deployment.json"))
				if e != nil {
					t.Fatal(e)
				}
				raw = bytes.Replace(raw, []byte(`"peerID":`), []byte(`"processEpoch":"`+runtimeID+`","peerID":`), 1)
				if e = os.WriteFile(filepath.Join(dir, "deployment.json"), raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			got, e := readOwnerInputs(context.Background(), in.files)
			if mode == "valid" || mode == "legacy" {
				if e != nil {
					t.Fatal(e)
				}
				if (got.config.Observation == nil) != (mode == "legacy") {
					t.Fatal("mode changed")
				}
			} else if e == nil {
				t.Fatal("unbounded/ambiguous input accepted")
			}
			if mode == "legacy" {
				raw, e := json.Marshal(c)
				if e != nil || bytes.Contains(raw, []byte(`"observation"`)) {
					t.Fatal("legacy bytes gained observation field", e)
				}
			}
		})
	}
}
func TestOwnerObservationPinsNeverAdoptAnotherAcceptedPool(t *testing.T) {
	_, _, c := ownerInputFixture(t)
	c.Observation = &contracts.OwnerObservationBootstrap{Format: contracts.OwnerObservationFormat, TemplateDigest: strings.Repeat("1", 64), ImageDigest: strings.Repeat("2", 64), ProtectionDigest: strings.Repeat("3", 64), Activation: ownerObservationTestActivation(c), Peers: []contracts.OwnerObservationPeer{{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, PeerID: runtimeID, Roots: c.Kubernetes.Roots}}}
	p := value.OwnerPool{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, Namespace: c.Namespace.Name, NamespaceUID: c.Namespace.UID, Service: "hub", ServiceUID: runtimeID, Deployment: "hub", DeploymentUID: runtimeID, ServiceAccount: "hub", AccountUID: runtimeID, Port: 9443, NativePort: 9444, NativeBootstrap: value.OwnerBootstrapProfile}
	pin, peers, e := ownerObservationConfig(c, p)
	if e != nil || !pin.Valid() || len(peers) != 1 {
		t.Fatal("valid explicit pin", e)
	}
	original := peers[0].Roots[0][0]
	c.Observation.Peers[0].Roots[0][0] ^= 1
	if peers[0].Roots[0][0] != original {
		t.Fatal("input root alias retained")
	}
	c.Observation.Peers[0].Roots[0][0] ^= 1
	for _, mode := range []string{"unopted", "namespace", "installation", "cluster", "peer-epoch"} {
		t.Run(mode, func(t *testing.T) {
			changed := p
			switch mode {
			case "unopted":
				changed.NativeBootstrap = ""
			case "namespace":
				changed.Namespace = "other"
			case "installation":
				changed.InstallationID = "22222222-2222-4222-8222-222222222222"
			case "cluster":
				changed.ClusterID = "22222222-2222-4222-8222-222222222222"
			case "peer-epoch":
				changed.IssuerEpoch = "22222222-2222-4222-8222-222222222222"
			}
			if _, _, e = ownerObservationConfig(c, changed); e == nil {
				t.Fatal("changed original pool adopted")
			}
		})
	}
}

func ownerObservationTestActivation(c contracts.OwnerDeployment) *contracts.OwnerIdentityActivation {
	suffix := strings.ReplaceAll(c.InstallationID, "-", "")
	first := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	return &contracts.OwnerIdentityActivation{
		Input:    contracts.OwnerIdentityRoles{Format: contracts.OwnerIdentityRolesFormat, InstallationID: c.InstallationID, InitialClaimID: runtimeID, ClusterID: c.ClusterID, Namespace: c.Namespace, OwnerConfigurationUID: c.ConfigurationUID, Resources: contracts.WorkerObjectReference{Name: "asservat-runtime-resources-" + suffix, UID: "22222222-2222-4222-8222-222222222222"}, ResourceSetupID: runtimeID, ResourceBinding: strings.Repeat("1", 64), OwnerLayout: contracts.OwnerInstalledLayout, Deployment: contracts.WorkerObjectReference{Name: "asservat-" + suffix + "-owner", UID: "33333333-3333-4333-8333-333333333333"}, ServiceAccount: contracts.WorkerObjectReference{Name: "asservat-" + suffix + "-owner", UID: "44444444-4444-4444-8444-444444444444"}, LayoutDigest: strings.Repeat("2", 64)},
		RoleRoot: contracts.WorkerObjectReference{Name: "asservat-owner-identity-roles-" + suffix, UID: "55555555-5555-4555-8555-555555555555"}, RoleSetupID: runtimeID, ResourcesCreatedAt: first, ResourcesUntil: first.Add(30 * time.Minute),
	}
}
