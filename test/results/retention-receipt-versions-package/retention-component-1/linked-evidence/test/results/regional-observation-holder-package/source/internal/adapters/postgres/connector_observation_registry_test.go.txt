package postgres

import (
	"context"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type connectorObservationSourceTrap struct {
	calls int
	until time.Time
}

func (s *connectorObservationSourceTrap) ReadConnectorIdentitySource(ctx context.Context) (value.ConnectorIdentitySource, error) {
	s.calls++
	s.until, _ = ctx.Deadline()
	return value.ConnectorIdentitySource{}, value.ErrUnavailable
}

func TestConnectorObservationRegistryRejectsMismatchedOriginalBeforeAnyIO(t *testing.T) {
	id, other := "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"
	now := time.Now().UTC()
	b := value.PeerBinding{InstallationID: id, ClusterID: id, PeerID: id, IssuerEpoch: id, Role: value.ConnectorPeer}
	profile := value.ConnectorCredentialProfile{RootID: id, Binding: b, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, ServerName: "connector.invalid", ClientIssuerRoots: [][]byte{{1}}, ServerIssuerRoots: [][]byte{{2}}, Deployment: value.ConnectorDeployment{Namespace: "connector", NamespaceUID: id, ServiceAccount: "connector", AccountUID: id, Deployment: "connector", DeploymentUID: id, ServingSlots: 2, RetainedProcesses: 8}}
	leaf := value.ConnectorCredentialCertificate{Binding: b, Usage: "client", Digest: artifact.Digest{3}, PublicKeyDigest: artifact.Digest{4}, NotBefore: now.Add(-time.Second), NotAfter: now.Add(time.Minute)}
	if !profile.Valid() || !leaf.Valid(now) {
		t.Fatal("invalid fixture")
	}
	for _, mode := range []string{"root", "source", "revision", "cluster", "issuer", "roots", "controller", "suspended", "leaf-binding", "server-leaf", "expired-leaf", "cancelled", "matching"} {
		t.Run(mode, func(t *testing.T) {
			// A nil native pool would panic if any test accidentally reached SQL.
			// This exercises pre-I/O binding only, not native role qualification.
			registry := &ConnectorObservationRegistry{ledger: &Ledger{}, profile: profile.Clone()}
			original, selected := profile.Clone(), leaf
			source := &connectorObservationSourceTrap{}
			deadline := time.Now().Add(2 * time.Second)
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			switch mode {
			case "root":
				original.RootID = other
			case "source":
				original.Revision.UID = other
			case "revision":
				original.Revision.Generation++
			case "cluster":
				original.Binding.ClusterID = other
			case "issuer":
				original.Binding.IssuerEpoch = other
			case "roots":
				original.ClientIssuerRoots[0][0]++
			case "controller":
				original.Deployment.DeploymentUID = other
			case "suspended":
				original.Suspended = true
			case "leaf-binding":
				selected.Binding.PeerID = other
			case "server-leaf":
				selected.Usage, selected.ServerName = "server", profile.ServerName
			case "expired-leaf":
				selected.NotAfter = now
			case "cancelled":
				cancel()
			}
			got, err := registry.ReadConnectorObservationRegistration(ctx, original, source, selected)
			if err == nil || got != (app.ConnectorLeafRegistration{}) {
				t.Fatal("unavailable source returned activation")
			}
			want := 0
			if mode == "matching" {
				want = 1
				if !source.until.Equal(deadline) {
					t.Fatal("original caller deadline lost")
				}
			}
			if source.calls != want {
				t.Fatal("wrong original profile/leaf reached source I/O", source.calls, want)
			}
		})
	}
}
