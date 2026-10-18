package bootstrap

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
)

func registrationSourceFixture(t *testing.T, r *RegionalLifecycle, request value.ConnectorProcessRequest, now time.Time) value.ConnectorIdentitySource {
	t.Helper()
	profile := value.ConnectorCredentialProfile{RootID: r.Credential.Profile.RootID, Binding: request.Process.Binding,
		Revision: identity.Revision{UID: regionalPod, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, ServerName: "connector.example",
		Deployment:        value.ConnectorDeployment{Namespace: "control", NamespaceUID: regionalPod, ServiceAccount: "connector", AccountUID: regionalPod, Deployment: "connector", DeploymentUID: regionalPod, ServingSlots: 1, RetainedProcesses: 2},
		ClientIssuerRoots: [][]byte{{1}}, ServerIssuerRoots: [][]byte{{2}}}
	source := value.ConnectorIdentitySource{Observation: value.ConnectorCredentialObservation{Profile: profile, Backing: value.ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{3}, SourceDigest: artifact.Digest{4}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)},
		Roles: value.ConnectorIdentityRoles{Source: "source", Journal: "journal", Acknowledgement: "ack", Cleanup: "cleanup", Verifier: "verifier", Finalizer: "finalizer"}}
	if !source.Valid(now) {
		t.Fatal("synthetic source fixture invalid")
	}
	return source
}

// Real TLS1.3/HTTP2/exporter-bound presentation with scripted registry/native
// authority. This qualifies the explicit source handoff, not native enforcement
// or SQL49. The ordinary Local reader cannot supply a valid source in this fixture.
func TestRegionalRegistrationAtOwnsOnlyOneOriginalSourceConversation(t *testing.T) {
	for _, mode := range []string{"two-reads", "one-read", "three-reads", "configuration", "begin", "revoked", "cancelled", "expired", "foreign-source", "unknown-leaf", "missing-local"} {
		t.Run(mode, func(t *testing.T) {
			r, services, request, presenter, _ := regionalLifecycleSetup(t)
			now := time.Now().UTC()
			var clock atomic.Int64
			clock.Store(now.UnixNano())
			r.Now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			source := registrationSourceFixture(t, r, request, now)
			leaf := value.ConnectorCredentialCertificate{Binding: request.Process.Binding, Usage: "client", Digest: artifact.Digest{5}, PublicKeyDigest: artifact.Digest{6}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(20 * time.Minute)}
			r.issued = []regionalLeaf{{certificate: leaf, request: request}}
			ctx, cancel := context.WithDeadline(context.Background(), now.Add(2*time.Second))
			defer cancel()
			end, _ := ctx.Deadline()
			services.readRegistration = func(call context.Context, region *connectorlifecycle.Region, certificate value.ConnectorCredentialCertificate) (app.ConnectorLeafRegistration, error) {
				first, err := region.ReadConnectorIdentitySource(call)
				if err != nil || first.Observation.ObservedAt != source.Observation.ObservedAt || first.Observation.FreshUntil.After(end) || !first.Observation.SameSource(source.Observation) {
					return app.ConnectorLeafRegistration{}, value.ErrDenied
				}
				// Mutating a received public buffer must not alter the reader's next reply.
				first.Observation.Profile.ClientIssuerRoots[0][0] = 99
				if mode != "one-read" {
					last, err := region.ReadConnectorIdentitySource(call)
					if err != nil || last.Observation.Profile.ClientIssuerRoots[0][0] != 1 || last.Observation.ObservedAt != source.Observation.ObservedAt || last.Observation.FreshUntil.After(end) {
						return app.ConnectorLeafRegistration{}, value.ErrDenied
					}
				}
				switch mode {
				case "three-reads":
					_, _ = region.ReadConnectorIdentitySource(call)
				case "configuration":
					_, _ = region.ReadConnectorIdentityConfiguration(call)
				case "begin":
					_, _ = region.BeginConnectorLifecycle(call, app.ConnectorLifecycleRequest{Binding: value.ConnectorLifecycleBinding{ID: regionalEpoch, Purpose: value.ConnectorLifecycleEnroll, Process: request.Process, RequestedAt: now, NotAfter: end}, Request: request})
				case "revoked":
					return app.ConnectorLeafRegistration{}, value.ErrDenied
				case "cancelled":
					cancel()
				case "expired":
					clock.Store(source.Observation.FreshUntil.UnixNano())
				}
				return app.ConnectorLeafRegistration{Certificate: certificate, Process: request.Process, Revision: source.Observation.Profile.Revision, ObservedAt: now, FreshUntil: end}, nil
			}
			if mode == "foreign-source" {
				source.Observation.Profile.RootID = regionalEpoch
			}
			if mode == "unknown-leaf" {
				leaf.Digest = artifact.Digest{9}
			}
			if mode == "missing-local" {
				r.Local = nil
			}
			registered, err := r.ConnectorLeafRegistrationAt(ctx, leaf, source)
			if mode == "two-reads" {
				if err != nil || registered.Certificate != leaf || registered.Process != request.Process || registered.FreshUntil.After(end) || len(presenter.seen) != 1 {
					t.Fatal("original source conversation", err)
				}
			} else if err == nil {
				t.Fatal("invalid or late read-only conversation returned a registration", mode)
			}
			if (mode == "foreign-source" || mode == "unknown-leaf" || mode == "missing-local") && len(presenter.seen) != 0 {
				t.Fatal("invalid provenance reached the hub")
			}
		})
	}
}

func TestRegionalRegistrationSourceCannotOutliveClose(t *testing.T) {
	r, _, request := regionalLifecycleFixture(t)
	now := time.Now().UTC()
	source := registrationSourceFixture(t, r, request, now)
	reader := &regionalRegistrationSource{root: context.Background(), source: source, now: time.Now}
	reader.close()
	if _, err := reader.ReadConnectorIdentitySource(context.Background()); err == nil || reader.complete() {
		t.Fatal("closed source reused")
	}
}
