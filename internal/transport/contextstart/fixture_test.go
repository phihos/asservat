package contextstart

import (
	"context"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// workFixture is one synthetic verified API context work for stream tests.
func workFixture() fleet.AuthenticatedAPIContextWork {
	id := func(n string) string { return "00000000-0000-4000-8000-0000000000" + n }
	n := time.Now().UTC().Truncate(time.Microsecond)
	actor := identity.Principal{Issuer: "https://identity.invalid", Subject: "actor", ClientID: "console", Kind: identity.Human}
	rev := identity.Revision{UID: "revision", Generation: 1, Digest: [32]byte{1}}
	hub := fleet.OwnerBinding{InstallationID: id("01"), ClusterID: id("02"), IssuerEpoch: id("03"), PodUID: id("04"), ProcessEpoch: id("05")}
	peer := fleet.ConnectorProcessIdentity{Binding: fleet.PeerBinding{InstallationID: hub.InstallationID, ClusterID: id("06"), IssuerEpoch: hub.IssuerEpoch, PeerID: id("07"), Role: fleet.ConnectorPeer}, PodUID: id("08"), ProcessEpoch: id("09")}
	channel := fleet.APIContextChannel{RootID: id("10"), ExchangeID: id("11"), Challenge: id("12"), Hub: hub, Connector: peer, ConnectorLeaf: artifact.Digest{1}, Executor: fleet.APIContextExecutor{NamespaceUID: id("13"), AccountUID: id("14"), PodUID: peer.PodUID, ProcessEpoch: id("15"), StartupDigest: artifact.Digest{2}, ImageDigest: artifact.Digest{3}}}
	w := fleet.APIContextWork{Channel: channel, CaptureID: id("16"), AttemptID: id("17"), Actor: actor, Target: authorization.Target{ClusterID: peer.Binding.ClusterID, NamespaceUID: id("18"), WorkloadUID: id("19"), PodUID: id("20")}, ScopeDigest: artifact.Digest{1}, ExpectationDigest: artifact.Digest{2}, IntentDigest: artifact.Digest{3}, BudgetDigest: artifact.Digest{4}, Capability: rev, ProjectionDigest: artifact.Digest{5}, IssuedAt: n, NotAfter: n.Add(5 * time.Second)}
	return fleet.AuthenticatedAPIContextWork{Work: w, KeyID: "key", TrustRevision: rev, VerifiedAt: n, ValidUntil: w.NotAfter}
}

// countingLocal is a regional port set that only counts calls; tests that use
// it expect no regional operation to run.
type countingLocal struct{ calls int }

func (c *countingLocal) ReadAPIProcess(context.Context) (value.APIProcessObservation, error) {
	c.calls++
	return value.APIProcessObservation{}, value.ErrUnavailable
}
func (c *countingLocal) ResolvePod(context.Context, targets.Request) (targets.PodResolution, error) {
	c.calls++
	return targets.PodResolution{}, value.ErrUnavailable
}
func (c *countingLocal) ResolveWorkload(context.Context, targets.WorkloadRequest) (targets.PodResolution, error) {
	c.calls++
	return targets.PodResolution{}, value.ErrUnavailable
}
func (c *countingLocal) PrepareStart(context.Context, value.PreparationCheck) (value.PreparedStart, error) {
	c.calls++
	return value.PreparedStart{}, value.ErrUnavailable
}
func (c *countingLocal) ReadyStart(context.Context, value.Request) (value.Disposition, error) {
	c.calls++
	return value.Disposition{}, value.ErrUnavailable
}
func (c *countingLocal) ConsumeStart(context.Context, value.Request) (value.Disposition, error) {
	c.calls++
	return value.Disposition{}, value.ErrUnavailable
}
func (c *countingLocal) LookupStart(context.Context, value.Request) (value.Disposition, error) {
	c.calls++
	return value.Disposition{}, value.ErrUnavailable
}
func (c *countingLocal) PrepareContext(context.Context, artifact.ContextExpectation) (evidence.PreparedContext, error) {
	c.calls++
	return nil, value.ErrUnavailable
}
func (c *countingLocal) Capture(context.Context, artifact.PinnedPod) ([]byte, error) {
	c.calls++
	return nil, value.ErrUnavailable
}

func (c *countingLocal) ReadConnectorIdentitySource(context.Context) (fleet.ConnectorIdentitySource, error) {
	c.calls++
	return fleet.ConnectorIdentitySource{}, fleet.ErrUnavailable
}

func (c *countingLocal) local() RegionalLocal {
	return RegionalLocal{Process: c, Targets: c, Local: c, Starts: c, Output: c, Collector: c, Source: c, Now: time.Now}
}
