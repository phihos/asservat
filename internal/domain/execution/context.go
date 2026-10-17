package execution

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextStart is resolved from independent accepted references, current rights,
// local ceilings, registered custody and the current collector process epoch.
// It is never decoded directly from a peer request or uploaded manifest.
type ContextStart struct {
	Start       Request
	Expectation artifact.ContextExpectation
	Pin         artifact.PinnedPod
}

func (s ContextStart) Valid(a fleet.AuthenticatedAction, r fleet.Receiver, now time.Time) bool {
	w, b, e := a.Work, s.Start.Binding, s.Expectation
	if b.ExecutionClass != artifact.ContextNodeExecution || e.ExecutionClass != artifact.ContextNodeExecution || !slices.Contains(w.RequiredCapabilities, "pod-status/v1") || w.Validate(r, now) != nil || !a.TrustRevision.Valid() || !identity.Text(a.KeyID, 128) || !identity.Fresh(a.VerifiedAt, a.ValidUntil, now, 30*time.Second) || s.Start.Validate(now) != nil || e.Validate() != nil {
		return false
	}
	if s.Start.ValidUntil.After(a.ValidUntil) || s.Start.ValidUntil.After(r.ValidUntil) {
		return false
	}
	return b.OperationID == w.OperationID && b.CaptureID == w.CaptureID && b.ActionID == w.ActionID && b.AttemptID == w.AttemptID && b.ClusterID == w.ClusterID && b.IssuerEpoch == w.IssuerEpoch && b.PodUID == w.PodUID && b.NodeUID == w.NodeUID && b.NodeBootID == w.NodeBootID && b.CollectorEpoch == r.CollectorEpoch && b.ScopeDigest == w.ScopeDigest && b.AuthorityDigest == w.Authority.Digest && b.BudgetDigest == w.Budget.Digest && b.AuditDigest == w.Audit.Digest && !b.NotBefore.Before(w.IssuedAt) && !b.NotAfter.After(w.NotAfter) && b.NativeBytes == artifact.MaxContextBytes && e.ActionID == "pod-status" && e.ActionID == b.ActionID && e.CaptureUID == b.CaptureID && e.Registration.Location.ClusterID == b.ClusterID && e.Registration.Location.AttemptID == b.AttemptID && e.Registration.NativeLimit == b.NativeBytes && e.PlanDigest == b.ScopeDigest && e.PodUID == b.PodUID && e.NodeUID == b.NodeUID && e.NodeBootID == b.NodeBootID && e.DataClass == "metadata" && !now.Before(e.Registration.AnchorAt) && now.Before(e.Registration.WriteUntil) && !b.NotAfter.After(e.Registration.WriteUntil) && s.Pin.UID == e.PodUID && s.Pin.NamespaceUID == e.NamespaceUID && s.Pin.Namespace == e.Namespace && identity.Text(s.Pin.Name, 253) && identity.Text(s.Pin.NodeName, 253)
}
