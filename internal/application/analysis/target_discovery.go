package analysis

import (
	"context"
	"errors"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type TargetDiscoveryRoutes interface {
	ResolveTargetDiscoveryRoute(context.Context, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error)
}
type TargetDiscoveryReads struct {
	Service ContextProjectionService
	Routes  TargetDiscoveryRoutes
}

func (s ContextProjectionService) TargetDiscoveries() (TargetDiscoveryReads, bool) {
	return TargetDiscoveryReads{Service: s, Routes: s.DiscoveryRoutes}, s.DiscoveryRoutes != nil
}

type targetDiscoveryPreAdmissionRefusal struct{ cause error }

func (e *targetDiscoveryPreAdmissionRefusal) Error() string { return e.cause.Error() }
func (e *targetDiscoveryPreAdmissionRefusal) Unwrap() error { return e.cause }
func TargetDiscoveryUnavailableBeforeAdmission(err error) bool {
	var refusal *targetDiscoveryPreAdmissionRefusal
	return errors.As(err, &refusal)
}

func (s TargetDiscoveryReads) Begin(ctx context.Context, current identities.CurrentIdentity, invocation ContextQueryInvocation, r value.TargetDiscoveryRequest) (*ContextProjectionDelivery, error) {
	if s.Routes == nil || !r.Valid() {
		return nil, &targetDiscoveryPreAdmissionRefusal{value.ErrUnavailable}
	}
	w, e := value.NormalizeTargetDiscoveryWindow(r)
	if e != nil {
		return nil, &targetDiscoveryPreAdmissionRefusal{e}
	}
	return s.Service.begin(ctx, current, invocation, "get_target_discovery", ContextQueryInput{Discovery: r}, func(ctx context.Context, i identity.Identity, recovery artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
		c, e := s.Routes.ResolveTargetDiscoveryRoute(ctx, r.CaptureID, i, recovery)
		if e != nil || !c.RouteValid() || c.CaptureID != r.CaptureID || c.NativeType != artifact.ProcessesArtifact || c.Selection != (value.LineSelection{}) || c.Headers != (value.HTTPHeaderWindow{}) || c.Profile != (value.ProfileSummarySelection{}) || c.Syscalls != (value.SyscallWindow{}) || c.Logs != (value.LogWindow{}) || c.PacketQuery != (value.PacketQueryWindow{}) || c.Comparison != (value.ProfileComparisonWindow{}) || c.Discovery != (value.TargetDiscoveryWindow{}) || c.RawGrantID != "" {
			return value.ContextProjectionCandidate{}, errors.Join(value.ErrUnavailable, e)
		}
		c.Discovery = w
		return c, nil
	})
}

func (d *ContextProjectionDelivery) TargetDiscovery() (value.TargetDiscoveryPage, bool) {
	if d == nil || d.owner == nil || d.pending || d.owner.query.Scope.NativeType != artifact.ProcessesArtifact {
		return value.TargetDiscoveryPage{}, false
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.closed || d.refusal != ContextProjectionNoRefusal || d.discovery == nil {
		return value.TargetDiscoveryPage{}, false
	}
	return *value.CloneTargetDiscoveryPage(d.discovery), true
}
