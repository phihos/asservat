package analysis

import (
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"encoding/json"
	"errors"
)

type packetSummaryPreAdmissionRefusal struct{ cause error }

func (e *packetSummaryPreAdmissionRefusal) Error() string { return e.cause.Error() }
func (e *packetSummaryPreAdmissionRefusal) Unwrap() error { return e.cause }

// PacketSummaryUnavailableBeforeAdmission identifies only a source-authority
// refusal before query admission; final identity/audit checks remain mandatory.
func PacketSummaryUnavailableBeforeAdmission(err error) bool {
	var refusal *packetSummaryPreAdmissionRefusal
	return errors.As(err, &refusal)
}

func (s ContextProjectionService) PacketSummaries() (PacketSummaryReads, bool) {
	return PacketSummaryReads{Service: s, Routes: s.PacketRoutes}, s.PacketRoutes != nil
}

type PacketSummaryReads struct {
	Service ContextProjectionService
	Routes  ContextProjectionRouteReader
}

// ContextPacketProjectionRouteReader is an optional source discriminator from
// the same private case-locator lookup. It grants no read authority; C-03 must
// independently match the exact published source. Legacy routes remain
// metadata-only and cannot enable raw aggregates.
type ContextPacketProjectionRouteReader interface {
	ResolvePacketProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error)
}

func (s PacketSummaryReads) Begin(ctx context.Context, current identities.CurrentIdentity, invocation ContextQueryInvocation, request value.PacketSummaryRequest) (*ContextProjectionDelivery, error) {
	var d *ContextProjectionDelivery
	err := queryStepped("configuration", value.ErrUnavailable)
	if request.Valid() && s.Routes != nil {
		d, err = s.Service.begin(ctx, current, invocation, "get_pcap_summary", ContextQueryInput{Packet: request}, func(ctx context.Context, caller identity.Identity, recovery artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
			var c value.ContextProjectionCandidate
			var err error
			if routes, ok := s.Routes.(ContextPacketProjectionRouteReader); ok {
				c, err = routes.ResolvePacketProjectionRoute(ctx, request.CaseID, request.ArtifactID, caller, recovery)
				if c.NativeType != artifact.PCAPNGArtifact && c.NativeType != artifact.RawPCAPNGArtifact {
					return value.ContextProjectionCandidate{}, errors.Join(value.ErrUnavailable, err)
				}
			} else {
				c, err = s.Routes.ResolveProjectionRoute(ctx, request.CaseID, request.ArtifactID, caller, recovery)
				if c.NativeType != "" {
					return value.ContextProjectionCandidate{}, errors.Join(value.ErrUnavailable, err)
				}
				c.NativeType = artifact.PCAPNGArtifact
			}
			if err != nil || !c.RouteValid() || c.CaseID != request.CaseID || c.ArtifactID != request.ArtifactID || c.Selection != (value.LineSelection{}) || c.Headers != (value.HTTPHeaderWindow{}) || c.Profile != (value.ProfileSummarySelection{}) || c.Syscalls != (value.SyscallWindow{}) || c.Comparison != (value.ProfileComparisonWindow{}) {
				return value.ContextProjectionCandidate{}, errors.Join(value.ErrUnavailable, err)
			}
			return c, nil
		})
	}
	s.Service.Results.refused(ctx, "packet-summary", err)
	return d, err
}
func (d *ContextProjectionDelivery) PacketSummary() (value.PacketSummary, bool) {
	if d == nil || d.owner == nil || d.pending || d.owner.query.Scope.NativeType != artifact.PCAPNGArtifact && d.owner.query.Scope.NativeType != artifact.RawPCAPNGArtifact {
		return value.PacketSummary{}, false
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.closed || d.refusal != ContextProjectionNoRefusal || d.packetSummary == nil {
		return value.PacketSummary{}, false
	}
	return value.ClonePacketSummary(*d.packetSummary), true
}
func boundedPacketSummary(s *value.PacketSummary) bool {
	if s == nil || !s.Valid() {
		return false
	}
	b, err := json.Marshal(s)
	return err == nil && len(b) <= value.ContextResultBytes
}
