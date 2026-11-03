package analysis

import (
	"context"
	"encoding/json"
	"errors"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// The route supplies source type as internal routing observation only. C-03
// independently checks current rights before protected source verification.
type SyscallProjectionRouteReader interface {
	ResolveSyscallProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error)
}
type SyscallReads struct {
	Service ContextProjectionService
	Routes  SyscallProjectionRouteReader
}

func (s ContextProjectionService) SyscallQueries() (SyscallReads, bool) {
	return SyscallReads{Service: s, Routes: s.SyscallRoutes}, s.SyscallRoutes != nil
}
func (s SyscallReads) Begin(ctx context.Context, current identities.CurrentIdentity, invocation ContextQueryInvocation, request value.SyscallQueryRequest) (*ContextProjectionDelivery, error) {
	var d *ContextProjectionDelivery
	err := queryStepped("configuration", value.ErrUnavailable)
	if request.Valid() && s.Routes != nil {
		tool := "get_syscall_summary"
		if request.Selection.View == value.SyscallEventsView {
			tool = "get_syscall_events"
		}
		d, err = s.Service.begin(ctx, current, invocation, tool, ContextQueryInput{Syscalls: request}, func(ctx context.Context, caller identity.Identity, recovery artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
			c, err := s.Routes.ResolveSyscallProjectionRoute(ctx, request.CaseID, request.ArtifactID, caller, recovery)
			if err != nil || !c.RouteValid() || c.CaseID != request.CaseID || c.ArtifactID != request.ArtifactID || c.Selection != (value.LineSelection{}) || c.Headers != (value.HTTPHeaderWindow{}) || c.Profile != (value.ProfileSummarySelection{}) || c.Syscalls != (value.SyscallWindow{}) || c.NativeType != artifact.SyscallRecordsArtifact && c.NativeType != artifact.SyscallArgumentsArtifact {
				return value.ContextProjectionCandidate{}, errors.Join(value.ErrUnavailable, err)
			}
			c.Syscalls = request.Selection
			return c, nil
		})
	}
	s.Service.Results.refused(ctx, "syscall-query", err)
	return d, err
}
func (d *ContextProjectionDelivery) SyscallSummary() (value.SyscallSummaryPage, bool) {
	if d == nil || d.pending {
		return value.SyscallSummaryPage{}, false
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.closed || d.syscallSummary == nil {
		return value.SyscallSummaryPage{}, false
	}
	return value.CloneSyscallSummaryPage(*d.syscallSummary), true
}
func (d *ContextProjectionDelivery) SyscallEvents() (value.SyscallEventPage, bool) {
	if d == nil || d.pending {
		return value.SyscallEventPage{}, false
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.closed || d.syscallEvents == nil {
		return value.SyscallEventPage{}, false
	}
	return value.CloneSyscallEventPage(*d.syscallEvents), true
}

// SyscallSelection returns an owned display selection for encoding a cursor.
// It supplies no read authority and cannot extend the admitted query.
func (d *ContextProjectionDelivery) SyscallSelection() value.SyscallSelection {
	if d == nil || d.owner == nil {
		return value.SyscallSelection{}
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.closed {
		return value.SyscallSelection{}
	}
	s := d.owner.query.Scope
	return s.Syscalls.Selection(s.CaseID, s.ArtifactID)
}
func boundedSyscallResult(result value.ProjectionResult) bool {
	var body []byte
	var err error
	switch {
	case result.SyscallSummary != nil:
		body, err = json.Marshal(result.SyscallSummary)
	case result.SyscallEvents != nil:
		body, err = json.Marshal(result.SyscallEvents)
	default:
		return false
	}
	return err == nil && len(body) <= value.ContextResultBytes
}
