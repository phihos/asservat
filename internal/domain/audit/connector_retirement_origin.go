package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorRetirementOrigin is the original independently accepted restrictive
// allowance. It intentionally does not implement a live peer/process or human
// identity. The admission transaction joins its exact canonical digest to the
// retained ticket and acceptance receipts before it can fund any new write.
type ConnectorRetirementOrigin struct {
	Ticket         ConnectorRetirementTicket
	TicketDigest   artifact.Digest
	Cause          string
	RetiringSource *ConnectorRetiringSource `json:",omitempty"`
}

const ConnectorRetirementExplicit = "protectedRetiringSource"
const ConnectorRetirementExpiry = "originalAdmissionEnd"

// ConnectorRetiringSource is a historical audit fact about the independently
// current higher retiring revision. SQL still checks the complete guarded
// configuration and the exact last accepted ticket under the same root lock.
type ConnectorRetiringSource struct {
	Revision       identity.Revision
	CompleteDigest artifact.Digest
}

func (o ConnectorRetirementOrigin) ValidFor(in OperationIntent) bool {
	t := o.Ticket
	if !t.Valid() || o.TicketDigest == (artifact.Digest{}) || in.ID != t.ID || in.RootID != t.RootID || in.AccountVersion != t.AccountVersion || in.PrincipalDigest != t.PrincipalDigest || in.CreatedAt.Before(t.ReservedAt) || !in.CreatedAt.Before(t.ConsumeUntil) || in.RequestUntil.After(t.ConsumeUntil) || in.WriteUntil.After(t.ConsumeUntil) || !in.RetainUntil.Equal(t.RetainUntil) || in.ConnectorReservations != nil {
		return false
	}
	switch o.Cause {
	case ConnectorRetirementExplicit:
		s := o.RetiringSource
		if s == nil || !s.Revision.Valid() || s.Revision.UID != t.Behavior.UID || s.Revision.Generation <= t.Behavior.Generation || s.CompleteDigest == (artifact.Digest{}) {
			return false
		}
	case ConnectorRetirementExpiry:
		if o.RetiringSource != nil || in.CreatedAt.Before(t.AdmissionUntil) {
			return false
		}
	default:
		return false
	}
	// BindOperationLifecycle checks an unbound copy first. Nil is construction
	// shape only; every producer/admission requires the complete binding.
	if in.Lifecycle != nil {
		p := in.Lifecycle.Policy
		q := t.Policy
		if !CompatibleConnectorPolicy(p, q) || p.PolicyID != q.PolicyID || p.PolicyDigest != q.PolicyDigest || p.BackingRevision != q.BackingRevision || !p.ValidUntil.Equal(q.ValidUntil) || !in.Lifecycle.OriginalPurgeAt.Equal(t.OriginalPurgeAt()) {
			return false
		}
	}
	return true
}

func (o ConnectorRetirementOrigin) Clone() ConnectorRetirementOrigin {
	o.Ticket = o.Ticket.Clone()
	if o.RetiringSource != nil {
		copy := *o.RetiringSource
		o.RetiringSource = &copy
	}
	return o
}

func (in OperationIntent) connectorReservationsValid() bool {
	s := in.ConnectorReservations
	acceptance := in.Name == "connector_process_enrollment" || in.Name == "connector_backing_acceptance"
	if s == nil {
		// Historical v1 encodings remain unchanged. A v2 backing acceptance
		// always binds its successor set. Process renewal/restart may instead
		// reuse its exact already active profile ticket; SQL distinguishes it
		// from first profile admission and denies a missing initial reservation.
		return in.Name != "connector_backing_acceptance" || in.Lifecycle == nil || in.Lifecycle.Policy.History == nil || in.Lifecycle.Policy.History.Layout != ConnectorRetirementHistoryLayout
	}
	return acceptance && s.Valid() && in.RetirementOrigin == nil && in.Actor == (identity.Principal{}) && in.Peer == nil && in.Process != nil && in.Process.Valid() && (in.Lifecycle == nil || in.Lifecycle.Policy.History != nil && in.Lifecycle.Policy.History.Layout == ConnectorRetirementHistoryLayout)
}
