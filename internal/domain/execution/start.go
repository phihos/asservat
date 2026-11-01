// Package execution contains local effect identities and conservative start
// dispositions. These values do not mint authority or prepaid capacity.
package execution

import (
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

var (
	ErrInvalid              = errors.New("invalid local start")
	ErrUnavailable          = errors.New("local start state unavailable")
	ErrPreparationUncertain = errors.New("original execution preparation already owned or spent")
	ErrConflict             = errors.New("local start binding changed")
	ErrExpired              = errors.New("local start authority expired")
	ErrDenied               = errors.New("local start denied")
	// ErrNotStarted marks a refusal known to precede every start effect: only
	// reads ran, or the preparation transaction rolled back before its insert
	// (ADR-212). It is joined with the refusal's own class, never alone.
	ErrNotStarted = errors.New("refused before any start effect")
)

// Binding is frozen only after every required grant and capacity reservation is
// durably held. Delivery work IDs and lease fences deliberately are not effect
// identities. A changed delivery must never create another reservation.
type Binding struct {
	ExecutionClass                                                      artifact.ContextExecutionClass `json:",omitempty"`
	ExecutorPodUID                                                      string                         `json:",omitempty"`
	ExecutorAccountUID                                                  string                         `json:",omitempty"`
	OperationID, CaptureID, ActionID, AttemptID                         string
	ClusterID, IssuerEpoch, PodUID, NodeUID, NodeBootID, CollectorEpoch string
	ScopeDigest, AuthorityDigest, BudgetDigest, AuditDigest             artifact.Digest
	NativeBytes                                                         int64
	NotBefore, NotAfter                                                 time.Time
}

func (b Binding) Valid() bool {
	for _, id := range []string{b.OperationID, b.CaptureID, b.AttemptID, b.ClusterID, b.IssuerEpoch, b.PodUID, b.CollectorEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	if b.ExecutionClass == artifact.ContextAPIExecution {
		// Pod status has exact bytes. A recorder binding carries the admitted
		// output ceiling: finite expectations still require their original 8 MiB
		// registration; typed snapshots may admit a smaller bounded output.
		podStatus := b.ActionID == "pod-status" && b.NativeBytes == artifact.MaxContextBytes
		recording := recorderAction(b.ActionID) && b.NativeBytes > 0 && b.NativeBytes <= artifact.RecordingNativeLimit
		if b.NodeUID != "" || b.NodeBootID != "" || !authorization.UUID(b.ExecutorPodUID) || !authorization.UUID(b.ExecutorAccountUID) || !podStatus && !recording || b.NotAfter.After(b.NotBefore.Add(5*time.Second)) {
			return false
		}
	} else if b.ExecutionClass != artifact.ContextNodeExecution || !authorization.UUID(b.NodeUID) || !authorization.UUID(b.NodeBootID) || b.ExecutorPodUID != "" || b.ExecutorAccountUID != "" {
		return false
	}
	return identity.Text(b.ActionID, 63) && b.ScopeDigest != (artifact.Digest{}) && b.AuthorityDigest != (artifact.Digest{}) && b.BudgetDigest != (artifact.Digest{}) && b.AuditDigest != (artifact.Digest{}) && b.NativeBytes > 0 && b.NativeBytes <= 1<<40 && canonicalTime(b.NotBefore) && canonicalTime(b.NotAfter) && b.NotAfter.After(b.NotBefore) && !b.NotAfter.After(b.NotBefore.Add(time.Minute))
}

// recorderAction is the generated action ID of a composed recorder action.
func recorderAction(s string) bool {
	if len(s) != 25 || s[0] != 'a' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func canonicalTime(t time.Time) bool {
	return t.Year() >= 2020 && t.Year() <= 9999 && t.Equal(t.Truncate(time.Microsecond)) && t.Location() == time.UTC
}

// Request comes from the authority/reference resolver, never directly from a
// node JSON body. ObjectUID is the original reservation UID; object replacement
// cannot reset consumed spend. CheckedAt/ValidUntil retain the original current
// authority check, and are checked again after blocking API work.
type Request struct {
	Binding               Binding
	ObjectUID             string
	CheckedAt, ValidUntil time.Time
}

func (r Request) Validate(now time.Time) error {
	if !r.Binding.Valid() || !authorization.UUID(r.ObjectUID) {
		return ErrInvalid
	}
	if !identity.Fresh(r.CheckedAt, r.ValidUntil, now, 5*time.Second) || now.Before(r.Binding.NotBefore) || !now.Before(r.Binding.NotAfter) || r.ValidUntil.After(r.Binding.NotAfter) {
		return ErrExpired
	}
	return nil
}

type Phase string

const (
	Ready          Phase = "Ready"
	StartCommitted Phase = "StartCommitted"
)

type Disposition struct {
	ObjectUID, ResourceVersion string
	Phase                      Phase
	CommittedAt                time.Time
	// MayStart is true only for a caller that receives the successful CAS result
	// while its original authority is still valid. Lookup/retry never sets it.
	MayStart   bool
	ValidUntil time.Time
}
