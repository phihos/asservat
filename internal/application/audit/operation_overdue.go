package audit

import (
	value "asservat.local/asservat/internal/domain/audit"
	"context"
)

// Only an explicitly admitted policy capability can enter this branch.
// No clock, writer proof or new policy is accepted from a cleanup caller.
type OperationOverdueJournal interface {
	BeginOperationPurge(context.Context, string, string) (value.OperationPurgeLease, error)
	RecordOverdueOperationPurge(context.Context, value.OperationPurgeLease) (value.OperationOverduePurge, error)
}
type OperationOverdueAcknowledgements interface {
	AcknowledgeOverdueOperationPurge(context.Context, value.OperationPurgeLease, value.OperationOverduePurge) error
}
type OperationPurgeObjects interface {
	PurgeOperationObjects(context.Context, value.OperationPurgeLease) error
}
type OperationAbsenceVerifier interface {
	VerifyOperationAbsence(context.Context, value.OperationPurgeLease) error
}
type OperationOverdueCleanup struct {
	Journal          OperationOverdueJournal
	Acknowledgements OperationOverdueAcknowledgements
	Finalizer        OperationRetirementFinalizer
	Objects          OperationPurgeObjects
	Verifier         OperationAbsenceVerifier
}

func (s OperationOverdueCleanup) Advance(ctx context.Context, id string) error {
	if ctx == nil || ctx.Err() != nil || s.Journal == nil || s.Acknowledgements == nil || s.Finalizer == nil || s.Objects == nil || s.Verifier == nil {
		return ErrUnavailable
	}
	lease, e := s.Journal.BeginOperationPurge(ctx, id, "overdueOriginal")
	if e != nil {
		return ErrUnavailable
	}
	if e = s.Objects.PurgeOperationObjects(ctx, lease); e != nil {
		return ErrUnavailable
	}
	result, e := s.Journal.RecordOverdueOperationPurge(ctx, lease)
	if e != nil {
		return ErrUnavailable
	}
	if e = s.Verifier.VerifyOperationAbsence(ctx, lease); e != nil {
		return ErrUnavailable
	}
	if e = s.Acknowledgements.AcknowledgeOverdueOperationPurge(ctx, lease, result); e != nil {
		return ErrUnavailable
	}
	return s.Finalizer.RetireOperationAudit(ctx, id)
}
