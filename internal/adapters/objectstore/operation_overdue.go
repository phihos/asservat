package objectstore

import (
	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"context"
)

// Distinct facets allow an overdue-only worker and independent verifier to hold
// no wrap/unwrap/sign/PUT capabilities. Backend IAM still enforces their roles.
type OperationAuditPurger struct {
	store   *Store
	storeID string
}
type OperationAuditAbsenceVerifier struct {
	store   *Store
	storeID string
}

func NewOperationAuditPurger(s *Store, id string) (*OperationAuditPurger, error) {
	if s == nil || !authorization.UUID(id) {
		return nil, app.ErrUnavailable
	}
	return &OperationAuditPurger{s, id}, nil
}
func NewOperationAuditAbsenceVerifier(s *Store, id string) (*OperationAuditAbsenceVerifier, error) {
	if s == nil || !authorization.UUID(id) {
		return nil, app.ErrUnavailable
	}
	return &OperationAuditAbsenceVerifier{s, id}, nil
}
func (s *OperationAuditPurger) PurgeOperationObjects(ctx context.Context, l value.OperationPurgeLease) error {
	if s == nil {
		return app.ErrUnavailable
	}
	return purgeOperationObjects(ctx, s.store, s.storeID, l)
}
func (s *OperationAuditAbsenceVerifier) VerifyOperationAbsence(ctx context.Context, l value.OperationPurgeLease) error {
	if s == nil {
		return app.ErrUnavailable
	}
	return operationAbsence(ctx, s.store, s.storeID, l)
}

var _ app.OperationPurgeObjects = (*OperationAuditPurger)(nil)
var _ app.OperationAbsenceVerifier = (*OperationAuditAbsenceVerifier)(nil)
