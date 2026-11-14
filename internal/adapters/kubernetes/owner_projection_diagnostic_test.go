package kubernetes

import (
	"context"
	"testing"
)

type ownerProjectionDiagnosticVerification struct {
	*ownerProjectionSQLFixture
	advance func(context.Context, *OwnerProjectionOperation) (OwnerProjectionAdvance, error)
}

func (s ownerProjectionDiagnosticVerification) AdvanceOwnerProjectionOperation(ctx context.Context, op *OwnerProjectionOperation) (OwnerProjectionAdvance, error) {
	return s.advance(ctx, op)
}

type ownerProjectionHostileError struct{}

func (ownerProjectionHostileError) Error() string { panic("private error text must never be rendered") }

func assertProjectionCodesOnly(t *testing.T, d *ownerProjectionDiagnostic) {
	t.Helper()
	for d != nil {
		if d.cause != nil {
			t.Fatal("retained driver value instead of fixed code")
		}
		for n := d.native; n != nil; n = n.detail {
			if n.cause != nil {
				t.Fatal("retained native error cause")
			}
		}
		d = d.inner
	}
}
