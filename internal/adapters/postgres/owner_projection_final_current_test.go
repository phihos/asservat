package postgres

import (
	"context"
)

type ownerProjectionReasonContext struct {
	context.Context
	failure error
	reads   int
}

func (c *ownerProjectionReasonContext) Err() error {
	c.reads++
	return c.failure
}

type ownerProjectionPrivateDiagnosticError struct{}

func (ownerProjectionPrivateDiagnosticError) Error() string {
	panic("raw diagnostic error must not be rendered")
}
func (ownerProjectionPrivateDiagnosticError) Unwrap() error {
	panic("raw diagnostic error must not be unwrapped")
}
