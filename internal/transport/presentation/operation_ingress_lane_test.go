package presentation

import (
	"asservat.local/asservat/internal/contracts"
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/audit"
)

// Uses only the pre-existing API, so the original source reproduces the defect.
func TestInvalidResolutionCannotConsumeProtectedAuditPool(t *testing.T) {
	for _, mode := range []string{"schema", "read-scope"} {
		t.Run(mode, func(t *testing.T) {
			s, f, normal := auditedFixture(t)
			resolution := &presentationAuditGate{}
			s.audit["resolution"] = resolution
			raw := []byte(wireRequest)
			if mode == "schema" {
				raw = []byte(`{"idempotency_key":"same-key"}`)
			} else {
				f.i.Scopes = nil
			}
			if _, err := s.Call(context.Background(), f, "resolve_capture_request", raw); err == nil {
				t.Fatal("rejected invocation succeeded")
			}
			if len(resolution.intents) != 0 || len(resolution.outcomes) != 0 || f.resolutions != 0 || f.requests != 0 {
				t.Fatalf("rejection spent protected resolution backing: intents=%d outcomes=%d resolutions=%d", len(resolution.intents), len(resolution.outcomes), f.resolutions)
			}
			if len(normal.intents) != 1 || normal.intents[0].Name != "invalid_operation" || audit.OperationLane(normal.intents[0].Name) != "normal" || normal.intents[0].InputFormat != "invalid-input/v1" || len(normal.outcomes) != 1 || normal.outcomes[0].Effect != "none" {
				t.Fatal("rejection is not a proven normal-lane invocation rejection")
			}
		})
	}
}

func TestAuditedOperationsValidateIdentityBeforeSQLTimestampFloor(t *testing.T) {
	s, f, g := auditedFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond).Add(900 * time.Nanosecond)
	s.config.Now = func() time.Time { return now }
	f.i.VerifiedAt = now
	f.i.ValidUntil = now.Add(5 * time.Second)
	_, err := s.Call(context.Background(), f, "resolve_capture_request", []byte(`{}`))
	if !errors.Is(err, contracts.ErrInvestigationWire) || len(g.intents) != 1 || len(g.outcomes) != 1 {
		t.Fatalf("SQL rounding made current identity appear future: err=%v intents=%d", err, len(g.intents))
	}
}
