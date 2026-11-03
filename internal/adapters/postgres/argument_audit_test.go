package postgres

import (
	"asservat.local/asservat/internal/domain/authorization"
	"testing"
)

func TestArgumentEventCeilingMustMatchAuditedAutomationEnvelope(t *testing.T) {
	a := authorization.AutomationEnvelope{AllowedActions: []string{"syscallTrace"}, MaxLifetimeSeconds: 60, MaxExecutions: 1, MaxBytes: 65536, MaxObservedBytes: 65536, MaxObservedEvents: 10}
	b := a
	b.MaxObservedEvents = 11
	if sameAutomationEnvelope(a, b) {
		t.Fatal("unaudited event authority expansion matched historical audit")
	}
	b.MaxObservedEvents = 0
	if sameAutomationEnvelope(a, b) {
		t.Fatal("removed event authority matched historical audit")
	}
}
