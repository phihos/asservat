package fleet

import (
	"context"
	"strings"
	"testing"
)

func TestOwnerProtectionDiagnosticsRejectUnknownAndCompoundProviderText(t *testing.T) {
	for _, tc := range []struct {
		step string
		want string
	}{
		{"protection.guard-last/source.guard-policy-read", "protection.guard-last/source.guard-policy-read"},
		{"protection.namespace-last", "protection.namespace-last"},
		{"protection.namespace-last/canceled", "protection.namespace-last/canceled"},
		{"protection.original-interval/deadline", "protection.original-interval/deadline"},
		{"protection.probe/source.probe-conflicts-exhausted", "protection.probe/source.probe-conflicts-exhausted"},
		{"source.guard-policy-read", "source.guard-policy-read"},
		{"protection.guard-last/private-token-host", "other"},
		{"protection.guard-last/source.guard-policy-read: private-token-host", "other"},
		{"protection.guard-last/source.guard-policy-read/private-token-host", "other"},
		{"protection.namespace-last/source.guard-policy-read", "other"},
		{"protection.namespace-last/canceled/private-token-host", "other"},
		{"private-token-host", "other"},
		{strings.Repeat("source.guard-policy-read", 1000), "other"},
	} {
		var reports []string
		ctx := WithRefusalSteps(context.Background(), func(step string) { reports = append(reports, step) })
		protectionReadRefusal(ctx, "protection-after", ownerProtectionDiagnosticError{step: tc.step})
		want := "protection-after/read/" + tc.want + "@none"
		if len(reports) != 1 || reports[0] != want {
			t.Fatalf("unsafe fixed-code classification: %v, want %q", reports, want)
		}
	}
}
