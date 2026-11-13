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
		{"protection.entry", "protection.entry"},
		{"protection.result/canceled", "protection.result/canceled"},
		{"protection.result-context/deadline", "protection.result-context/deadline"},
		{"protection.guard-last/source.guard-policy-read", "other"},
		{"protection.probe", "other"},
		{"source.guard-policy-read", "other"},
		{"protection.result/private-token-host", "other"},
		{"protection.result/canceled/private-token-host", "other"},
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
