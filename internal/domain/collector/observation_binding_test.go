package collector

import (
	"crypto/sha256"
	"testing"
)

func TestObservationAccountingRuleMatchesDocumentedCanonicalRule(t *testing.T) {
	const rule = "wire-token-bucket-v1;burst=rate;whole-frame;no-refund"
	if got := ObservationAccountingRule(); got != sha256.Sum256([]byte(rule)) {
		t.Fatalf("accounting rule changed: %x", got)
	}
}
