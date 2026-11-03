package collector

import (
	"crypto/sha256"
	"testing"
)

func TestArgumentObservationAccountingRuleSeparateFromPacketBytes(t *testing.T) {
	const rule = "syscall-probe-v1;fixed=256;argument-reserve=256;entry-exit;rate=gcra-ceil-ns;burst=rate;overflow=stop;cas=8;no-refund;effective-rate=min(events,bytes/max-probe)"
	got := ArgumentObservationAccountingRule()
	if got != sha256.Sum256([]byte(rule)) || got == ObservationAccountingRule() {
		t.Fatal("argument pre-read accounting must retain its distinct pinned rule")
	}
}
