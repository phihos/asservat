package identity

import (
	"testing"
	"time"
)

func TestPolicyGrantPeriodsFiniteAndCoherent(t *testing.T) {
	good := PolicyGrantApproval{DefaultAge: 7 * 24 * time.Hour, MaxAge: 30 * 24 * time.Hour, RenewalNotice: 24 * time.Hour}
	if !good.Valid() {
		t.Fatal("accepted defaults")
	}
	for _, change := range []func(*PolicyGrantApproval){func(p *PolicyGrantApproval) { p.MaxAge = 366 * 24 * time.Hour }, func(p *PolicyGrantApproval) { p.DefaultAge = p.MaxAge + time.Second }, func(p *PolicyGrantApproval) { p.RenewalNotice = p.MaxAge + time.Second }, func(p *PolicyGrantApproval) { p.DefaultAge = 0 }, func(p *PolicyGrantApproval) { p.MaxAge += time.Nanosecond }} {
		bad := good
		change(&bad)
		if bad.Valid() {
			t.Fatal("unbounded/incoherent approval setting", bad)
		}
	}
}
