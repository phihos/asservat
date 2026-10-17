package fleet

import (
	"testing"
	"time"
)

func TestOwnerCertificateWindowIsStableAndRenewable(t *testing.T) {
	start := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	first, end, err := OwnerCertificateWindow(start)
	if err != nil || !end.Equal(start.Add(20*time.Minute)) {
		t.Fatal("first period", err)
	}
	for _, d := range []time.Duration{time.Second, 18 * time.Minute, 19*time.Minute - time.Nanosecond} {
		epoch, until, err := OwnerCertificateWindow(start.Add(d))
		if err != nil || epoch != first || !until.Equal(end) {
			t.Fatal("retry extended certificate", d)
		}
	}
	for _, d := range []time.Duration{19 * time.Minute, 20 * time.Minute, 38 * time.Minute} {
		epoch, until, err := OwnerCertificateWindow(start.Add(d))
		if err != nil || epoch != first+1 || !until.Equal(start.Add(40*time.Minute)) {
			t.Fatal("renewal boundary", d)
		}
	}
	if _, _, err := OwnerCertificateWindow(start.Add(30 * 24 * time.Hour)); err != nil {
		t.Fatal("long lived owner forced to restart", err)
	}
	if _, _, err := OwnerCertificateWindow(time.Time{}); err == nil {
		t.Fatal("zero time accepted")
	}
}
