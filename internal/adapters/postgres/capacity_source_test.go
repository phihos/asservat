package postgres

import (
	"strings"
	"testing"
	"time"
)

func TestCapacitySourceAcknowledgementRejectsAmbiguousFields(t *testing.T) {
	raw := `{"Accepted":true,"Revision":2,"ObservedAt":"2026-10-12T10:00:00Z","FreshUntil":"2026-10-12T10:00:05+00:00"}`
	if a, e := decodeCapacitySourceAcknowledgement([]byte(raw)); e != nil || a.Revision != 2 || !a.Accepted {
		t.Fatalf("valid actual SQL timestamp shape: %v", e)
	}
	if a, e := decodeCapacitySourceAcknowledgement([]byte(strings.Replace(raw, `"Accepted":true`, `"Accepted":false`, 1))); e != nil || a.Accepted || a.Revision != 2 {
		t.Fatal("negative receipt must remain a decodable committed result, never acceptance")
	}
	for _, bad := range []string{
		strings.Replace(raw, `"Accepted":true,`, ``, 1),
		strings.Replace(raw, `"Accepted":true`, `"Accepted":null`, 1),
		strings.Replace(raw, `"Accepted":true`, `"accepted":true`, 1),
		strings.Replace(raw, `"Revision":2`, `"revision":2`, 1),
		strings.Replace(raw, `"Revision":2`, `"Revision":2,"Revision":2`, 1),
		strings.Replace(raw, `"Revision":2`, `"Revision":2,"Unknown":false`, 1),
		strings.Replace(raw, `"FreshUntil":"2026-10-12T10:00:05+00:00"`, `"FreshUntil":null`, 1),
		raw + raw,
	} {
		if _, e := decodeCapacitySourceAcknowledgement([]byte(bad)); e == nil {
			t.Fatal("ambiguous acknowledgement accepted")
		}
	}
}
func TestCapacitySQLPrecisionOnlyNarrowsOriginalInterval(t *testing.T) {
	n := time.Date(2026, 10, 12, 10, 0, 0, 121, time.UTC)
	start, end := capacityObservedMicro(n), n.Add(5*time.Second).Truncate(time.Microsecond)
	if start.Before(n) || end.After(n.Add(5*time.Second)) || end.Sub(start) > 5*time.Second || start.Nanosecond()%1000 != 0 || end.Nanosecond()%1000 != 0 {
		t.Fatal("SQL rounding extended the original proof")
	}
	if !capacityObservedMicro(start).Equal(start) {
		t.Fatal("exact SQL time changed on replay")
	}
}
