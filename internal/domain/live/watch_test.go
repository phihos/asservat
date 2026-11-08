package live

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticCarriesOnlyFixedClassAndMarkers(t *testing.T) {
	dependency := errors.New("dial tcp postgres:5432: user alice@example.test pod 0f7c secret-token")
	inner := fmt.Errorf("%w: live_batch:83: %v", ErrUnavailable, dependency)
	err := fmt.Errorf("%w: %w: service:442: %v", ErrUnavailable, ErrTransient, inner)
	if got := Diagnostic(err); got != "transient at service:442 live_batch:83" {
		t.Fatalf("diagnostic %q", got)
	}
	if got := Diagnostic(fmt.Errorf("%w: live_watch:not-current", ErrDenied)); got != "denied at live_watch:not-current" {
		t.Fatalf("diagnostic %q", got)
	}
	if got := Diagnostic(dependency); got != "other" {
		t.Fatalf("dependency text leaked: %q", got)
	}
	if got := Diagnostic(nil); got != "other" {
		t.Fatalf("nil diagnostic %q", got)
	}
}

func testRow(now time.Time) Row {
	return Row{ID: "source:1", SourceID: "11111111-1111-4111-8111-111111111111", Sequence: 1, ObservedAt: now.Add(-time.Second), ReceivedAt: now, ExpiresAt: now.Add(29 * time.Second), Projection: Packet, PodUID: "pod", Packet: &PacketFields{Protocol: "TCP", RemoteIP: "192.0.2.2", RemotePort: 8080, Direction: "unknown", WireBytes: 64}}
}
func TestLiveRowsOriginalClockTTLAndUnion(t *testing.T) {
	now := time.Now()
	r := testRow(now)
	if !r.Valid(now) {
		t.Fatal("valid projected row")
	}
	for name, mutate := range map[string]func(*Row){"past TTL": func(v *Row) { v.ExpiresAt = now.Add(30 * time.Second) }, "future receive": func(v *Row) { v.ReceivedAt = now.Add(time.Second) }, "unknown clock": func(v *Row) { v.ClockUncertainty = 5001 }, "mixed fields": func(v *Row) { v.Syscall = &SyscallFields{PID: 1, Name: "read"} }, "raw protocol": func(v *Row) { v.Packet.Protocol = "payload" }} {
		t.Run(name, func(t *testing.T) {
			v := r.Clone()
			mutate(&v)
			if v.Valid(now) {
				t.Fatal("invalid row accepted")
			}
		})
	}
	if r.Valid(r.ExpiresAt) {
		t.Fatal("row expiry is exclusive")
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "Packet") || strings.Contains(string(raw), "Syscall") {
		t.Fatal("private union leaked", string(raw))
	}
	clone := r.Clone()
	clone.Packet.RemoteIP = "203.0.113.1"
	if r.Packet.RemoteIP == clone.Packet.RemoteIP {
		t.Fatal("retained shared fields")
	}
}
func TestLiveFilterClosedFieldsAndUnknownNeverPredicate(t *testing.T) {
	r := testRow(time.Now())
	predicate := func(field, op, value string) Filter {
		return Filter{All: []Predicate{{field, op, json.RawMessage(value)}}}
	}
	if !predicate("port", "eq", "8080").Match(r) || predicate("port", "eq", "0").Match(r) {
		t.Fatal("numeric filtering")
	}
	if predicate("peer_uid", "neq", `"hidden"`).Match(r) {
		t.Fatal("unknown field is predicate oracle")
	}
	for _, f := range []Filter{predicate("arguments", "eq", `"secret"`), predicate("syscall", "eq", `"read"`), predicate("remote_ip", "eq", `"host.example"`), predicate("port", "eq", "65536"), predicate("port", "eq", "null"), predicate("pid", "eq", "1.2"), predicate("protocol", "gte", `"TCP"`)} {
		if f.Valid(Packet) {
			t.Fatal("invalid filter accepted", f)
		}
	}
}

func TestLiveNullFilterWhitespaceAndZeroSequenceAreNotKnownValues(t *testing.T) {
	for _, field := range []string{"port", "pid", "status", "error"} {
		projection := Packet
		if field == "status" {
			projection = HTTP
		}
		if field == "error" {
			projection = Syscall
		}
		f := Filter{All: []Predicate{{Field: field, Op: "eq", Value: json.RawMessage(" \n null \t")}}}
		if f.Valid(projection) {
			t.Fatal("null became numeric/boolean zero", field)
		}
	}
	row := testRow(time.Now())
	row.Sequence = 0
	if row.Valid(time.Now()) {
		t.Fatal("zero sequence accepted")
	}
}
