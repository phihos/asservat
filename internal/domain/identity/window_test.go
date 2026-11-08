package identity

import (
	"io/fs"
	"math/rand/v2"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/migrations"
)

func TestWindowStartsAtItsCheckAndOnlyNarrows(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	w := Check(now, Recheck)
	if !w.From().Equal(now) || !w.Until().Equal(now.Add(30*time.Second)) || w.Kind() != Recheck || !w.Valid(now) || w.Valid(now.Add(30*time.Second)) || w.Valid(now.Add(-time.Nanosecond)) {
		t.Fatal("check window", w)
	}
	if n := w.Narrow(now.Add(time.Hour)); n != w {
		t.Fatal("narrow extended", n)
	}
	if n := w.Narrow(now.Add(time.Second), now.Add(2*time.Second)); !n.Until().Equal(now.Add(time.Second)) || !n.From().Equal(now) {
		t.Fatal("narrow", n)
	}
	if w.Narrow(time.Time{}).Valid(now) || (Window{}).Valid(now) || Check(time.Time{}, Recheck).Valid(now) || Check(now, 0).Valid(now) || Check(now, WindowKind(9)).Valid(now) {
		t.Fatal("zero window valid")
	}
	if Check(now, PolicyObservation).Until() != now.Add(60*time.Second) || Check(now, SQLFenced).Until() != now.Add(5*time.Second) {
		t.Fatal("kind intervals")
	}
}

// The regional receiver once returned its inner local check's later start plus
// the interval, which its own consumer refused (PR #174). However inner checks
// nest, an outer window never exceeds its own start plus its interval.
func TestWindowNestedLaterChecksNeverExceedTheOuterInterval(t *testing.T) {
	r := rand.New(rand.NewPCG(311, 174))
	base := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	kinds := []WindowKind{Recheck, PolicyObservation, SQLFenced}
	var nest func(start time.Time, kind WindowKind, depth int) Window
	nest = func(start time.Time, kind WindowKind, depth int) Window {
		w := Check(start, kind)
		for range r.IntN(4) {
			at := start.Add(time.Duration(r.Int64N(int64(40 * time.Second))))
			if depth < 4 && r.IntN(2) == 0 {
				w = w.Narrow(nest(at, kinds[r.IntN(len(kinds))], depth+1).Until())
			} else {
				w = w.Narrow(at.Add(time.Duration(r.Int64N(int64(time.Minute)))))
			}
		}
		return w
	}
	for range 20000 {
		start := base.Add(time.Duration(r.Int64N(int64(time.Hour))))
		kind := kinds[r.IntN(len(kinds))]
		w := nest(start, kind, 0)
		if !w.From().Equal(start) || w.Kind() != kind || w.Until().After(start.Add(kind.Interval())) {
			t.Fatal("window exceeded its own check", start, kind, w)
		}
		if now := start.Add(time.Duration(r.Int64N(int64(2 * time.Minute)))); w.Valid(now) && !now.Before(start.Add(kind.Interval())) {
			t.Fatal("valid past its interval", w, now)
		}
	}
}

// Each Go interval equals the SQL fence that persists or checks it, so a
// Go-only change fails here instead of on an installed run. Only the latest Up
// definition of each fence counts.
func TestWindowIntervalsMatchSQLFences(t *testing.T) {
	recovery := `'Recovery'->>'FreshUntil'\)::timestamptz<=\(\w+->'Recovery'->>'ObservedAt'\)::timestamptz\+interval '(\d+) seconds?'`
	for _, fence := range []struct {
		name, definition, pattern string
		interval                  time.Duration
	}{
		{"context_execution_check", `ADD CONSTRAINT context_execution_check CHECK\(`, `not_after<=not_before\+interval '(\d+) seconds?'`, AuthorityRecheckInterval},
		{"capacity_recovery_current", `CREATE (?:OR REPLACE )?FUNCTION (?:public\.)?capacity_recovery_current\(`, `\(a->>'FreshUntil'\)::timestamptz<=\(a->>'ObservedAt'\)::timestamptz\+interval '(\d+) seconds?'`, SQLFencedInterval},
		{"lock_connector_process_current", `CREATE (?:OR REPLACE )?FUNCTION (?:public\.)?lock_connector_process_current\(`, recovery, SQLFencedInterval},
		{"lock_connector_backing_current", `CREATE (?:OR REPLACE )?FUNCTION (?:public\.)?lock_connector_backing_current\(`, recovery, SQLFencedInterval},
	} {
		body := latestSQLDefinition(t, regexp.MustCompile(fence.definition))
		matches := regexp.MustCompile(fence.pattern).FindAllStringSubmatch(body, -1)
		if len(matches) == 0 {
			t.Fatalf("%s: interval pattern not found in its latest definition", fence.name)
		}
		for _, m := range matches {
			if seconds, _ := strconv.Atoi(m[1]); time.Duration(seconds)*time.Second != fence.interval {
				t.Fatalf("%s: SQL fence %ss, Go %s", fence.name, m[1], fence.interval)
			}
		}
	}
}

// latestSQLDefinition returns the statement of the last migration whose Up
// section defines the object: up to the closing $$; of a function, otherwise
// to the statement's semicolon.
func latestSQLDefinition(t *testing.T, header *regexp.Regexp) string {
	t.Helper()
	names, err := fs.Glob(migrations.Files(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(names)
	var body string
	for _, name := range names {
		raw, err := fs.ReadFile(migrations.Files(), name)
		if err != nil {
			t.Fatal(err)
		}
		up, _, _ := strings.Cut(string(raw), "-- +goose Down")
		for _, at := range header.FindAllStringIndex(up, -1) {
			rest := up[at[0]:]
			end := ";"
			if strings.Contains(rest[:at[1]-at[0]], "FUNCTION") {
				end = "$$;"
			}
			if i := strings.Index(rest, end); i >= 0 {
				rest = rest[:i]
			}
			body = rest
		}
	}
	if body == "" {
		t.Fatalf("no definition matches %s", header)
	}
	return body
}
