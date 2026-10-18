package analysis

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func displayProjection() value.PodStatusProjection {
	return value.PodStatusProjection{Format: artifact.ContextFormat, NamespaceUID: "namespace", PodUID: "pod", ResourceVersion: "123",
		ObservedAt: time.Date(2026, 10, 18, 12, 34, 56, 120000000, time.FixedZone("source", 2*60*60)), Phase: "Running",
		Ready: "Unknown", Initialized: "True", Scheduled: "False", RuntimeInstances: 3, Running: 1, Waiting: 1, Terminated: 1, Restarts: 137438953408}
}

func TestContextDisplayExactCanonicalLines(t *testing.T) {
	out, err := FormatContextExcerpt(displayProjection(), value.LineSelection{LineStart: 1, MaxLines: 200})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`format: "asservat-pod-status/v1"`, `namespaceUID: "namespace"`, `podUID: "pod"`,
		`resourceVersion: "123"`, `observedAt: "2026-10-18T10:34:56.12Z"`,
		`phase: "Running"`, `ready: "Unknown"`, `initialized: "True"`, `scheduled: "False"`,
		`runtimeInstances: 3`, `running: 1`, `waiting: 1`, `terminated: 1`, `restarts: 137438953408`,
	}
	if out.LogicalPath != "pod-status.txt" || out.LineStart != 1 || !reflect.DeepEqual(out.Lines, want) {
		t.Fatalf("wrong fixed projection: %#v", out)
	}
}

func TestContextDisplaySelectionsEscapingAndBounds(t *testing.T) {
	p := displayProjection()
	p.ResourceVersion = "\"\n\\<script>&😀"
	for _, tc := range []struct {
		selection value.LineSelection
		count     int
		first     string
	}{
		{value.LineSelection{LineStart: 1, MaxLines: 200}, 14, `format: "asservat-pod-status/v1"`},
		{value.LineSelection{LineStart: 4, MaxLines: 1}, 1, `resourceVersion: "\"\n\\\u003cscript\u003e\u0026😀"`},
		{value.LineSelection{LineStart: 13, MaxLines: 200}, 2, `terminated: 1`},
		{value.LineSelection{LineStart: 14, MaxLines: 1}, 1, `restarts: 137438953408`},
		{value.LineSelection{LineStart: 15, MaxLines: 1}, 0, ""},
		{value.LineSelection{LineStart: 1_000_000_000, MaxLines: 200}, 0, ""},
	} {
		out, err := FormatContextExcerpt(p, tc.selection)
		if err != nil || out.LineStart != tc.selection.LineStart || len(out.Lines) != tc.count || out.Lines == nil ||
			(tc.count > 0 && out.Lines[0] != tc.first) {
			t.Fatalf("selection %#v: %#v, %v", tc.selection, out, err)
		}
		for _, line := range out.Lines {
			if strings.ContainsAny(line, "\r\n") {
				t.Fatalf("line injection: %q", line)
			}
		}
	}
	for _, s := range []value.LineSelection{{LineStart: 0, MaxLines: 1}, {LineStart: 1, MaxLines: 0}, {LineStart: -1, MaxLines: 1}, {LineStart: 1, MaxLines: 201}, {LineStart: 1_000_000_001, MaxLines: 1}} {
		if _, err := FormatContextExcerpt(p, s); !errors.Is(err, value.ErrInvalid) {
			t.Fatalf("invalid selection accepted: %#v", s)
		}
	}
	// The worst permitted byte-length strings remain bounded after escaping and
	// nesting. No field is silently truncated to fit the result budget.
	p.ResourceVersion = strings.Repeat("\x00", 128)
	p.NamespaceUID, p.PodUID = strings.Repeat("<", 64), strings.Repeat("&", 64)
	out, err := FormatContextExcerpt(p, value.LineSelection{LineStart: 1, MaxLines: 200})
	if err != nil || len(out.Lines) != 14 {
		t.Fatal("valid maximum projection was truncated", err)
	}
	encoded, err := json.Marshal(map[string]any{"query_handle": strings.Repeat("h", 4096), "tool_name": "get_file_excerpt", "result": out})
	if err != nil || len(encoded) > value.ContextResultBytes || bytes.Contains(encoded, []byte(`"lines":null`)) {
		t.Fatal("result wrapper too large or invalid", len(encoded), err)
	}
	p.ResourceVersion += "x"
	if out, err := FormatContextExcerpt(p, value.LineSelection{LineStart: 1, MaxLines: 200}); !errors.Is(err, value.ErrInvalid) || out.Lines != nil {
		t.Fatal("oversized field silently truncated", out, err)
	}
}
