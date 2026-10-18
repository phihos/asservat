package objectstore

import (
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

const testNative = `{"format":"asservat-pod-status/v1","namespaceUID":"namespace","podUID":"pod","resourceVersion":"123","observedAt":"2026-10-18T12:34:56.120000000+02:00","phase":"Running","ready":"Unknown","initialized":"True","scheduled":"False","runtimeInstances":3,"running":1,"waiting":1,"terminated":1,"restarts":137438953408}`

func testProjectionScope() analysis.ContextProjectionScope {
	const id = "11111111-1111-4111-8111-111111111111"
	return analysis.ContextProjectionScope{RootID: id, CaseID: id, ArtifactID: id, CaptureID: id, ClusterID: id,
		NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{2},
		SourceProjectionDigest: analysis.ContextSourceProjectionDigest(), SourceFormat: artifact.ContextFormat, DisplayVersion: analysis.ContextDisplayVersion,
		Selection: analysis.LineSelection{LineStart: 1, MaxLines: 200},
		Principal: identity.Principal{Issuer: "https://issuer.example", Subject: "developer", ClientID: "client", Kind: identity.Human}}
}

func TestContextProjectionNativeExactFields(t *testing.T) {
	native := []byte(testNative)
	p, err := ParseContextProjection(native, testProjectionScope())
	if err != nil {
		t.Fatal(err)
	}
	clear(native)
	want := analysis.PodStatusProjection{Format: artifact.ContextFormat, NamespaceUID: "namespace", PodUID: "pod", ResourceVersion: "123",
		ObservedAt: time.Date(2026, 10, 18, 10, 34, 56, 120000000, time.UTC), Phase: "Running", Ready: "Unknown", Initialized: "True",
		Scheduled: "False", RuntimeInstances: 3, Running: 1, Waiting: 1, Terminated: 1, Restarts: 137438953408}
	if p != want {
		t.Fatalf("wrong native projection: %#v", p)
	}
	var reordered map[string]any
	if err := json.Unmarshal([]byte(testNative), &reordered); err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(reordered, "", "  ")
	p2, err := ParseContextProjection(b, testProjectionScope())
	if err != nil || !reflect.DeepEqual(p, p2) {
		t.Fatalf("order-sensitive parser: %#v, %v", p2, err)
	}
	escaped := strings.Replace(testNative, `"123"`, `"\"\n\\<script>&\ud83d\ude00"`, 1)
	p, err = ParseContextProjection([]byte(escaped), testProjectionScope())
	if err != nil || p.ResourceVersion != "\"\n\\<script>&😀" {
		t.Fatal("escaped scalar changed", p.ResourceVersion, err)
	}
	for _, mutate := range []func(*analysis.ContextProjectionScope){
		func(s *analysis.ContextProjectionScope) { s.SourceFormat = "other" },
		func(s *analysis.ContextProjectionScope) { s.SourceProjectionDigest[0] ^= 1 },
		func(s *analysis.ContextProjectionScope) { s.DisplayVersion = "other" },
		func(s *analysis.ContextProjectionScope) { s.Version = artifact.Digest{} },
	} {
		scope := testProjectionScope()
		mutate(&scope)
		if _, err := ParseContextProjection([]byte(testNative), scope); !errors.Is(err, analysis.ErrInvalid) {
			t.Fatal("unsupported source scope accepted", err)
		}
	}
}

func TestContextDisplayRejectsMalformedNative(t *testing.T) {
	for name, native := range map[string]string{
		"empty": "", "array": "[]", "null": "null", "trailing-value": testNative + "{}",
		"truncated":              testNative[:len(testNative)-1],
		"too-large":              testNative + strings.Repeat(" ", artifact.MaxContextBytes),
		"extra-field":            strings.Replace(testNative, `"phase":`, `"environment":"secret","phase":`, 1),
		"duplicate-field":        strings.Replace(testNative, `"phase":`, `"phase":"Failed","phase":`, 1),
		"case-insensitive-field": strings.Replace(testNative, `"podUID"`, `"PodUID"`, 1),
		"wrong-format":           strings.Replace(testNative, "asservat-pod-status/v1", "incident-context/v1", 1),
		"wrong-pod":              strings.Replace(testNative, `"podUID":"pod"`, `"podUID":"other"`, 1),
		"wrong-namespace":        strings.Replace(testNative, `"namespaceUID":"namespace"`, `"namespaceUID":"other"`, 1),
		"unknown-phase":          strings.Replace(testNative, `"Running"`, `"Ready"`, 1),
		"boolean-condition":      strings.Replace(testNative, `"ready":"Unknown"`, `"ready":true`, 1),
		"unknown-condition":      strings.Replace(testNative, `"ready":"Unknown"`, `"ready":"Maybe"`, 1),
		"negative-count":         strings.Replace(testNative, `"running":1`, `"running":-1`, 1),
		"large-count":            strings.Replace(testNative, `"running":1`, `"running":65`, 1),
		"fractional-count":       strings.Replace(testNative, `"running":1`, `"running":1.5`, 1),
		"negative-restarts":      strings.Replace(testNative, "137438953408", "-1", 1),
		"large-restarts":         strings.Replace(testNative, "137438953408", "137438953409", 1),
		"long-resource-version":  strings.Replace(testNative, `"123"`, `"`+strings.Repeat("a", 129)+`"`, 1),
		"empty-resource-version": strings.Replace(testNative, `"123"`, `""`, 1),
		"unpaired-surrogate":     strings.Replace(testNative, `"123"`, `"\ud800"`, 1),
		"low-surrogate":          strings.Replace(testNative, `"123"`, `"\udc00"`, 1),
		"bad-surrogate-pair":     strings.Replace(testNative, `"123"`, `"\ud800\u0041"`, 1),
		"invalid-utf8":           strings.Replace(testNative, "123", string([]byte{0xff}), 1),
		"bad-calendar-date":      strings.Replace(testNative, "2026-10-18", "2026-02-30", 1),
		"single-digit-hour":      strings.Replace(testNative, "T12:", "T2:", 1),
		"comma-fraction":         strings.Replace(testNative, "56.120", "56,120", 1),
		"offset-hour-overflow":   strings.Replace(testNative, "+02:00", "+24:00", 1),
		"offset-minute-overflow": strings.Replace(testNative, "+02:00", "+02:60", 1),
		"precision-loss":         strings.Replace(testNative, ".120000000", ".1200000001", 1),
	} {
		t.Run(name, func(t *testing.T) {
			p, err := ParseContextProjection([]byte(native), testProjectionScope())
			if !errors.Is(err, analysis.ErrInvalid) || p != (analysis.PodStatusProjection{}) {
				t.Fatalf("malformed source accepted: %#v, %v", p, err)
			}
		})
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(testNative), &fields); err != nil {
		t.Fatal(err)
	}
	for name := range fields {
		for _, null := range []bool{false, true} {
			candidate := maps.Clone(fields)
			if null {
				candidate[name] = json.RawMessage("null")
			} else {
				delete(candidate, name)
			}
			b, _ := json.Marshal(candidate)
			if _, err := ParseContextProjection(b, testProjectionScope()); !errors.Is(err, analysis.ErrInvalid) {
				t.Fatalf("missing/null %s accepted: %v", name, err)
			}
		}
	}
}

func TestContextProjectionLiteralUnicodeEscapeText(t *testing.T) {
	for name, raw := range map[string]string{
		"literal-high-surrogate":  `"\\ud800"`,
		"literal-low-surrogate":   `"\\udc00"`,
		"literal-short-escape":    `"\\u12"`,
		"literal-nonhex-escape":   `"\\uzzzz"`,
		"two-literal-backslashes": `"\\\\ud800"`,
		"literal-and-real-pair":   `"\\ud800 \ud83d\ude00"`,
		"escaped-quote":           `"\"\\u12"`,
	} {
		t.Run(name, func(t *testing.T) {
			var want string
			if err := json.Unmarshal([]byte(raw), &want); err != nil {
				t.Fatal("invalid test JSON", err)
			}
			native := strings.Replace(testNative, `"123"`, raw, 1)
			got, err := ParseContextProjection([]byte(native), testProjectionScope())
			if err != nil || got.ResourceVersion != want {
				t.Fatalf("literal escape changed: raw=%s got=%q want=%q error=%v", raw, got.ResourceVersion, want, err)
			}
		})
	}
	for _, raw := range []string{`"\ud800"`, `"\udc00"`, `"\\\ud800"`, `"\\\udc00"`} {
		native := strings.Replace(testNative, `"123"`, raw, 1)
		if _, err := ParseContextProjection([]byte(native), testProjectionScope()); !errors.Is(err, analysis.ErrInvalid) {
			t.Fatalf("unpaired real surrogate accepted: %s", raw)
		}
	}
}
