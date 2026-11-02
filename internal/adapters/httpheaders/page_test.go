package httpheaders

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

const (
	pageCase     = "00000000-0000-4000-8000-000000000060"
	pageArtifact = "00000000-0000-4000-8000-000000000061"
)

// pageProjection is a synthetic projection of n exchanges; every third
// is a partial request without a response.
func pageProjection(t *testing.T, n int) (Projection, []byte) {
	t.Helper()
	l := DefaultLimits()
	pr := Projection{Format: artifact.HTTPHeadersFormat, Protocol: "http1", StartedAt: t0, EndedAt: t0.Add(time.Hour),
		Limits:  LimitsRecord{MaxFlows: l.MaxFlows, MaxHeaderBytes: l.MaxHeaderBytes, MaxFlowBytes: l.MaxFlowBytes, MaxTotalBytes: l.MaxTotalBytes, IdleTimeoutSeconds: int64(l.IdleTimeout / time.Second), Snaplen: Snaplen},
		Records: []Record{}}
	for i := range n {
		r := Record{Timestamp: t0.Add(time.Duration(i) * time.Millisecond), Method: "GET", Status: 200, Headers: []Header{{"content-type", "application/json"}, {"content-length", "64"}}}
		if i%3 == 2 {
			r = Record{Timestamp: r.Timestamp, Method: "POST", Headers: []Header{}, Partial: true}
			pr.Counters.PartialRecords++
		}
		pr.Records = append(pr.Records, r)
	}
	pr.Counters.Records = uint64(n)
	pr.Counters.StoppedTLS, pr.Counters.StoppedGap, pr.Counters.EngineLostFrames = 2, 1, 5
	return pr, encode(t, pr)
}

func selection(t *testing.T, cursor string, limit int) analysis.HTTPHeaderSelection {
	t.Helper()
	s, err := analysis.NormalizeHTTPHeaderSelection(pageCase, pageArtifact, cursor, limit)
	if err != nil {
		t.Fatal(cursor, limit, err)
	}
	return s
}

func TestReadPageWalksTheProjectionWithCursors(t *testing.T) {
	pr, b := pageProjection(t, 250)
	digest := artifact.Digest(sha256.Sum256(b))
	var got []analysis.HTTPHeaderRecord
	cursor := ""
	for pages := 0; ; pages++ {
		p, err := ReadPage(b, DefaultLimits(), int64(len(b)), selection(t, cursor, 0))
		if err != nil {
			t.Fatal(pages, err)
		}
		if p.ProjectionDigest != digest || p.Total != 250 || len(p.Records) > analysis.HTTPHeaderPageRecords {
			t.Fatalf("page %d: %+v", pages, p.Total)
		}
		if p.DroppedFlows != 2 || p.IncompleteFlows != 1 || len(p.CoverageGaps) != 3 || !strings.Contains(p.CoverageGaps[1], "TLS") {
			t.Fatalf("gaps %d %d %q", p.DroppedFlows, p.IncompleteFlows, p.CoverageGaps)
		}
		got = append(got, p.Records...)
		if cursor = p.Next(len(p.Records)); cursor == "" {
			break
		}
	}
	if len(got) != 250 {
		t.Fatalf("walked %d records", len(got))
	}
	for i, r := range got {
		w := pr.Records[i]
		if !r.Timestamp.Equal(w.Timestamp) || r.Method != w.Method || r.Status != w.Status || r.Partial != w.Partial || len(r.Headers) != len(w.Headers) || r.Headers == nil {
			t.Fatalf("record %d: %+v", i, r)
		}
	}
	// A smaller limit pages exactly; an empty projection is one empty page.
	p, err := ReadPage(b, DefaultLimits(), int64(len(b)), selection(t, "", 7))
	if err != nil || len(p.Records) != 7 || p.Next(7) != analysis.HTTPHeaderCursor(7, digest) {
		t.Fatal(err, len(p.Records))
	}
	_, empty := pageProjection(t, 0)
	if p, err := ReadPage(empty, DefaultLimits(), int64(len(empty)), selection(t, "", 0)); err != nil || len(p.Records) != 0 || p.Next(0) != "" {
		t.Fatal(err)
	}
}

func TestReadPageRefusesForeignCursorsAndTamperedDocuments(t *testing.T) {
	pr, b := pageProjection(t, 20)
	digest := artifact.Digest(sha256.Sum256(b))
	other := digest
	other[0] ^= 1
	for name, cursor := range map[string]string{
		"other projection": analysis.HTTPHeaderCursor(5, other),
		"beyond end":       analysis.HTTPHeaderCursor(20, digest),
	} {
		if _, err := ReadPage(b, DefaultLimits(), int64(len(b)), selection(t, cursor, 0)); !errors.Is(err, analysis.ErrInvalidCursor) {
			t.Fatal(name, err)
		}
	}
	tampered := map[string][]byte{
		"credential header": func() []byte {
			c := pr
			c.Records = append([]Record(nil), pr.Records...)
			c.Records[0].Headers = []Header{{"authorization", "Bearer synthetic"}}
			return encode(t, c)
		}(),
		"whitespace":    append([]byte(" "), b...),
		"unknown field": []byte(strings.Replace(string(b), `"protocol":"http1"`, `"protocol":"http1","body":"x"`, 1)),
		"counter":       []byte(strings.Replace(string(b), `"records":20`, `"records":19`, 1)),
		"format":        []byte(strings.Replace(string(b), artifact.HTTPHeadersFormat, "http-response-headers/v2", 1)),
	}
	for name, doc := range tampered {
		if _, err := ReadPage(doc, DefaultLimits(), artifact.HTTPHeadersNativeLimit, selection(t, "", 0)); err == nil {
			t.Fatal(name, "accepted")
		}
	}
	if _, err := ReadPage(b, DefaultLimits(), int64(len(b))-1, selection(t, "", 0)); !errors.Is(err, artifact.ErrLimit) {
		t.Fatal("over the output cap", err)
	}
	if _, err := ReadPage(b, DefaultLimits(), int64(len(b)), analysis.HTTPHeaderSelection{}); err == nil {
		t.Fatal("invalid selection accepted")
	}
}
