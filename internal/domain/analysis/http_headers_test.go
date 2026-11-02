package analysis

import (
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

const (
	headerCase     = "00000000-0000-4000-8000-000000000080"
	headerArtifact = "00000000-0000-4000-8000-000000000081"
)

func TestHTTPHeaderSelectionNormalization(t *testing.T) {
	d := artifact.Digest{0xab, 0xcd}
	s, err := NormalizeHTTPHeaderSelection(headerCase, headerArtifact, "", 0)
	if err != nil || s.Start != 0 || s.Limit != HTTPHeaderPageRecords || !s.Matches(d) {
		t.Fatal(s, err)
	}
	cursor := HTTPHeaderCursor(250, d)
	if cursor != "250:abcd"+strings.Repeat("0", 28) {
		t.Fatal(cursor)
	}
	s, err = NormalizeHTTPHeaderSelection(headerCase, headerArtifact, cursor, 7)
	if err != nil || s.Start != 250 || s.Limit != 7 || !s.Matches(d) || s.Matches(artifact.Digest{1}) {
		t.Fatal(s, err)
	}
	for _, c := range []string{"x", "0:" + strings.Repeat("0", 32), "007:" + strings.Repeat("0", 32), "7:" + strings.Repeat("A", 32), "7:" + strings.Repeat("0", 31),
		"-1:" + strings.Repeat("0", 32), "99999999:" + strings.Repeat("0", 32), "32760:" + strings.Repeat("0", 32), "7"} {
		if _, err := NormalizeHTTPHeaderSelection(headerCase, headerArtifact, c, 0); !errors.Is(err, ErrInvalidCursor) {
			t.Fatal(c, err)
		}
	}
	for _, limit := range []int{-1, 101} {
		if _, err := NormalizeHTTPHeaderSelection(headerCase, headerArtifact, "", limit); !errors.Is(err, ErrInvalid) {
			t.Fatal(limit, err)
		}
	}
	if _, err := NormalizeHTTPHeaderSelection("case", headerArtifact, cursor, 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("case id", err)
	}
}

func TestHTTPHeaderPageRequiresTheExactSelection(t *testing.T) {
	d := artifact.Digest{7}
	s, _ := NormalizeHTTPHeaderSelection(headerCase, headerArtifact, "", 2)
	at := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	ok := HTTPHeaderRecord{Timestamp: at, Method: "GET", Status: 200, Headers: []HTTPHeaderField{{"content-type", "text/plain"}}}
	page := HTTPHeaderPage{ProjectionDigest: d, Total: 3, Records: []HTTPHeaderRecord{ok, ok}, CoverageGaps: []string{}}
	if !page.Valid(s) || page.Next(2) != HTTPHeaderCursor(2, d) || page.Next(0) != "" {
		t.Fatal("valid page")
	}
	partial := HTTPHeaderRecord{Timestamp: at, Method: "POST", Partial: true}
	for name, m := range map[string]func(*HTTPHeaderPage){
		"short page":       func(p *HTTPHeaderPage) { p.Records = p.Records[:1] },
		"credential":       func(p *HTTPHeaderPage) { p.Records[0].Headers = []HTTPHeaderField{{"cookie", "a=b"}} },
		"status missing":   func(p *HTTPHeaderPage) { p.Records[0].Status = 0 },
		"method":           func(p *HTTPHeaderPage) { p.Records[0].Method = "BREW" },
		"order":            func(p *HTTPHeaderPage) { p.Records[1].Timestamp = at.Add(-time.Second) },
		"start":            func(p *HTTPHeaderPage) { p.Start = 1 },
		"no digest":        func(p *HTTPHeaderPage) { p.ProjectionDigest = artifact.Digest{} },
		"gap text":         func(p *HTTPHeaderPage) { p.CoverageGaps = []string{strings.Repeat("g", 129)} },
		"dropped overflow": func(p *HTTPHeaderPage) { p.DroppedFlows = HTTPHeaderMaxCount + 1 },
	} {
		c := page
		c.Records = []HTTPHeaderRecord{ok, ok}
		c.Records[1].Headers = nil
		m(&c)
		if c.Valid(s) {
			t.Fatal(name)
		}
	}
	page.Records[1] = partial
	if !page.Valid(s) {
		t.Fatal("partial record")
	}
}
