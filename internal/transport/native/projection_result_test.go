package native

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func resultScope() query.ContextProjectionScope {
	id := "00000000-0000-4000-8000-000000000001"
	return query.ContextProjectionScope{RootID: id, CaseID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "w", PodUID: "p",
		Version: artifact.Digest{1}, SourceProjectionDigest: query.ContextSourceProjectionDigest(), SourceFormat: artifact.ContextFormat, DisplayVersion: query.ContextDisplayVersion,
		Selection: query.LineSelection{LineStart: 1, MaxLines: 200}, Principal: identity.Principal{Issuer: "https://issuer.invalid", Subject: "s", ClientID: "c", Kind: identity.Human}}
}

func headerScope(w query.HTTPHeaderWindow) query.ContextProjectionScope {
	s := resultScope()
	s.NativeType, s.SourceFormat, s.DisplayVersion, s.SourceProjectionDigest = artifact.HTTPHeadersArtifact, artifact.HTTPHeadersFormat, query.HTTPHeadersDisplayVersion, artifact.Digest{}
	s.Selection, s.Headers = query.LineSelection{}, w
	return s
}

func wirePage(n int, value string) query.HTTPHeaderPage {
	at := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	p := query.HTTPHeaderPage{ProjectionDigest: artifact.Digest{7}, Total: 500, DroppedFlows: 1, CoverageGaps: []string{"gap"}}
	for i := range n {
		p.Records = append(p.Records, query.HTTPHeaderRecord{Timestamp: at.Add(time.Duration(i)), Method: "GET", Status: 200,
			Headers: []query.HTTPHeaderField{{Name: "content-type", Value: value}, {Name: "content-length", Value: "12"}}})
	}
	return p
}

// Pod status keeps its historical payload byte for byte: the bare DTO.
func TestProjectionPayloadPodStatusUnchanged(t *testing.T) {
	s := resultScope()
	p := query.PodStatusProjection{Format: artifact.ContextFormat, NamespaceUID: "ns", PodUID: "p", ResourceVersion: "1", ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Phase: "Running", Ready: "True", Initialized: "True", Scheduled: "True", RuntimeInstances: 1, Running: 1}
	b, err := encodeProjectionResult(query.ProjectionResult{PodStatus: p}, s)
	legacy, _ := json.Marshal(p)
	if err != nil || !bytes.Equal(b, legacy) {
		t.Fatalf("pod-status payload changed: %s", b)
	}
	back, err := decodeProjectionResult(b, s)
	if err != nil || back.PodStatus != p {
		t.Fatal("pod-status payload does not decode", err)
	}
	if _, err := decodeProjectionResult(b, headerScope(query.HTTPHeaderWindow{Limit: 10})); err == nil {
		t.Fatal("extract scope accepted a pod-status payload")
	}
}

// A page sends the longest record prefix within its own bound; the decoded
// page is that prefix and its continuation starts at the first omitted record.
func TestProjectionPayloadPagePrefixWithinBound(t *testing.T) {
	s := headerScope(query.HTTPHeaderWindow{Limit: 100})
	full := wirePage(100, "text/"+strings.Repeat("x", 900))
	b, err := encodeProjectionResult(query.ProjectionResult{Headers: full}, s)
	if err != nil || len(b) > query.HTTPHeaderPageWireBytes {
		t.Fatal("page exceeds its wire bound", err, len(b))
	}
	r, err := decodeProjectionResult(b, s)
	n := len(r.Headers.Records)
	if err != nil || n < 1 || n >= 100 || r.Headers.Next(n) != query.HTTPHeaderCursor(n, full.ProjectionDigest) || r.Headers.DroppedFlows != 1 {
		t.Fatal("prefix page not continued at its first omitted record", err, n)
	}
	for i := range n {
		if !r.Headers.Records[i].Timestamp.Equal(full.Records[i].Timestamp) || r.Headers.Records[i].Headers[0] != full.Records[i].Headers[0] {
			t.Fatal("prefix record changed", i)
		}
	}
	// The bounded payload, with its envelope, fits one control frame.
	frame, err := nativeControl(contracts.NativeMetadataFrame, contracts.NativeMetadata{Format: contracts.NativeExchangeFormat, Nonce: strings.Repeat("n", 64), Metadata: b})
	if err != nil || len(frame.Payload) > contracts.NativeControlBytes {
		t.Fatal("page does not fit the control frame", err)
	}
	small := wirePage(3, "text/plain")
	if b, err = encodeProjectionResult(query.ProjectionResult{Headers: small}, s); err != nil {
		t.Fatal(err)
	}
	if r, err = decodeProjectionResult(b, s); err != nil || len(r.Headers.Records) != 3 {
		t.Fatal("whole small page not delivered", err)
	}
}

func TestProjectionPayloadRefusals(t *testing.T) {
	s := headerScope(query.HTTPHeaderWindow{Start: 2, Limit: 5, Binding: strings.Repeat("0", 32)})
	b, err := encodeProjectionResult(query.ProjectionResult{InvalidCursor: true}, s)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := decodeProjectionResult(b, s); err != nil || !r.InvalidCursor || r.Headers.Records != nil {
		t.Fatal("invalid cursor refusal", err)
	}
	for name, raw := range map[string]string{
		"both":          `{"Page":{"ProjectionDigest":[7,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Start":2,"Total":9,"Records":[],"DroppedFlows":0,"IncompleteFlows":0,"CoverageGaps":null},"InvalidCursor":true}`,
		"neither":       `{}`,
		"unknown field": `{"InvalidCursor":true,"Extra":1}`,
		"not canonical": `{ "InvalidCursor":true}`,
		"oversized":     `{"InvalidCursor":true` + strings.Repeat(" ", query.HTTPHeaderPageWireBytes) + `}`,
	} {
		if _, err := decodeProjectionResult([]byte(raw), s); err == nil {
			t.Fatal("accepted", name)
		}
	}
	// A page whose binding does not match the scope's cursor is no result.
	page := wirePage(1, "text/plain")
	page.Start = 2
	if _, err := encodeProjectionResult(query.ProjectionResult{Headers: page}, s); err == nil {
		t.Fatal("encoded a page for another document")
	}
	// A page longer than its selection is never sent.
	over := wirePage(6, "text/plain")
	if _, err := encodeProjectionResult(query.ProjectionResult{Headers: over}, headerScope(query.HTTPHeaderWindow{Limit: 5})); err == nil {
		t.Fatal("encoded more records than selected")
	}
}

// A single valid record whose escaped values exceed the wire bound is an
// explicit TooLarge refusal, not a (retryable) protocol error.
func TestProjectionPayloadOversizedRecordIsTooLarge(t *testing.T) {
	s := headerScope(query.HTTPHeaderWindow{Limit: 100})
	p := wirePage(1, "text/plain")
	p.Records[0].Headers = nil
	for range 32 {
		p.Records[0].Headers = append(p.Records[0].Headers, query.HTTPHeaderField{Name: "content-type", Value: strings.Repeat("<", 1024)})
	}
	if !(query.ProjectionResult{Headers: p}).Valid(s) {
		t.Fatal("fixture record must be valid")
	}
	b, err := encodeProjectionResult(query.ProjectionResult{Headers: p}, s)
	if err != nil {
		t.Fatal("oversized record failed as protocol error", err)
	}
	r, err := decodeProjectionResult(b, s)
	if err != nil || !r.TooLarge || r.InvalidCursor || len(r.Headers.Records) != 0 {
		t.Fatal("oversized record not refused as TooLarge", err, string(b))
	}
}
