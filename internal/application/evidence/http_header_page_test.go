package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type pagerFixture struct {
	seen []byte
	err  error
}

func (p *pagerFixture) HTTPHeaderPage(native []byte, r *artifact.Recording, s query.HTTPHeaderSelection) (query.HTTPHeaderPage, error) {
	p.seen = native // retained to observe that the worker cleared it
	if p.err != nil {
		return query.HTTPHeaderPage{}, p.err
	}
	if r == nil || r.Profile != "httpHeaders" || !bytes.HasPrefix(native, []byte(`{"format":"http-response-headers/v1"`)) {
		return query.HTTPHeaderPage{}, errors.New("tampered projection")
	}
	page := query.HTTPHeaderPage{ProjectionDigest: sha256.Sum256(native), Start: s.Start, Total: 1, CoverageGaps: []string{}}
	page.Records = []query.HTTPHeaderRecord{{Timestamp: time.Unix(1, 0).UTC(), Method: "GET", Status: 200, Headers: []query.HTTPHeaderField{{Name: "content-type", Value: "text/plain"}}}}
	return page, nil
}

type closingSource struct {
	framedSourceFixture
	closed bool
}

func (s *closingSource) Close() { s.closed = true }

// httpHeaderPageFixture is a published httpHeaders extract, its pinned
// copies, an opened one-frame source and the matching extract scope.
func httpHeaderPageFixture(t *testing.T) (NativeContextSource, query.ContextProjectionScope, []byte, *framedReadFixture) {
	t.Helper()
	_, _, source, o := nativeResultFixture(t)
	e := &source.Expectation
	now := e.TriggeredAt
	e.ExecutionClass = artifact.ContextNodeExecution
	e.NativeType, e.DataClass = artifact.HTTPHeadersArtifact, "extract"
	e.NodeUID, e.NodeBootID = "synthetic-node-uid", o.Reference.InstallationID
	e.ActionID = "a0123456789abcdef01234567"
	e.Registration.NativeLimit = artifact.RecordingNativeLimit
	e.TriggeredAt = now.Add(-20 * time.Second)
	e.Recording = &artifact.Recording{Kind: "packetCapture", Profile: "httpHeaders", Composition: []byte("{}"), DurationMillis: 10_000, MaxBytes: artifact.RecordingNativeLimit, Snaplen: artifact.MaxRawSnaplen, RequireApproval: true,
		Filter: &artifact.RecordingFilter{Expression: "tcp port 8080", Program: []artifact.FilterInstruction{{Code: 6, K: 65535}}},
		HTTP:   &artifact.RecordingHTTP{MaxFlows: artifact.MaxHTTPFlows, MaxHeaderBytes: artifact.MaxHTTPHeaderBytes, MaxFlowBytes: artifact.MaxHTTPFlowBytes, MaxTotalBytes: artifact.MaxHTTPTotalBytes, IdleMillis: artifact.MaxHTTPIdleMillis}}
	if !source.Valid(o.SourceVersion) {
		t.Fatal("synthetic httpHeaders source invalid", e.Validate())
	}
	l := e.Registration.Location
	scope := query.ContextProjectionScope{RootID: l.ClusterID, CaseID: e.CaseID, ArtifactID: l.ArtifactID, CaptureID: e.CaptureUID, ClusterID: l.ClusterID,
		NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Version: o.SourceVersion, SourceFormat: artifact.HTTPHeadersFormat,
		DisplayVersion: query.HTTPHeadersDisplayVersion, NativeType: artifact.HTTPHeadersArtifact, Headers: query.HTTPHeaderWindow{Limit: 100},
		Principal: identity.Principal{Issuer: "https://issuer.invalid", Subject: "s", ClientID: "c", Kind: identity.Human}}
	if !scope.Valid() {
		t.Fatal("synthetic extract scope invalid")
	}
	body := append([]byte(`{"format":"http-response-headers/v1"`), bytes.Repeat([]byte(" "), int(artifact.DeliveryBytes)+100)...)
	body = append(body, '}')
	framed := &framedReadFixture{body: body, m: expectedNativeMetadata(source, int64(len(body)), sha256.Sum256(body))}
	return source, scope, body, framed
}

func TestReadHTTPHeaderPageReturnsOnlyThePageAndClearsPlaintext(t *testing.T) {
	source, scope, body, framed := httpHeaderPageFixture(t)
	opened := &closingSource{framedSourceFixture: framedSourceFixture{f: framed, next: -1}}
	pager := &pagerFixture{}
	page, err := ReadHTTPHeaderPage(t.Context(), opened, source, scope, pager)
	if err != nil || len(page.Records) != 1 || page.ProjectionDigest != sha256.Sum256(body) {
		t.Fatalf("page: %v %+v", err, page)
	}
	if !opened.closed {
		t.Fatal("opened artifact not closed")
	}
	if len(pager.seen) != len(body) || !bytes.Equal(pager.seen, make([]byte, len(body))) {
		t.Fatal("native plaintext not cleared")
	}
}

func TestReadHTTPHeaderPageRefusesOtherSourcesAndTampering(t *testing.T) {
	for _, name := range []string{"pod-status-scope", "wrong-type", "raw-class", "tampered", "digest-mismatch", "format", "oversized", "short-read", "invalid-cursor"} {
		t.Run(name, func(t *testing.T) {
			source, scope, body, framed := httpHeaderPageFixture(t)
			pager := &pagerFixture{}
			switch name {
			case "pod-status-scope":
				scope.NativeType, scope.SourceFormat, scope.DisplayVersion = "", artifact.ContextFormat, query.ContextDisplayVersion
				scope.SourceProjectionDigest, scope.Headers, scope.Selection = query.ContextSourceProjectionDigest(), query.HTTPHeaderWindow{}, query.LineSelection{LineStart: 1, MaxLines: 1}
			case "wrong-type":
				source.Expectation.NativeType = artifact.PCAPNGArtifact
			case "raw-class":
				source.Expectation.DataClass = "raw"
			case "tampered":
				framed.body = append([]byte(`{"format":"other"`), body[17:]...)
				framed.m.SHA256 = sha256.Sum256(framed.body)
			case "digest-mismatch":
				framed.m.SHA256 = artifact.Digest{1}
			case "format":
				framed.m.Format = artifact.PCAPNGFormat
			case "oversized":
				framed.m.Size = source.Expectation.Recording.MaxBytes + 1
			case "short-read":
				framed.body = body[:len(body)-1]
			case "invalid-cursor":
				pager.err = query.ErrInvalidCursor
			}
			opened := &closingSource{framedSourceFixture: framedSourceFixture{f: framed, next: -1}}
			page, err := ReadHTTPHeaderPage(context.Background(), opened, source, scope, pager)
			if err == nil || page.Records != nil {
				t.Fatalf("%s accepted", name)
			}
			if name == "invalid-cursor" && !errors.Is(err, query.ErrInvalidCursor) {
				t.Fatal("invalid cursor collapsed")
			}
			if !opened.closed {
				t.Fatal("refused artifact not closed")
			}
		})
	}
}
