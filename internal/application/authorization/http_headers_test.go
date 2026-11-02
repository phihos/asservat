package authorization

import (
	"context"
	"slices"
	"testing"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// newHTTPHeaderFixture turns the pod-status fixture into a published
// httpHeaders extract of one recording frame and returns the extract
// candidate of its first page (ADR-282).
func newHTTPHeaderFixture() (*projectionFixture, ContextProjectionAuthority, analysis.ContextProjectionCandidate) {
	f, s, scope := newProjectionFixture()
	f.record.NativeType, f.record.SourceFormat, f.record.DataClass = artifact.HTTPHeadersArtifact, artifact.HTTPHeadersFormat, "extract"
	f.record.SourceProjectionDigest = artifact.Digest{}
	f.record.Retained.Input.EvidenceType = "packetCapture"
	f.record.Retained.Registration.NativeLimit = artifact.RecordingNativeLimit
	c := scope.Candidate()
	c.Selection, c.NativeType, c.Headers = analysis.LineSelection{}, artifact.HTTPHeadersArtifact, analysis.HTTPHeaderWindow{Limit: analysis.HTTPHeaderPageRecords}
	return f, s, c
}

func TestHTTPHeaderReadAuthorityAdmitsExtractWithReadRights(t *testing.T) {
	f, s, c := newHTTPHeaderFixture()
	out, err := s.ResolveProjectionCurrent(context.Background(), f, c)
	if err != nil || !out.Valid(f.now) {
		t.Fatalf("read refused: %v %v", err, f.calls)
	}
	src, _ := out.Scope.Source()
	if out.Scope.Candidate() != c || src.Format != artifact.HTTPHeadersFormat || src.DataClass != "extract" || out.Scope.Version != f.record.Version ||
		out.Scope.CaptureID != f.record.CaptureID || out.Scope.Principal != f.identity.Principal || !out.AccessUntil.Equal(f.retention.ExpiresAt) ||
		out.Scope.DisplayVersion != analysis.HTTPHeadersDisplayVersion || out.Scope.BeginTool() != "get_http_headers" {
		t.Fatalf("wrong decision: %+v", out)
	}
	// The protected catalog read follows ordinary target eligibility.
	want := []string{"identity", "permissions", "catalog", "retention", "environment", "identity", "permissions", "retention", "environment", "identity"}
	if !slices.Equal(f.calls, want) {
		t.Fatalf("wrong authority sequence: %v", f.calls)
	}
	if f.evidence[0].NativeType != artifact.HTTPHeadersArtifact {
		t.Fatal("environment did not receive the extract source")
	}
}

func TestHTTPHeaderReadAuthorityRefusesOtherSources(t *testing.T) {
	for _, name := range []string{"pod-status", "metadata-class", "raw-class", "format", "evidence-type", "native-limit", "projection-digest", "pcapng", "classification"} {
		t.Run(name, func(t *testing.T) {
			f, s, c := newHTTPHeaderFixture()
			switch name {
			case "pod-status":
				f, s, ps := newProjectionFixture()
				c := ps.Candidate()
				c.Selection, c.NativeType, c.Headers = analysis.LineSelection{}, artifact.HTTPHeadersArtifact, analysis.HTTPHeaderWindow{Limit: 1}
				if out, err := s.ResolveProjectionCurrent(context.Background(), f, c); err == nil || out.Scope.Valid() {
					t.Fatal("served pod status as http headers")
				}
				return
			case "metadata-class":
				f.record.DataClass = "metadata"
			case "raw-class":
				f.record.DataClass = "raw"
			case "format":
				f.record.SourceFormat = artifact.ContextFormat
			case "evidence-type":
				f.record.Retained.Input.EvidenceType = "context"
			case "native-limit":
				f.record.Retained.Registration.NativeLimit = artifact.HTTPHeadersNativeLimit
			case "projection-digest":
				f.record.SourceProjectionDigest = analysis.ContextSourceProjectionDigest()
			case "pcapng":
				f.record.NativeType, f.record.SourceFormat = artifact.PCAPNGArtifact, artifact.PCAPNGFormat
			case "classification":
				f.record.Retained.Input.PrivacyClass = "verifiedNonPersonal"
			}
			if out, err := s.ResolveProjectionCurrent(context.Background(), f, c); err == nil || out.Scope.Valid() {
				t.Fatalf("accepted %s", name)
			}
			if f.counts["environment"] != 0 {
				t.Fatal("refused source reached the environment")
			}
		})
	}
}

func TestHTTPHeaderReadAuthorityRefusesLostRights(t *testing.T) {
	for _, name := range []string{"no-read-scope", "explicit-deny", "revoked-during-read", "expired", "retention-lapsed", "route-substitution"} {
		t.Run(name, func(t *testing.T) {
			f, s, c := newHTTPHeaderFixture()
			switch name {
			case "no-read-scope":
				f.identity.Scopes = []string{"evidence:download"}
			case "explicit-deny":
				f.permission.Denies = slices.Clone(f.permission.Allows)
			case "revoked-during-read":
				f.on = func(_ context.Context, port string, count int) {
					if port == "environment" && count == 1 {
						f.permission.Denies = slices.Clone(f.permission.Allows)
					}
				}
			case "expired":
				f.record.Retained.Effective.ExpiresAt = f.now
			case "retention-lapsed":
				f.retention.ExpiresAt = f.now
			case "route-substitution":
				c.ArtifactID = projectionTestID(99)
			}
			if out, err := s.ResolveProjectionCurrent(context.Background(), f, c); err == nil || out.Scope.Valid() {
				t.Fatalf("read admitted after %s: %v", name, f.calls)
			}
			if (name == "no-read-scope" || name == "explicit-deny") && f.counts["catalog"] != 0 {
				t.Fatal("protected catalog read before eligibility")
			}
		})
	}
}

func TestHTTPHeaderScopeDoesNotReadPodStatusOrViceVersa(t *testing.T) {
	// A pod-status scope never accepts the published extract.
	f, s, _ := newHTTPHeaderFixture()
	_, _, scope := newProjectionFixture()
	if _, err := s.CheckProjectionCurrent(context.Background(), f, scope); err == nil {
		t.Fatal("pod-status scope accepted an httpHeaders source")
	}
	// An extract scope with a line selection is invalid.
	c := scope.Candidate()
	c.NativeType = artifact.HTTPHeadersArtifact
	if c.Valid() {
		t.Fatal("extract candidate accepted a line selection")
	}
}
