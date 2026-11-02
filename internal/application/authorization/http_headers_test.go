package authorization

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type httpHeaderRoutes struct {
	f         *projectionFixture
	candidate analysis.ContextProjectionCandidate
	recovery  artifact.RecoveryProof
	fail      string
}

func (r *httpHeaderRoutes) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	if e := r.f.step(ctx, "recovery"); e != nil || r.fail == "recovery" {
		return artifact.RecoveryProof{}, errors.Join(e, errors.New("recovery"))
	}
	return r.recovery, nil
}

func (r *httpHeaderRoutes) ResolveProjectionRoute(ctx context.Context, caseID, artifactID string, caller identity.Identity, recovery artifact.RecoveryProof) (analysis.ContextProjectionCandidate, error) {
	if e := r.f.step(ctx, "route"); e != nil || r.fail == "route" || caseID != r.candidate.CaseID || artifactID != r.candidate.ArtifactID || recovery != r.recovery || caller.Principal != r.candidate.Principal {
		return analysis.ContextProjectionCandidate{}, errors.Join(e, errors.New("route"))
	}
	return r.candidate, nil
}

// newHTTPHeaderFixture turns the pod-status fixture into a published
// httpHeaders extract of one recording frame.
func newHTTPHeaderFixture() (*projectionFixture, *httpHeaderRoutes, HTTPHeaderReadAuthority) {
	f, s, scope := newProjectionFixture()
	f.record.NativeType, f.record.SourceFormat, f.record.DataClass = artifact.HTTPHeadersArtifact, artifact.HTTPHeadersFormat, "extract"
	f.record.SourceProjectionDigest = artifact.Digest{}
	f.record.Retained.Input.EvidenceType = "packetCapture"
	f.record.Retained.Registration.NativeLimit = artifact.RecordingNativeLimit
	route := scope.Candidate()
	route.Selection = analysis.LineSelection{}
	r := &httpHeaderRoutes{f: f, candidate: route, recovery: f.environment.Recovery}
	return f, r, HTTPHeaderReadAuthority{Projection: s, Recovery: r, Routes: r}
}

func TestHTTPHeaderReadAuthorityAdmitsExtractWithReadRights(t *testing.T) {
	f, r, s := newHTTPHeaderFixture()
	out, err := s.CurrentHTTPHeaderRead(context.Background(), f, r.candidate.CaseID, r.candidate.ArtifactID)
	if err != nil || !out.Valid(f.now) {
		t.Fatalf("read refused: %v %v", err, f.calls)
	}
	if out.NativeType != artifact.HTTPHeadersArtifact || out.Format != artifact.HTTPHeadersFormat || out.DataClass != "extract" || out.Version != f.record.Version ||
		out.CaptureID != f.record.CaptureID || out.Principal != f.identity.Principal || !out.AccessUntil.Equal(f.retention.ExpiresAt) {
		t.Fatalf("wrong decision: %+v", out)
	}
	// Route and recovery precede the shared projection checks; the protected
	// catalog read follows ordinary target eligibility.
	want := []string{"identity", "recovery", "route", "identity", "permissions", "catalog", "retention", "environment", "identity", "permissions", "retention", "environment", "identity"}
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
			f, r, s := newHTTPHeaderFixture()
			switch name {
			case "pod-status":
				f, _, ps := newProjectionFixture()
				r := &httpHeaderRoutes{f: f, candidate: ps.Candidate(), recovery: f.environment.Recovery}
				r.candidate.Selection = analysis.LineSelection{}
				s := HTTPHeaderReadAuthority{Projection: ContextProjectionAuthority{RootID: ps.RootID, Permissions: f, Catalog: f, Retention: f, Environment: f, Now: func() time.Time { return f.now }}, Recovery: r, Routes: r}
				if out, err := s.CurrentHTTPHeaderRead(context.Background(), f, ps.CaseID, ps.ArtifactID); err == nil || out != (analysis.HTTPHeaderReadAuthority{}) {
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
			if out, err := s.CurrentHTTPHeaderRead(context.Background(), f, r.candidate.CaseID, r.candidate.ArtifactID); err == nil || out != (analysis.HTTPHeaderReadAuthority{}) {
				t.Fatalf("accepted %s", name)
			}
			if f.counts["environment"] != 0 {
				t.Fatal("refused source reached the environment")
			}
		})
	}
}

func TestHTTPHeaderReadAuthorityRefusesLostRights(t *testing.T) {
	for _, name := range []string{"no-read-scope", "explicit-deny", "revoked-during-read", "expired", "retention-lapsed", "recovery", "route", "route-substitution", "recovery-changed"} {
		t.Run(name, func(t *testing.T) {
			f, r, s := newHTTPHeaderFixture()
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
			case "recovery", "route":
				r.fail = name
			case "route-substitution":
				r.candidate.ArtifactID = projectionTestID(99)
			case "recovery-changed":
				f.environment.Recovery.Revision.Generation++
			}
			if out, err := s.CurrentHTTPHeaderRead(context.Background(), f, r.candidate.CaseID, f.record.Retained.Registration.Location.ArtifactID); err == nil || out != (analysis.HTTPHeaderReadAuthority{}) {
				t.Fatalf("read admitted after %s: %v", name, f.calls)
			}
			if (name == "no-read-scope" || name == "explicit-deny" || name == "recovery" || name == "route") && f.counts["catalog"] != 0 {
				t.Fatal("protected catalog read before eligibility")
			}
		})
	}
}

func TestHTTPHeaderScopeDoesNotReadPodStatusOrViceVersa(t *testing.T) {
	// A pod-status scope never accepts the published extract.
	f, _, s := newHTTPHeaderFixture()
	_, _, scope := newProjectionFixture()
	if _, err := s.Projection.CheckProjectionCurrent(context.Background(), f, scope); err == nil {
		t.Fatal("pod-status scope accepted an httpHeaders source")
	}
	// An extract scope with a line selection is invalid.
	c := scope.Candidate()
	c.NativeType = artifact.HTTPHeadersArtifact
	if c.Valid() {
		t.Fatal("extract candidate accepted a line selection")
	}
}
