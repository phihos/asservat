package authorization

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func newProfileProjectionFixture() (*projectionFixture, ContextProjectionAuthority, analysis.ContextProjectionScope) {
	f, service, scope := newProjectionFixture()
	scope.NativeType, scope.SourceFormat, scope.DisplayVersion = artifact.PprofArtifact, artifact.PprofFormat, analysis.ProfileSummaryDisplayVersion
	scope.SourceProjectionDigest, scope.Selection = artifact.Digest{}, analysis.LineSelection{}
	scope.Profile = analysis.ProfileSummarySelection{SampleType: "cpu", TopN: 20}
	f.record.NativeType, f.record.SourceFormat, f.record.SourceProjectionDigest = scope.NativeType, scope.SourceFormat, scope.SourceProjectionDigest
	f.record.DataClass, f.record.Retained.Input.EvidenceType = "raw", "profile"
	f.record.Retained.Registration.NativeLimit = artifact.MaxPprofBytes
	return f, service, scope
}

func TestProfileProjectionRetainsRawProvenanceAndOrdinaryAudience(t *testing.T) {
	f, service, scope := newProfileProjectionFixture()
	out, err := service.CheckProjectionCurrent(t.Context(), f, scope)
	if err != nil || !out.Valid(f.now) || out.Scope != scope || len(f.evidence) != 2 || f.evidence[0].DataClass != "raw" || f.evidence[0].Retained.Input.EvidenceType != "profile" {
		t.Fatal("profile summary authority lost original raw provenance", err)
	}
	if !out.ValidUntil.Equal(f.record.ValidUntil) || !out.AccessUntil.Equal(f.retention.ExpiresAt) {
		t.Fatal("original authority bounds changed")
	}
}

func TestProfileProjectionNeverUsesMetadataShareFallback(t *testing.T) {
	f, service, scope := newProfileProjectionFixture()
	shares := &projectionShares{now: func() time.Time { return f.now }}
	service.Shares = shares
	f.permission.Allows = nil
	if _, err := service.CheckProjectionCurrent(t.Context(), f, scope); err == nil || shares.reads != 0 || f.counts["catalog"] != 0 {
		t.Fatal("raw profile gained metadata share fallback")
	}
}

func TestProfileProjectionPolicyRequiresExtractProfileClient(t *testing.T) {
	f, _, record, actor := newEnvironmentFixture()
	service, _ := NewContextProjectionPolicies(f, func() time.Time { return f.now })
	path := f.policy.Paths[0]
	for _, mode := range []string{"metadata-context", "raw-profile", "extract-context", "extract-profile"} {
		t.Run(mode, func(t *testing.T) {
			f.policy.Clients[0].DataClasses, f.policy.Clients[0].EvidenceTypes = []string{"extract"}, []string{"profile"}
			switch mode {
			case "metadata-context":
				f.policy.Clients[0].DataClasses, f.policy.Clients[0].EvidenceTypes = []string{"metadata"}, []string{"context"}
			case "raw-profile":
				f.policy.Clients[0].DataClasses = []string{"raw"}
			case "extract-context":
				f.policy.Clients[0].EvidenceTypes = []string{"context"}
			}
			policy, err := service.ContextProjectionPolicy(t.Context(), path.TargetClusterID, path.StoreID, artifact.PprofArtifact)
			if err != nil || policy.NativeType != artifact.PprofArtifact || policy.Permits(actor, path.TargetClusterID, path.StoreID, record.PurposeRef, f.now) != (mode == "extract-profile") {
				t.Fatal("profile output classification ignored", err)
			}
		})
	}
}

func TestProfileEnvironmentRejectsPolicyForAnotherSource(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		f, service, record, actor := newQueryEnvironmentFixture()
		record.NativeType, record.SourceFormat, record.SourceProjectionDigest = artifact.PprofArtifact, artifact.PprofFormat, artifact.Digest{}
		record.DataClass, record.Retained.Input.EvidenceType = "raw", "profile"
		record.Retained.Registration.NativeLimit = artifact.MaxPprofBytes
		if !mismatch {
			f.policy.NativeType = artifact.PprofArtifact
		}
		_, err := service.ProjectionEnvironment(t.Context(), record, actor)
		if (err != nil) != mismatch {
			t.Fatal("source-specific environment policy", mismatch, err)
		}
	}
}

func TestProfileProjectionRejectsWrongSourceAndExpiredAuthority(t *testing.T) {
	for _, mode := range []string{"trace", "core", "class", "format", "version", "source-digest", "scope-display", "scope-selection", "size", "type", "audience", "permissions", "read-scope", "deny", "retention", "after-block", "groups-after-block", "cancel-after-block"} {
		t.Run(mode, func(t *testing.T) {
			f, service, scope := newProfileProjectionFixture()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "trace":
				f.record.NativeType = artifact.GoTraceArtifact
			case "core":
				f.record.NativeType = "core"
			case "class":
				f.record.DataClass = "extract"
			case "format":
				f.record.SourceFormat = artifact.ContextFormat
			case "version":
				f.record.Version[0]++
			case "source-digest":
				f.record.SourceProjectionDigest[0]++
			case "scope-display":
				scope.DisplayVersion = analysis.HTTPHeadersDisplayVersion
			case "scope-selection":
				scope.Headers = analysis.HTTPHeaderWindow{Limit: 1}
			case "size":
				f.record.Retained.Registration.NativeLimit++
			case "type":
				f.record.Retained.Input.EvidenceType = "coreDump"
			case "audience":
				f.record.Audience[0].AssignmentID = projectionTestID(99)
			case "permissions":
				f.permission.Allows = nil
			case "read-scope":
				f.identity.Scopes = nil
			case "deny":
				f.permission.Denies = append(f.permission.Denies, f.permission.Allows[0])
			case "retention":
				f.retention.ExpiresAt = f.now
			case "after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						f.now = f.now.Add(6 * time.Second)
					}
				}
			case "groups-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						f.identity.Groups = nil
					}
				}
			case "cancel-after-block":
				f.on = func(_ context.Context, step string, _ int) {
					if step == "environment" {
						cancel()
					}
				}
			}
			if _, err := service.CheckProjectionCurrent(ctx, f, scope); err == nil {
				t.Fatal("profile summary admitted invalid authority", mode)
			}
			if (mode == "permissions" || mode == "read-scope" || mode == "deny") && f.counts["catalog"] != 0 {
				t.Fatal("protected lookup preceded eligibility")
			}
		})
	}
}
