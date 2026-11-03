package catalog

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func rawCaseFixture() (*caseFixture, ContextCaseService) {
	f, s := newCaseFixture()
	f.i.Scopes = append(f.i.Scopes, "evidence:download")
	f.record.CaseID = f.routes.CaseID
	f.record.DataClass = "raw"
	f.record.NativeType = artifact.SyscallArgumentsArtifact
	f.record.Retained.Input.EvidenceType = "syscallTrace"
	f.record.ExecutionDigest = artifact.Digest{7}
	f.record.ActionID = "arguments"
	f.record.Namespace = "payments"
	f.record.WorkloadKind = "Deployment"
	f.record.WorkloadName = "api"
	size := int64(234)
	f.record.NativeBytes = &size
	f.routes.Routes[0].Version = f.record.Version
	return f, s
}
func TestRawQuerySelectionUsesExactPublishedVersionAndReadableProvenance(t *testing.T) {
	f, s := rawCaseFixture()
	f.retained.ExpiresAt = f.now.Add(10 * time.Minute)
	got, err := s.ResolveRawQuery(t.Context(), f, f.routes.CaseID, []artifact.Digest{f.record.Version})
	if err != nil || len(got.Artifacts) != 1 || got.Artifacts[0].Output.ExecutionDigest != f.record.ExecutionDigest || got.Artifacts[0].NativeBytes != 234 || !got.Artifacts[0].ExpiresAt.Equal(f.retained.ExpiresAt) || got.Review[0].WorkloadName != "api" || got.Review[0].PodName != "" {
		t.Fatal("exact selection", got, err)
	}
	if f.catalogReads != 1 || f.retentionReads != 1 || f.processingReads != 2 || f.permissionReads != 2 {
		t.Fatal("missing current authority checks", f)
	}
	// The ordinary case view receives the same accepted display metadata.
	c, err := s.GetContextCase(t.Context(), f, f.routes.CaseID)
	if err != nil || c.Artifacts[0].Namespace != "payments" || c.Artifacts[0].WorkloadName != "api" {
		t.Fatal("case labels", c, err)
	}
}
func TestRawQuerySelectionRefusesUnavailableAndChangedFacts(t *testing.T) {
	for _, name := range []string{"unknown size", "wrong case", "missing execution", "wrong native", "metadata", "wrong version", "audience", "retention", "processing", "changed processing", "final deny", "expired observation", "identity changed"} {
		t.Run(name, func(t *testing.T) {
			f, s := rawCaseFixture()
			digest := f.record.Version
			switch name {
			case "unknown size":
				f.record.NativeBytes = nil
			case "wrong case":
				f.record.CaseID = caseID(999)
			case "missing execution":
				f.record.ExecutionDigest = artifact.Digest{}
			case "wrong native":
				f.record.NativeType = artifact.SyscallRecordsArtifact
			case "metadata":
				f.record.DataClass = "metadata"
			case "wrong version":
				f.record.Version[0]++
			case "audience":
				f.record.Audience[0].SubjectID = "another-team"
			case "retention":
				f.retained.ExpiresAt = f.now
			case "processing":
				f.fail = "processing"
			case "changed processing":
				f.processingChange = true
			case "final deny":
				f.afterFinalPermissions = func() { f.p.Denies = f.p.Allows }
			case "expired observation":
				f.afterRetention = func() { f.now = f.now.Add(6 * time.Second) }
			case "identity changed":
				f.afterFinalRecovery = func() { f.i.Principal.ClientID = "other" }
			}
			got, err := s.ResolveRawQuery(t.Context(), f, f.routes.CaseID, []artifact.Digest{digest})
			if err == nil || len(got.Artifacts) != 0 {
				t.Fatal("admitted invalid selected record", got, err)
			}
		})
	}
}
func TestRawQuerySelectionChecksDownloadRightsBeforeCatalogAndNeverUsesShares(t *testing.T) {
	for _, name := range []string{"missing download scope", "denied", "no permission", "unknown digest", "duplicate digest", "ambiguous digest"} {
		t.Run(name, func(t *testing.T) {
			f, s := rawCaseFixture()
			digests := []artifact.Digest{f.record.Version}
			switch name {
			case "missing download scope":
				f.i.Scopes = []string{"evidence:read"}
			case "denied":
				f.p.Denies = f.p.Allows
			case "no permission":
				f.p.Allows = nil
			case "unknown digest":
				digests[0] = artifact.Digest{99}
			case "duplicate digest":
				digests = append(digests, digests[0])
			case "ambiguous digest":
				r := f.routes.Routes[0]
				r.ArtifactID = caseID(300)
				f.routes.Routes = append(f.routes.Routes, r)
			}
			got, err := s.ResolveRawQuery(t.Context(), f, f.routes.CaseID, digests)
			if err == nil || len(got.Artifacts) != 0 || f.catalogReads != 0 {
				t.Fatal("unauthorized catalog lookup", got, err, f.catalogReads)
			}
		})
	}
}

// Private routing may contain unselected other workloads, but their catalog
// records are never fetched to find the caller's already selected exact digest.
func TestRawQuerySelectionDoesNotReadUnselectedTarget(t *testing.T) {
	f, s := rawCaseFixture()
	r := f.routes.Routes[0]
	r.ArtifactID = caseID(300)
	r.Target.PodUID = "unrelated"
	r.Version = artifact.Digest{99}
	f.routes.Routes = append(f.routes.Routes, r)
	got, err := s.ResolveRawQuery(context.Background(), f, f.routes.CaseID, []artifact.Digest{f.record.Version})
	if err != nil || len(got.Artifacts) != 1 || f.catalogReads != 1 {
		t.Fatal(got, err)
	}
}

func TestRawQuerySelectionEverySelectedTargetNeedsItsOwnRights(t *testing.T) {
	f, s := rawCaseFixture()
	r := f.routes.Routes[0]
	r.ArtifactID = caseID(300)
	r.Target.PodUID = "other"
	r.Version = artifact.Digest{99}
	f.routes.Routes = append(f.routes.Routes, r)
	got, err := s.ResolveRawQuery(t.Context(), f, f.routes.CaseID, []artifact.Digest{f.record.Version, r.Version})
	if err == nil || len(got.Artifacts) != 0 || f.catalogReads != 1 {
		t.Fatal("first target authority leaked to second", got, err, f.catalogReads)
	}
}
