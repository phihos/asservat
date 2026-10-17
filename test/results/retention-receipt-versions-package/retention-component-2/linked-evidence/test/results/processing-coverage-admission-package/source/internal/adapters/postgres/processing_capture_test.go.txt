package postgres

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/privacy"
)

func processingCoverageID(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", i) }
func processingCoverageFixture(t *testing.T) (custodydb.ProcessingRoot, capture.ProcessingCoverageRequest, time.Time) {
	t.Helper()
	n := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	b := privacy.ProcessingBacking{RootID: processingCoverageID(1), InstallationID: processingCoverageID(2), PolicyID: processingCoverageID(3), BackupIdentity: processingCoverageID(4), PolicyDigest: artifact.Digest{1}, BackupDigest: artifact.Digest{2}, History: privacy.ProcessingHistoryQualification{Format: privacy.ProcessingHistoryFormat, ID: processingCoverageID(5), Digest: artifact.Digest{3}, RowBytes: 16384, TransitionWALBytes: 65536, BackupCopies: 1, WALCopies: 1}, MaxCaptures: 8, MaxRules: 8, MaxRootTransitions: 8, CleanupSeconds: 1, ValidUntil: n.Add(time.Minute), RetireBy: n.Add(time.Minute + time.Second)}
	var ok bool
	b.BackupBytes, b.WALBytes, ok = b.RequiredBytes()
	if !ok || !b.Valid() {
		t.Fatal("invalid synthetic backing")
	}
	raw, e := json.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	p := custodydb.ProcessingRoot{RootID: id(b.RootID), InstallationID: id(b.InstallationID), IssuerEpoch: id(processingCoverageID(6)), Epoch: id(processingCoverageID(7)), SourceUid: id(processingCoverageID(8)), ProtectionDigest: make([]byte, 32), Backing: raw, BackingRevision: 1, ValidUntil: ts(b.ValidUntil), RetireBy: ts(b.RetireBy), MaxCaptures: b.MaxCaptures, MaxRules: b.MaxRules, MaxRootTransitions: b.MaxRootTransitions, RootTransitions: 1, Sequence: 2, InitializedAt: ts(n.Add(-time.Second)), InitializationID: id(processingCoverageID(9))}
	p.ProtectionDigest[0] = 1
	r := capture.ProcessingCoverageRequest{RootID: b.RootID, Location: artifact.Location{ClusterID: processingCoverageID(10), ArtifactID: processingCoverageID(11), AttemptID: processingCoverageID(12)}, Target: authorization.Target{ClusterID: processingCoverageID(10), NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod"}, AnchorAt: n, DeleteBy: n.Add(30 * time.Second)}
	return p, r, n
}

func TestProcessingCaptureCoverageOriginalRootBounds(t *testing.T) {
	for _, name := range []string{"covered", "exact-boundary", "one-microsecond-too-long", "expired", "missing-initialization", "wrong-installation", "wrong-issuer", "wrong-root", "malformed-backing", "zero-protection", "full", "negative-counter", "overflow-rules", "future-anchor"} {
		t.Run(name, func(t *testing.T) {
			p, r, n := processingCoverageFixture(t)
			installation, issuer := uid(p.InstallationID), uid(p.IssuerEpoch)
			var want error
			switch name {
			case "exact-boundary":
				r.DeleteBy = p.ValidUntil.Time
			case "one-microsecond-too-long":
				r.DeleteBy = p.ValidUntil.Time.Add(time.Microsecond)
				want = capture.ErrProcessingCoverage
			case "expired":
				n = p.ValidUntil.Time
				want = capture.ErrUnavailable
			case "missing-initialization":
				p.InitializationID.Valid = false
				want = capture.ErrUnavailable
			case "wrong-installation":
				installation = processingCoverageID(100)
				want = capture.ErrUnavailable
			case "wrong-issuer":
				issuer = processingCoverageID(100)
				want = capture.ErrUnavailable
			case "wrong-root":
				r.RootID = processingCoverageID(100)
				want = capture.ErrUnavailable
			case "malformed-backing":
				p.Backing = []byte(`{}`)
				want = capture.ErrUnavailable
			case "zero-protection":
				clear(p.ProtectionDigest)
				want = capture.ErrUnavailable
			case "full":
				p.Captures = p.MaxCaptures
				want = capture.ErrCapacity
			case "negative-counter":
				p.Captures = -1
				want = capture.ErrUnavailable
			case "overflow-rules":
				p.Rules = p.MaxRules + 1
				want = capture.ErrUnavailable
			case "future-anchor":
				r.AnchorAt = n.Add(time.Microsecond)
				want = capture.ErrUnavailable
			}
			if err := processingCaptureCoverage(p, nil, r, installation, issuer, n); !errors.Is(err, want) {
				t.Fatalf("coverage error=%v want=%v", err, want)
			}
		})
	}
}

func TestProcessingCaptureCoverageRetainsEachOriginalRule(t *testing.T) {
	for _, name := range []string{"matching-workload", "matching-artifact", "other-workload", "other-artifact", "acquisition-end-exclusive", "released", "exact-rule-boundary", "expired-restriction", "duplicate", "malformed-unrelated", "malformed-after-short-root", "unknown-state", "more-rules-than-accounted"} {
		t.Run(name, func(t *testing.T) {
			p, r, n := processingCoverageFixture(t)
			scope := privacy.ProcessingScope{Kind: "workloadInterval", ClusterID: r.Target.ClusterID, NamespaceUID: r.Target.NamespaceUID, WorkloadUID: r.Target.WorkloadUID, AcquiredFrom: r.AnchorAt.Add(-time.Second), AcquiredUntil: r.AnchorAt.Add(time.Second)}
			row := custodydb.ProcessingRule{RootID: p.RootID, ID: id(processingCoverageID(20)), Revision: 1, State: "restricted", ValidUntil: ts(n.Add(20 * time.Second)), RetireBy: ts(n.Add(21 * time.Second))}
			want := capture.ErrProcessingCoverage
			switch name {
			case "matching-artifact":
				scope = privacy.ProcessingScope{Kind: "artifact", Location: r.Location}
			case "other-workload":
				scope.WorkloadUID = "unrelated"
				want = nil
			case "other-artifact":
				scope = privacy.ProcessingScope{Kind: "artifact", Location: r.Location}
				scope.Location.ArtifactID = processingCoverageID(101)
				want = nil
			case "acquisition-end-exclusive":
				scope.AcquiredUntil = r.AnchorAt
				want = nil
			case "released":
				row.State = "released"
				row.Revision = 2
				want = nil
			case "exact-rule-boundary":
				r.DeleteBy = row.ValidUntil.Time
				want = nil
			case "expired-restriction":
				row.ValidUntil = ts(n.Add(-time.Second))
				row.RetireBy = ts(n.Add(time.Second))
			case "unknown-state":
				row.State = "releasePending"
				want = capture.ErrUnavailable
			}
			raw, e := json.Marshal(scope)
			if e != nil {
				t.Fatal(e)
			}
			row.Scope = raw
			rows := []custodydb.ProcessingRule{row}
			p.Rules = 1
			switch name {
			case "duplicate":
				rows = append(rows, row)
				p.Rules = 2
				want = capture.ErrUnavailable
			case "malformed-unrelated", "malformed-after-short-root":
				bad := row
				bad.ID = id(processingCoverageID(21))
				bad.Scope = []byte(`{}`)
				rows = append(rows, bad)
				p.Rules = 2
				want = capture.ErrUnavailable
				if name == "malformed-after-short-root" {
					r.DeleteBy = p.ValidUntil.Time.Add(time.Microsecond)
				}
			case "more-rules-than-accounted":
				p.Rules = 0
				want = capture.ErrUnavailable
			}
			if err := processingCaptureCoverage(p, rows, r, uid(p.InstallationID), uid(p.IssuerEpoch), n); !errors.Is(err, want) {
				t.Fatalf("coverage error=%v want=%v", err, want)
			}
		})
	}
}

func TestProcessingCaptureCoveragePurposePrivileges(t *testing.T) {
	for _, purpose := range []string{"capture-admit", "processing-read"} {
		grants, ok := publicRuntimeRoleGrants(purpose)
		if !ok {
			t.Fatal("missing purpose")
		}
		seen := map[string]bool{}
		for _, g := range grants {
			if g.object == "processing_root" || g.object == "processing_rule" {
				if g.kind != "table" || g.column != "" || g.privilege != "SELECT" {
					t.Fatal("processing effect grant escaped read facet", purpose, g.key())
				}
				seen[g.object] = true
			}
		}
		if !seen["processing_root"] || !seen["processing_rule"] {
			t.Fatal("missing exact coverage reads", purpose)
		}
	}
}
