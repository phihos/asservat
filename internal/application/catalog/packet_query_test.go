package catalog

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
)

func TestPacketQueryReviewSelectionNeedsRawButNotDownloadScope(t *testing.T) {
	for _, scope := range []string{"evidence:raw", "evidence:download"} {
		t.Run(scope, func(t *testing.T) {
			f, s := rawCaseFixture()
			f.i.Scopes = []string{"evidence:read", scope}
			f.record.NativeType = artifact.RawPCAPNGArtifact
			f.record.Retained.Input.EvidenceType = "packetCapture"
			out, e := s.ResolveRawPacketQuery(t.Context(), f, f.routes.CaseID, []artifact.Digest{f.record.Version})
			if scope == "evidence:raw" {
				if e != nil || len(out.Artifacts) != 1 || out.Artifacts[0].Output.ArtifactDigest != f.record.Version {
					t.Fatal("queryreviewrequiredDownload", e)
				}
			} else if e == nil {
				t.Fatal("queryreviewwithoutRaw")
			}
		})
	}
}
