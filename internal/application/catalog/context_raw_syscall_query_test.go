package catalog

import (
	permissions "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"testing"
)

type rawSyscallSelector interface {
	ResolveRawSyscallQuery(context.Context, identities.CurrentIdentity, string, []artifact.Digest) (permissions.RawQuerySelection, error)
}

func TestRawSyscallSelectionUsesCurrentRawRightsWithoutDownload(t *testing.T) {
	for _, mode := range []string{"allowed", "no-raw", "denied", "wrong-native", "changed-identity"} {
		t.Run(mode, func(t *testing.T) {
			f, s := rawCaseFixture()
			f.i.Scopes = []string{"evidence:read", "evidence:raw"}
			switch mode {
			case "no-raw":
				f.i.Scopes = []string{"evidence:read"}
			case "denied":
				f.p.Denies = f.p.Allows
			case "wrong-native":
				f.record.NativeType = artifact.RawPCAPNGArtifact
				f.record.Retained.Input.EvidenceType = "packetCapture"
			case "changed-identity":
				f.afterFinalRecovery = func() { f.i.Principal.ClientID = "other" }
			}
			selector, ok := any(s).(rawSyscallSelector)
			if !ok {
				t.Fatal("saved syscall query has no exact ordinary/raw selection facet")
			}
			selected, e := selector.ResolveRawSyscallQuery(t.Context(), f, f.routes.CaseID, []artifact.Digest{f.record.Version})
			if mode == "allowed" {
				if e != nil || len(selected.Artifacts) != 1 || selected.Artifacts[0].Output.ArtifactDigest != f.record.Version || f.catalogReads != 1 {
					t.Fatal(selected, e)
				}
			} else if e == nil || len(selected.Artifacts) != 0 {
				t.Fatal("unsafe raw syscall selection", selected, e)
			}
			if (mode == "no-raw" || mode == "denied") && f.catalogReads != 0 {
				t.Fatal("catalog read before current raw rights")
			}
		})
	}
}
