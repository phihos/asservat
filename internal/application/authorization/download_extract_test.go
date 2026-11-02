package authorization

import (
	"context"
	"testing"
	"time"
)

func extractDownload(f *downloadAuthorityFixture) {
	f.record.DataClass, f.record.ActionID = "extract", "a0123456789abcdef01234567"
	f.record.Retained.Input.EvidenceType = "packetCapture"
}

// ADR-282: an HTTP header projection (class extract) downloads under
// ordinary eligibility alone, without any grant child; without ordinary
// rights, or outside a packet capture, it is refused.
func TestContextDownloadAuthorityExtractUsesOrdinaryRights(t *testing.T) {
	f, s, scope := newDownloadAuthorityFixture()
	extractDownload(f)
	if out, err := s.CheckDownload(context.Background(), "synthetic-token", scope); err != nil || !out.Valid(f.now) {
		t.Fatal("extract download with ordinary rights", err)
	}
	for _, name := range []string{"no-ordinary-rights", "extract-context"} {
		t.Run(name, func(t *testing.T) {
			f, s, scope := newDownloadAuthorityFixture()
			extractDownload(f)
			switch name {
			case "no-ordinary-rights":
				f.p.Allows = nil
			case "extract-context":
				f.record.Retained.Input.EvidenceType = "context"
			}
			if _, err := s.CheckDownload(context.Background(), "synthetic-token", scope); err == nil {
				t.Fatal("extract admitted")
			}
		})
	}
}

// Shares in this release cover metadata only: a recipient without ordinary
// rights cannot download an extract through a share of it.
func TestContextDownloadAuthorityExtractRefusesShareRecipient(t *testing.T) {
	f, _, s, scope := shareDownloadFixture()
	if _, err := s.CheckDownload(context.Background(), "synthetic-token", scope); err != nil {
		t.Fatal("fixture share refused for metadata", err)
	}
	f, _, s, scope = shareDownloadFixture()
	extractDownload(f)
	if _, err := s.CheckDownload(context.Background(), "synthetic-token", scope); err == nil || f.environmentReads != 0 {
		t.Fatal("share admitted an extract", err)
	}
}

// A response-owned ordinary entitlement serves later checks of the same
// extract download (the native transfer checks per window).
func TestDownloadResponseReusesExtractEntitlement(t *testing.T) {
	f, s, scope := newDownloadAuthorityFixture()
	extractDownload(f)
	owner, err := s.NewDownloadResponse(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	current := credentialIdentity{f, "synthetic"}
	start := f.now
	currentDownloadResponseFacts(f, start)
	if _, err = owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil {
		t.Fatal("first extract check", err)
	}
	currentDownloadResponseFacts(f, start.Add(time.Second))
	if _, err = owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil {
		t.Fatal("second extract check of the same response", err)
	}
}
