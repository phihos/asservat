package authorization

import (
	"context"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type rawResultsProbe struct {
	calls  int
	until  time.Time
	err    error
	scope  artifact.DownloadScope
	action string
}

func (p *rawResultsProbe) CurrentResultAccess(_ context.Context, _ identities.CurrentIdentity, scope artifact.DownloadScope, action string) (time.Time, error) {
	p.calls++
	p.scope, p.action = scope, action
	return p.until, p.err
}

func rawDownload(f *downloadAuthorityFixture, s *ContextDownloadAuthority, evidenceType string) *rawResultsProbe {
	f.record.DataClass, f.record.ActionID = "raw", "a0123456789abcdef01234567"
	f.record.Retained.Input.EvidenceType = evidenceType
	if evidenceType == "syscallTrace" {
		f.record.NativeType = artifact.SyscallArgumentsArtifact
	}
	if evidenceType == "logs" {
		f.record.NativeType = artifact.LogsArtifact
	}
	p := &rawResultsProbe{until: f.now.Add(2 * time.Second)}
	s.RawResults = p
	return p
}

// ADR-279: a raw artifact needs ordinary eligibility and a current grant
// child, folded into the authority; nothing else admits it.
func TestContextDownloadAuthorityRawNeedsResultAccess(t *testing.T) {
	for _, evidenceType := range []string{"packetCapture", "profile", "syscallTrace", "logs"} {
		t.Run(evidenceType, func(t *testing.T) {
			f, s, scope := newDownloadAuthorityFixture()
			p := rawDownload(f, &s, evidenceType)
			out, err := s.CheckDownload(context.Background(), "synthetic-token", scope)
			if err != nil || !out.Valid(f.now) || !out.ValidUntil.Equal(p.until) || p.calls != 1 || p.scope != scope || p.action != f.record.ActionID {
				t.Fatal("raw download with a current child", err, out.ValidUntil, p.calls)
			}
			for _, name := range []string{"no-port", "refused", "child-ends-now", "no-ordinary-rights", "unknown-class", "raw-context", "raw-core", "profile-extract"} {
				t.Run(name, func(t *testing.T) {
					f, s, scope := newDownloadAuthorityFixture()
					p := rawDownload(f, &s, evidenceType)
					switch name {
					case "no-port":
						s.RawResults = nil
					case "refused":
						p.err = value.ErrGrantRevoked
					case "child-ends-now":
						p.until = f.now
					case "no-ordinary-rights":
						f.p.Allows = nil
					case "unknown-class":
						f.record.DataClass = "restricted"
					case "raw-context":
						f.record.Retained.Input.EvidenceType = "context"
					case "raw-core":
						f.record.Retained.Input.EvidenceType = "coreDump"
					case "profile-extract":
						f.record.Retained.Input.EvidenceType, f.record.DataClass = "profile", "extract"
					}
					if _, err := s.CheckDownload(context.Background(), "synthetic-token", scope); err == nil {
						t.Fatal("raw admitted")
					}
				})
			}
		})
	}
}

// No share admits raw, even one naming exactly this artifact and version.
func TestContextDownloadAuthorityRawRefusesShareRecipient(t *testing.T) {
	for _, evidenceType := range []string{"packetCapture", "profile", "syscallTrace", "logs"} {
		t.Run(evidenceType, func(t *testing.T) {
			f, _, s, scope := shareDownloadFixture()
			p := rawDownload(f, &s, evidenceType)
			if _, err := s.CheckDownload(context.Background(), "synthetic-token", scope); err == nil || p.calls != 0 || f.environmentReads != 0 {
				t.Fatal("share admitted raw", err)
			}
		})
	}
}

// A response-owned entitlement is never kept for raw: every check of the
// same response repeats ordinary rights and the grant facet.
func TestDownloadResponseNeverCachesRaw(t *testing.T) {
	for _, evidenceType := range []string{"packetCapture", "profile", "syscallTrace", "logs"} {
		t.Run(evidenceType, func(t *testing.T) {
			f, s, scope := newDownloadAuthorityFixture()
			p := rawDownload(f, &s, evidenceType)
			owner, err := s.NewDownloadResponse(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			current := credentialIdentity{f, "synthetic"}
			start := f.now
			currentDownloadResponseFacts(f, start)
			p.until = start.Add(2 * time.Second)
			if _, err = owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil || p.calls != 1 {
				t.Fatal("first raw check", err)
			}
			reads := f.policyReads
			currentDownloadResponseFacts(f, start.Add(time.Second))
			p.until = start.Add(3 * time.Second)
			if _, err = owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil || p.calls != 2 || f.policyReads != reads+2 {
				t.Fatal("raw entitlement reused", err, p.calls, f.policyReads-reads)
			}
			p.err = value.ErrGrantRevoked
			if _, err = owner.CheckDownloadCurrent(t.Context(), current, scope); err == nil {
				t.Fatal("revoked grant admitted within the response")
			}
		})
	}
}

func TestSyscallArgumentDownloadRejectsOtherNativeTypes(t *testing.T) {
	for _, native := range []string{"", artifact.SyscallRecordsArtifact, artifact.PprofArtifact, artifact.GoTraceArtifact, "core"} {
		t.Run(native, func(t *testing.T) {
			f, s, scope := newDownloadAuthorityFixture()
			p := rawDownload(f, &s, "syscallTrace")
			f.record.NativeType = native
			if _, err := s.CheckDownload(t.Context(), "synthetic-token", scope); err == nil || p.calls != 0 {
				t.Fatal("unverified syscall native type reached raw approval", err, p.calls)
			}
		})
	}
}

func TestLogsDownloadRejectsOtherNativeTypes(t *testing.T) {
	for _, native := range []string{"", artifact.RawPCAPNGArtifact, artifact.SyscallArgumentsArtifact, artifact.PprofArtifact, artifact.GoTraceArtifact, "core"} {
		t.Run(native, func(t *testing.T) {
			f, s, scope := newDownloadAuthorityFixture()
			p := rawDownload(f, &s, "logs")
			f.record.NativeType = native
			if _, err := s.CheckDownload(t.Context(), "synthetic-token", scope); err == nil || p.calls != 0 {
				t.Fatal("unverified logs native type reached raw approval", err, p.calls)
			}
		})
	}
}
