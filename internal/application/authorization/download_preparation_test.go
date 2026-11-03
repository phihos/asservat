package authorization

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"errors"
	"testing"
	"time"
)

type preparationRawProbe struct {
	*rawResultsProbe
	calls int
	bytes *int64
	after func()
}

func (p *preparationRawProbe) CurrentResultAccessForPreparation(ctx context.Context, i identities.CurrentIdentity, s artifact.DownloadScope, a string, n *int64) (time.Time, error) {
	p.calls++
	p.bytes = n
	if p.after != nil {
		p.after()
	}
	return p.rawResultsProbe.CurrentResultAccess(ctx, i, s, a)
}
func TestRawDownloadPreparationAuthorityOnlySignalsMissingApprovalAfterOrdinaryRights(t *testing.T) {
	for _, name := range []string{"missing", "ordinary-denied", "dependency", "covered", "legacy-size", "expired-during-lookup"} {
		t.Run(name, func(t *testing.T) {
			f, s, scope := newDownloadAuthorityFixture()
			p := &preparationRawProbe{rawResultsProbe: rawDownload(f, &s, "syscallTrace")}
			s.RawResults = p
			size := int64(512)
			f.record.NativeBytes = &size
			p.err = value.ErrApprovalRequired
			switch name {
			case "expired-during-lookup":
				p.after = func() { f.now = f.now.Add(6 * time.Second) }
			case "ordinary-denied":
				f.p.Allows = nil
			case "dependency":
				p.err = ErrGrantUnavailable
			case "covered":
				p.err = nil
			case "legacy-size":
				f.record.NativeBytes = nil
				p.err = nil
			}
			_, err := s.CheckDownloadPreparation(t.Context(), credentialIdentity{s.Identities, "synthetic-token"}, scope)
			if errors.Is(err, value.ErrApprovalRequired) != (name == "missing") {
				t.Fatal("wrong typed refusal", err)
			}
			if name == "ordinary-denied" && p.calls != 0 {
				t.Fatal("grant read before ordinary rights")
			}
			if name == "covered" && (err != nil || p.bytes == nil || *p.bytes != 512) {
				t.Fatal("verified size not reused", p.bytes, err)
			}
			if name == "legacy-size" && (err != nil || p.bytes != nil) {
				t.Fatal("invented legacy size", err)
			}
			p.err = value.ErrApprovalRequired
			if _, err = s.CheckDownloadCurrent(t.Context(), credentialIdentity{s.Identities, "synthetic-token"}, scope); errors.Is(err, value.ErrApprovalRequired) {
				t.Fatal("ongoing authority reopened review")
			}
		})
	}
}

type failingRawCandidates struct{ *memoryGrants }

func (failingRawCandidates) RawQueryCandidates(context.Context, artifact.DownloadScope, value.GrantUse) ([]value.Grant, error) {
	return nil, ErrGrantUnavailable
}
func TestRawDownloadPreparationChecksWholeFileOnlyBeforeTransfer(t *testing.T) {
	f, in, _ := rawQueryFixture(t)
	g := requestRawFixture(t, f, in)
	g = f.approve(t, g)
	o := g.RawQuery.Artifacts[0]
	scope := rawDownloadScope(grantRoot, f.requester.Principal, o.Output)
	dev := grantIdentity{f.requester, &f.now}
	size := o.NativeBytes
	if _, err := f.svc.CurrentResultAccessForPreparation(t.Context(), dev, scope, o.Output.ActionID, &size); err != nil {
		t.Fatal("covering grant prompted", err)
	}
	g = f.store.rows[g.ID]
	g.Spent.Bytes = g.RawQuery.MaxBytes - size + 1
	f.store.rows[g.ID] = g
	if _, err := f.svc.CurrentResultAccessForPreparation(t.Context(), dev, scope, o.Output.ActionID, &size); !errors.Is(err, value.ErrApprovalRequired) {
		t.Fatal("short whole-file budget did not request approval", err)
	}
	if _, err := f.svc.CurrentResultAccess(t.Context(), dev, scope, o.Output.ActionID); err != nil {
		t.Fatal("partial spend invalidated ongoing authority", err)
	}
	f.svc.RawStore = failingRawCandidates{f.store}
	if _, err := f.svc.CurrentResultAccessForPreparation(t.Context(), dev, scope, o.Output.ActionID, &size); !errors.Is(err, ErrGrantUnavailable) {
		t.Fatal("dependency became missing approval", err)
	}
}
