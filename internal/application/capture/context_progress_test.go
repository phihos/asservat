package capture

import (
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
	"context"
	"testing"
	"time"
)

type progressReadFunc func(context.Context, value.ProgressQuery) (value.ContextProgressObservation, error)

func (f progressReadFunc) ReadContextProgress(c context.Context, q value.ProgressQuery) (value.ContextProgressObservation, error) {
	return f(c, q)
}

type progressNavigationFunc func(context.Context, identities.CurrentIdentity, value.ContextProgressObservation) (ContextCaseLink, error)

func (f progressNavigationFunc) ContextCaseNavigation(c context.Context, i identities.CurrentIdentity, p value.ContextProgressObservation) (ContextCaseLink, error) {
	return f(c, i, p)
}
func TestContextProgressFinalAuthorityAndIndependentNavigation(t *testing.T) {
	for _, name := range []string{"pending-no-case", "published-no-case", "case-authorized", "case-denied", "wrong-case", "stale-case", "expired-permission", "expired-identity", "changed-groups", "cancelled", "recovery-blocked", "foreign-recovery", "wrong-capture"} {
		t.Run(name, func(t *testing.T) {
			f := newInvestigationFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			source := f.source(t, ctx)
			p := value.ContextProgressObservation{CaptureID: fixtureID(30), CandidateCaseID: fixtureID(31), CandidateArtifactID: fixtureID(32), Target: f.target.Target(), Revision: 4, Phase: "Pending", ActionPhase: "Pending", ReasonCode: "DispatchUnconfirmed", CreatedAt: f.now.Add(-time.Minute), Deadline: f.now.Add(time.Minute), ObservedAt: f.now, ValidUntil: f.now.Add(2 * time.Second)}
			s := ContextProgressService{RootID: fixtureID(1), InstallationID: fixtureID(2), Recovery: f, Now: func() time.Time { return f.now }}
			wantErr := false
			wantCase := false
			s.Reader = progressReadFunc(func(_ context.Context, q value.ProgressQuery) (value.ContextProgressObservation, error) {
				if q.CaptureID != p.CaptureID || q.RootID != s.RootID || q.Identity.Principal != f.actor {
					t.Fatal("request authority lost")
				}
				switch name {
				case "published-no-case":
					p.Phase = "Succeeded"
					p.ActionPhase = "Succeeded"
					p.ReasonCode = "Published"
				case "expired-permission":
					f.now = f.now.Add(2 * time.Second)
				case "expired-identity":
					f.now = f.now.Add(5 * time.Second)
				case "changed-groups":
					f.identityChange = "groups"
				case "cancelled":
					cancel()
				case "wrong-capture":
					p.CaptureID = fixtureID(99)
				}
				return p, nil
			})
			switch name {
			case "expired-permission", "expired-identity", "changed-groups", "cancelled", "wrong-capture":
				wantErr = true
			case "recovery-blocked":
				f.recoveryBlocked = true
				wantErr = true
			case "foreign-recovery":
				s.InstallationID = fixtureID(90)
				wantErr = true
			case "case-authorized", "case-denied", "wrong-case", "stale-case":
				wantCase = name == "case-authorized"
				s.Navigation = progressNavigationFunc(func(_ context.Context, _ identities.CurrentIdentity, got value.ContextProgressObservation) (ContextCaseLink, error) {
					if got.CandidateCaseID != p.CandidateCaseID {
						t.Fatal("navigation binding lost")
					}
					l := ContextCaseLink{CaseID: p.CandidateCaseID, ObservedAt: f.now, ValidUntil: f.now.Add(time.Second)}
					switch name {
					case "case-denied":
						return ContextCaseLink{}, value.ErrDenied
					case "wrong-case":
						l.CaseID = fixtureID(80)
					case "stale-case":
						l.ValidUntil = f.now
					}
					return l, nil
				})
			}
			got, err := s.Get(ctx, source, fixtureID(30))
			if (err != nil) != wantErr {
				t.Fatalf("got=%+v err=%v", got, err)
			}
			if wantErr {
				if got.CaptureID != "" {
					t.Fatal("failure exposed metadata")
				}
				return
			}
			if (got.CaseID != "") != wantCase || got.CanCancel {
				t.Fatal("unproven navigation/cancel")
			}
			if got.Phase == "Pending" && got.RetryAfterSeconds != 2 {
				t.Fatal("missing bounded polling hint")
			}
			if got.Phase == "Succeeded" && got.RetryAfterSeconds != 0 {
				t.Fatal("terminal result keeps polling")
			}
		})
	}
}
