package capture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type submissionFixture struct {
	f                     *investigationFixture
	current               identities.CurrentIdentity
	intentReads, starts   int
	intentHook, startHook func()
	intentErr, startErr   error
	changeIntent          bool
	started               map[string]bool
}

func (s *submissionFixture) AcknowledgedCaptureIntent(ctx context.Context, id string) (audit.CaptureIntent, error) {
	s.intentReads++
	var a value.Accepted
	for _, v := range s.f.accepted {
		if v.CaptureID == id {
			a = v
		}
	}
	b, _ := json.Marshal(a.Expectation)
	e := a.Expectation
	r := audit.CaptureIntent{RootID: s.f.svc.RootID, CaptureID: id, CaseID: e.CaseID, OccurrenceID: e.OccurrenceID, ArtifactID: e.Registration.Location.ArtifactID, AttemptID: e.Registration.Location.AttemptID, Actor: s.f.actor, Target: s.f.target.Target(), ScopeDigest: a.ScopeDigest, SubmissionDigest: a.SubmissionDigest, ExpectationDigest: sha256.Sum256(b), PermissionEpoch: s.f.epoch, PermissionSequence: 1, IdentityRevision: identity.Revision{UID: "identity-policy", Generation: 1, Digest: [32]byte{9}}, CreatedAt: a.CreatedAt, Deadline: a.Deadline, ExpiresAt: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy, ReservedBytes: e.Registration.ReservedBytes()}
	if s.changeIntent {
		r.SubmissionDigest = artifact.Digest{99}
	}
	if s.intentHook != nil {
		s.intentHook()
	}
	if s.intentErr != nil {
		return r, s.intentErr
	}
	return r, ctx.Err()
}
func (s *submissionFixture) StartContext(ctx context.Context, current identities.CurrentIdentity, id string) error {
	if current != s.current {
		return errors.New("caller replaced")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("missing original deadline")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !s.started[id] {
		s.started[id] = true
		s.starts++
	}
	if s.startHook != nil {
		s.startHook()
	}
	return s.startErr
}
func submissionTest(t *testing.T) (*investigationFixture, *submissionFixture, ContextSubmission, value.ContextPreview) {
	t.Helper()
	f := newInvestigationFixture()
	f.now = time.Now().UTC().Truncate(time.Microsecond)
	f.target.ExecutionClass = artifact.ContextAPIExecution
	f.target.NodeUID = ""
	f.target.NodeBootID = ""
	f.target.Pin.NodeName = ""
	f.cap.ExecutionClass = artifact.ContextAPIExecution
	p := f.preview(t)
	x := &submissionFixture{f: f, started: map[string]bool{}}
	return f, x, ContextSubmission{ContextInvestigation: f.svc, Intents: x, Start: x}, p
}

func TestContextSubmissionInvokesOriginalAcceptedStart(t *testing.T) {
	f, x, s, p := submissionTest(t)
	x.current = f.source(t, context.Background())
	a, err := s.Request(context.Background(), x.current, p.ID, "original")
	if err != nil || a.CaptureID != p.CaptureID || x.starts != 1 || x.intentReads != 1 || f.admissions.Load() != 1 {
		t.Fatal("admission did not reach original live start port", err, x.starts, x.intentReads)
	}
	x.current = f.source(t, context.Background())
	again, err := s.Request(context.Background(), x.current, p.ID, "original")
	if err != nil || !again.Replay || again.CaptureID != a.CaptureID || x.starts != 1 || x.intentReads != 1 || f.admissions.Load() != 1 {
		t.Fatal("same-key replay replaced accepted work", err)
	}
}
func TestContextSubmissionDownstreamFailureKeepsAdmission(t *testing.T) {
	for _, mode := range []string{"pending-intent", "wrong-intent", "expiry-in-audit", "cancel-in-audit", "denied-after-audit", "lost-start-response", "expiry-in-start"} {
		t.Run(mode, func(t *testing.T) {
			f, x, s, p := submissionTest(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			x.current = f.source(t, ctx)
			switch mode {
			case "pending-intent":
				x.intentErr = value.ErrUnavailable
			case "wrong-intent":
				x.changeIntent = true
			case "expiry-in-audit":
				x.intentHook = func() { f.now = f.now.Add(6 * time.Second) }
			case "cancel-in-audit":
				x.intentHook = cancel
			case "denied-after-audit":
				x.intentHook = func() { f.denied = true }
			case "lost-start-response":
				x.startErr = value.ErrUnavailable
			case "expiry-in-start":
				x.startHook = func() { f.now = f.now.Add(6 * time.Second) }
			}
			a, err := s.Request(ctx, x.current, p.ID, "original")
			if err == nil || a.CaptureID != p.CaptureID || f.admissions.Load() != 1 {
				t.Fatal("failure discarded or denied original admission", err)
			}
			want := 0
			if mode == "lost-start-response" || mode == "expiry-in-start" {
				want = 1
			}
			if x.starts != want {
				t.Fatal("invalid start", x.starts, want)
			}
			// The original accepted record survives; no fresh capture/key is
			// manufactured to repair this invocation's uncertainty.
			f.denied = false
			x.intentErr = nil
			x.intentHook = nil
			x.startHook = nil
			x.startErr = nil
			x.changeIntent = false
			r, err := f.svc.Request(context.Background(), f.source(t, context.Background()), p.ID, "original")
			if err != nil || !r.Replay || r.CaptureID != a.CaptureID || f.admissions.Load() != 1 || x.starts != want {
				t.Fatal("read-only admission recovery changed effects", err)
			}
		})
	}
}
