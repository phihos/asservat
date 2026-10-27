package capture

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// Pure application composition: a retained immutable preview and synthetic
// covering-grant port, with current facts expiring before admission. SQL grant
// admission/closure and the installed signed review are qualified separately.
func TestApprovedRetainedRecordingFactsRefusalThenExplicitResolutionCloses(t *testing.T) {
	for _, bound := range []string{"identity", "recovery", "target", "capability", "retention"} {
		t.Run(bound, func(t *testing.T) {
			base := newInvestigationFixture()
			f := &retainedRecording{investigationFixture: base}
			base.target.NodeUID, base.target.NodeBootID, base.target.Pin.NodeName = "", "", ""
			base.target.ExecutionClass, base.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
			base.svc.Previews, base.svc.Admission, base.svc.Recorders = f, f, availableRecording{}
			policy := identity.Policy{Revision: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{1}}, Issuer: f.actor.Issuer, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second), Clients: []identity.Client{{ID: "console", Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"dev-team"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute, RequireRecordingApproval: true}
			base.svc.Approvals = fixedApprovalSettings{policy: policy}
			grants := &fakeGrants{}
			base.svc.Grants = grants
			preview, err := base.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(networkComposition()))
			if err != nil || !preview.Recordable {
				t.Fatal("preview", err)
			}
			p := preview.Preview
			if _, err = f.request(t, p, "review"); !errors.Is(err, authorization.ErrApprovalRequired) {
				t.Fatal("review", err)
			}
			f.now = p.Deadline.Add(time.Minute)
			policy.ObservedAt, policy.FreshUntil = f.now, f.now.Add(30*time.Second)
			base.svc.Approvals = fixedApprovalSettings{policy: policy}
			grants.grant.ExpiresAt = f.now.Add(90 * time.Second)
			grants.covering = nil
			until := f.now.Add(1400 * time.Millisecond)
			source := f.source(t, t.Context())
			facts := &consumptionFacts{investigationFixture: base, eligible: base.svc.Eligibility, bound: bound, until: until}
			base.svc.Eligibility, base.svc.Capabilities, base.svc.Retention = facts, facts, facts
			switch bound {
			case "identity":
				source = &shortenedContinuationIdentity{source: source, until: until}
			case "recovery":
				base.svc.Recovery = consumptionRecovery{base, until}
			case "target":
				base.svc.Targets = consumptionTarget{base, until}
			}
			base.svc.Storage = consumptionStorageFunc(func(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
				// A new storage observation cannot revive an earlier original authority.
				f.now = until
				return base.ContextStorage(ctx, target)
			})
			var reports []string
			base.svc.ReportPreviewFailure = func(stage string) { reports = append(reports, stage) }
			if _, err = base.svc.Request(t.Context(), source, p.ID, "original"); !errors.Is(err, value.ErrChanged) || len(f.seen) != 0 || base.admissions.Load() != 0 || !slices.Equal(reports, []string{"request/facts/current/" + bound}) {
				t.Fatal("expired fact reached admission", bound, err, reports)
			}
			stored := base.previews[p.ID]
			if stored.ScopeDigest != p.ScopeDigest || !slices.Equal(stored.CanonicalScope, p.CanonicalScope) || !stored.Deadline.Equal(p.Deadline) || !stored.CreatedAt.Equal(p.CreatedAt) {
				t.Fatal("retained approved plan changed")
			}
			// Resolution is a separate explicit operation with independently current
			// identity/recovery. Since admission never occurred, its safe result is closed.
			base.svc.Recovery = base
			d, err := base.svc.ResolveContextRequest(t.Context(), f.source(t, t.Context()), p.ID, "original")
			if err != nil || d.State != value.RequestClosed || d.Accepted != nil || len(f.seen) != 0 {
				t.Fatal("refusal was mistaken for accepted work", d, err)
			}
			if _, err = base.svc.Request(t.Context(), f.source(t, t.Context()), p.ID, "original"); err == nil || len(f.seen) != 0 {
				t.Fatal("closed approved intent restarted", err)
			}
		})
	}
}
