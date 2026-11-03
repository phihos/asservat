package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type availableProfile struct{ availableRecording }

func (availableProfile) ProfileRecorder(context.Context, targets.PodResolution) error { return nil }
func (a availableProfile) ResolveProfileRecorder(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	return a.fixture.svc.Targets.ResolvePod(ctx, r)
}

type changingProfileEndpoint struct {
	fakeProfileEndpoints
	changed bool
}

func (p *changingProfileEndpoint) ResolveProfileEndpoint(ctx context.Context, r targets.ProfileEndpointRequest) (targets.ProfileEndpointResolution, error) {
	out, err := p.fakeProfileEndpoints.ResolveProfileEndpoint(ctx, r)
	if p.changed {
		out.EndpointDigest = artifact.Digest{9}
	}
	return out, err
}

func TestProfileAdmissionRequiresRawReviewAndFrozenEndpoint(t *testing.T) {
	base := newInvestigationFixture()
	f := &retainedRecording{investigationFixture: base}
	base.target.NodeUID, base.target.NodeBootID, base.target.Pin.NodeName = "", "", ""
	base.target.ExecutionClass, base.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	endpoint := &changingProfileEndpoint{}
	base.svc.Previews, base.svc.Admission, base.svc.Recorders = f, f, availableProfile{availableRecording{base}}
	base.svc.ProfileEndpoints = endpoint
	grants := &fakeGrants{}
	base.svc.Grants = grants
	c := planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "cpu", Profile: planning.ProfileRef{Catalog: "builtin", Name: "go-cpu", Version: "v1"}}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s"}
	preview, err := base.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(&c))
	if err != nil || !preview.Recordable || preview.Plan.Approval == nil || preview.Plan.Approval.DataClass != "raw" {
		t.Fatal("profile preview", err)
	}
	p := preview.Preview
	if _, err = f.request(t, p, "no-result-access"); !errors.Is(err, value.ErrInvalid) || len(grants.requests) != 0 {
		t.Fatal("raw profile without selected result access", err)
	}
	access := &authorization.ResultAccess{ActionIDs: []string{preview.Plan.Actions[0].ID}, Operations: []string{authorization.GrantDownloadOperation}, ClientIDs: []string{"console"}, MaxArtifacts: 1, MaxBytes: 16 << 20, MaxOperations: 1, NotAfter: f.now.Add(time.Hour)}
	if _, err = base.svc.RequestWithResultAccess(t.Context(), f.source(t, t.Context()), p.ID, "review", access); !errors.Is(err, authorization.ErrApprovalRequired) || len(grants.requests) != 1 {
		t.Fatal("profile review", err)
	}
	if grants.requests[0].DataClass != "raw" || grants.requests[0].Review.ObservationLimits != nil || len(f.seen) != 0 {
		t.Fatal("profile invented packet observation budget")
	}
	review := grants.requests[0].Review.Actions[0].Profile
	if review == nil || review.Runtime != "go" || review.Type != "cpu" || review.Mode != "interval" || review.Duration != preview.Plan.Actions[0].Duration || review.Timeout != preview.Plan.Actions[0].Timeout || review.SourceRef != preview.Plan.Input.Endpoints[0].Request.SourceRef || review.EndpointDigest != preview.Plan.Actions[0].EndpointDigest || review.Port != preview.Plan.Input.Endpoints[0].Port {
		t.Fatalf("profile approval lost reviewed parameters: %+v", review)
	}
	grants.covering = nil
	grants.grant.ExpiresAt = f.now.Add(time.Minute)
	if _, err = f.request(t, p, "start"); !errors.Is(err, reachedRecordingAdmission) || len(f.seen) != 1 {
		t.Fatal("approved profile did not reach admission", err)
	}
	a := f.seen[0]
	profile, _, err := compiler.ProfileForContext(a.Plan)
	if err != nil || a.Plan.Input.Recorder != nil || a.Plan.Input.Profile == nil || a.Registration.NativeLimit != 16<<20 || profile.MaxBytes != 16<<20 || a.Plan.ScopeDigest != p.ScopeDigest || !a.Plan.Input.Profile.Endpoints[0].ResolvedAt.Equal(preview.Plan.Input.Endpoints[0].ResolvedAt) {
		t.Fatal("profile scope or ceiling substituted", err)
	}
	endpoint.changed = true
	if _, err = f.request(t, p, "changed-endpoint"); !errors.Is(err, value.ErrChanged) || len(f.seen) != 1 {
		t.Fatal("changed endpoint reached admission", err)
	}
	endpoint.changed = false
	grants.covering = authorization.ErrGrantRevoked
	if _, err = f.request(t, p, "revoked"); !errors.Is(err, authorization.ErrGrantRevoked) || len(f.seen) != 1 {
		t.Fatal("revoked profile reached admission", err)
	}
}
