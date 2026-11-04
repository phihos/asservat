package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
)

// Current acceptance, endpoint and admission ports are synthetic. The real
// policy identity, C3 eligibility, preview and request compiler run together;
// this test grants no SQL or native acquisition authority.
func TestPolicyProfilePreviewRetainsFrozenScopeWithoutObservationLease(t *testing.T) {
	for _, mode := range []string{"current", "changed-endpoint", "denied", "cancelled-owner"} {
		t.Run(mode, func(t *testing.T) {
			f, authority, _, _ := newTeamRecordingFixture(t)
			authority.authority.Actions = []string{"profile"}
			authority.authority.Limits.MaxObservedBytes = 0
			owner, cancel := context.WithCancel(t.Context())
			defer cancel()
			current := newPolicyIdentity(owner, authority, authority.authority, f.now.Add(45*time.Second), func() time.Time { return f.now })
			endpoint := &changingProfileEndpoint{}
			admission := &retainedRecording{investigationFixture: f}
			f.svc.Previews, f.svc.Admission = admission, admission
			f.svc.Recorders = availableProfile{availableRecording{f}}
			f.svc.ProfileEndpoints = endpoint
			grants := &fakeGrants{}
			f.svc.Grants = grants
			composition := planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "cpu", Profile: planning.ProfileRef{Catalog: "builtin", Name: "go-cpu", Version: "v1"}}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s"}
			preview, err := f.svc.PreviewComposition(t.Context(), current, f.compositionIntent(&composition))
			if err != nil || !preview.Recordable || preview.Plan.Approval == nil || preview.Plan.Approval.DataClass != "raw" || preview.Plan.Approval.ObservationLimits != nil {
				t.Fatal("finite policy profile preview", err, preview.Recordable)
			}
			before := preview.Preview.Clone()
			switch mode {
			case "changed-endpoint":
				endpoint.changed = true
			case "denied":
				f.denied = true
			case "cancelled-owner":
				cancel()
			}
			_, err = f.svc.Request(t.Context(), current, before.ID, fixtureID(990))
			if mode != "current" {
				if err == nil || len(admission.seen) != 0 || len(grants.requests) != 0 {
					t.Fatal("changed profile reached admission or opened personal review", mode, err)
				}
				return
			}
			if !errors.Is(err, reachedRecordingAdmission) || len(admission.seen) != 1 || len(grants.requests) != 0 {
				t.Fatal("policy profile missed atomic admission or opened personal review", err)
			}
			accepted := admission.seen[0]
			profile, _, err := compiler.ProfileForContext(accepted.Plan)
			if err != nil || accepted.Plan.Input.Profile == nil || accepted.Plan.Input.Recorder != nil || accepted.Plan.Input.Executor != authority.authority.Executor || accepted.Plan.ScopeDigest != before.ScopeDigest || !accepted.Plan.Input.Deadline.Equal(before.Deadline) || !accepted.Registration.WriteUntil.Equal(identity.Earlier(before.Deadline, accepted.Registration.ExpiresAt)) || profile.Type != "cpu" || profile.Mode != "interval" || profile.ForceGC || profile.MaxBytes != 16<<20 || !accepted.Plan.Input.Profile.Endpoints[0].ResolvedAt.Equal(preview.Plan.Input.Endpoints[0].ResolvedAt) {
				t.Fatal("policy profile changed reviewed source, parameters or original deadline", err)
			}
			if stored := f.previews[before.ID]; stored.ScopeDigest != before.ScopeDigest || !stored.CreatedAt.Equal(before.CreatedAt) || !stored.Deadline.Equal(before.Deadline) {
				t.Fatal("policy profile renewed its original preview")
			}
		})
	}
}
