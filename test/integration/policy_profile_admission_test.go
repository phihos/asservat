package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Keep this component case within its existing funded 8MiB allocation. Native
// streaming and installed endpoint acquisition have their separate fixtures.
const policyProfileAdmissionBytes = 4 << 20

func policyProfileAdmissionComposition() map[string]any {
	return map[string]any{"components": []any{map[string]any{"id": "cpu", "profileRef": map[string]any{"catalog": "builtin", "name": "go-cpu", "version": "v1"}, "overrides": []any{map[string]any{"actionID": "cpu", "field": "actionMaxBytes", "value": policyProfileAdmissionBytes}}}}, "maxTotalBytes": policyProfileAdmissionBytes, "maxDuration": "30s"}
}

// The definition and eventual concrete Pod endpoint remain explicit synthetic
// component inputs. Both parent and child use the actual profile compilers.
func policyProfileAdmissionCompiler(t testing.TB, cluster string) (captureapp.PolicyRecorderCompiler, *planvalue.PolicyProfileEndpoint) {
	t.Helper()
	d := planvalue.GoEndpointDefinition{Source: planvalue.GoEndpointSource{ClusterID: cluster, ResourceUID: custodyID(), Name: "go-pprof-loopback", Digest: artifact.Digest{17}}, Host: "localhost", PathPolicy: planvalue.GoEndpointPathPolicy, AddressModes: []string{"targetLoopback"}, MinimumPort: 6000, MaximumPort: 6999, LoopbackFamily: "ipv4"}
	digest, err := planning.ProfileEndpointDefinitionDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	pin := &planvalue.PolicyProfileEndpoint{Definition: d, DefinitionDigest: digest, SourceRef: "go-pprof-loopback", SourceKind: targets.ProfileEndpointTemplateBinding, AddressMode: "targetLoopback"}
	compiler := captureapp.SingleRecorder(func(raw json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
		var wire contracts.CaptureComposition
		if err := json.Unmarshal(raw, &wire); err != nil {
			return planvalue.PolicyRecorderConfiguration{}, err
		}
		c, err := conversion.CompositionFromWire(wire)
		if err != nil || c == nil {
			return planvalue.PolicyRecorderConfiguration{}, planvalue.ErrInvalid
		}
		_, err = planning.CompilePolicyRecorder(*c, nil)
		var needed planning.PolicyProfileEndpointNeeded
		if !errors.As(err, &needed) || len(needed.Bindings) != 1 {
			return planvalue.PolicyRecorderConfiguration{}, planvalue.ErrInvalid
		}
		binding := needed.Bindings[0]
		pin.SourceRef, pin.Binding = needed.SourceRef, &binding
		return planning.CompilePolicyRecorder(*c, nil, pin)
	})
	return compiler, pin
}

type policyProfileAdmissionState struct {
	captures, attempts, chargedBytes, chargedObjects, reserved int64
}

func readPolicyProfileAdmissionState(t testing.TB, ctx context.Context, admin *pgxpool.Pool, s captureAdmissionScenario, a capture.Admission) policyProfileAdmissionState {
	t.Helper()
	var state policyProfileAdmissionState
	err := admin.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM context_capture WHERE id=$1),
 (SELECT count(*) FROM custody_attempt WHERE id=$2),
 charged_bytes,charged_objects,
 (SELECT count(*) FROM policy_occurrence WHERE root_id=$4 AND id=$5 AND reserved_capture_id IS NOT NULL)
 FROM custody_allocation WHERE id=$3`, a.Plan.Input.CaptureID, a.Registration.Location.AttemptID, s.a.Registration.AllocationID, a.RootID, a.IdempotencyKey).Scan(&state.captures, &state.attempts, &state.chargedBytes, &state.chargedObjects, &state.reserved)
	if err != nil {
		t.Fatal("profile admission state", err)
	}
	return state
}

func qualifyPolicyProfileAdmissionRefusal(t *testing.T, ctx context.Context, admin *pgxpool.Pool, admissions *postgres.ContextAdmissions, ledger *postgres.PolicyTriggers, s captureAdmissionScenario, authority authorization.AcceptedPolicyAuthority, preview capture.ContextPreview, a capture.Admission) {
	t.Helper()
	before := readPolicyProfileAdmissionState(t, ctx, admin, s, a)
	if _, err := admissions.AdmitReviewedContext(ctx, preview.ID, a); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("profile without raw recurring approval admitted", err)
	}
	if after := readPolicyProfileAdmissionState(t, ctx, admin, s, a); before != after {
		t.Fatal("missing profile grant left capture/custody/output reservation", before, after)
	}
	status, err := ledger.Status(ctx, authority.PolicyUID)
	if err != nil || status.ExecutionsSpent != 1 || status.CollectedBytesSpent != 0 || status.ObservedBytesSpent != 0 {
		t.Fatal("missing grant changed accepted output pools", status, err)
	}
}

func qualifyPolicyProfileChangedDefinition(t *testing.T, ctx context.Context, admin, hub *pgxpool.Pool, admissions *postgres.ContextAdmissions, previews *postgres.ContextPreviews, ledger *postgres.PolicyTriggers, s captureAdmissionScenario, authority authorization.AcceptedPolicyAuthority, grant string, recorder *planvalue.PolicyRecorderConfiguration, a capture.Admission) {
	t.Helper()
	changed := recorder.ProfileEndpoint.Clone()
	changed.Definition.Source.Digest[0]++
	var err error
	changed.DefinitionDigest, err = planning.ProfileEndpointDefinitionDigest(changed.Definition)
	if err != nil || !changed.Valid() {
		t.Fatal("changed protected endpoint definition", err)
	}
	// A fresh, valid concrete child and passive review bind the changed source.
	// Only the parent grant's full-scope matcher can reject this definition.
	a.Plan.Input.CaptureID = custodyID()
	a.Registration.Location.ArtifactID, a.Registration.Location.AttemptID = custodyID(), custodyID()
	a, preview := buildPolicyRecorderAdmissionFixture(t, a, recorder.Composition, nil, true, time.Now().UTC().Truncate(time.Microsecond), changed)
	requirePolicyRecorderAdmissionFixture(t, a, preview, time.Now().UTC())
	if err := previews.CreateContextPreview(ctx, preview); err != nil {
		t.Fatal("changed definition concrete preview", err)
	}
	qualifyPolicyProfileAdmissionRefusal(t, ctx, admin, admissions, ledger, s, authority, preview, a)
	grants, err := postgres.NewAccessGrants(ctx, hub, a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	g, err := grants.Grant(ctx, grant)
	if err != nil || g.PolicySpend != (authorization.PolicyGrantSpend{}) {
		t.Fatal("changed profile definition debited its parent grant", g.PolicySpend, err)
	}
}

func qualifyPolicyProfileExhaustedGrant(t *testing.T, ctx context.Context, admin, hub *pgxpool.Pool, admissions *postgres.ContextAdmissions, previews *postgres.ContextPreviews, s captureAdmissionScenario, a capture.Admission, recorder *planvalue.PolicyRecorderConfiguration, occurrence, grant string) {
	t.Helper()
	a.IdempotencyKey = occurrence
	a.Plan.Input.CaptureID = custodyID()
	a.Registration.Location.ArtifactID, a.Registration.Location.AttemptID = custodyID(), custodyID()
	a, preview := buildPolicyRecorderAdmissionFixture(t, a, recorder.Composition, nil, true, time.Now().UTC().Truncate(time.Microsecond), recorder.ProfileEndpoint)
	if err := previews.CreateContextPreview(ctx, preview); err != nil {
		t.Fatal(err)
	}
	before := readPolicyProfileAdmissionState(t, ctx, admin, s, a)
	if _, err := admissions.AdmitReviewedContext(ctx, preview.ID, a); !errors.Is(err, capture.ErrCapacity) {
		t.Fatal("exhausted profile grant admitted a second capture", err)
	}
	if after := readPolicyProfileAdmissionState(t, ctx, admin, s, a); before != after {
		t.Fatal("profile budget refusal left capture/custody/output reservation", before, after)
	}
	grants, err := postgres.NewAccessGrants(ctx, hub, a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	g, err := grants.Grant(ctx, grant)
	if err != nil || g.PolicySpend != (authorization.PolicyGrantSpend{Executions: 1, CollectedBytes: policyProfileAdmissionBytes}) {
		t.Fatal("profile budget refusal changed original grant spend", g.PolicySpend, err)
	}
}

func TestPolicyProfileAdmissionFixtureOfflineBindings(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	a := policyRecorderOfflineAdmission(t, now)
	a.Plan.Input.Retention.EvidenceType = "profile"
	compiler, endpoint := policyProfileAdmissionCompiler(t, a.Storage.ClusterID)
	raw, err := json.Marshal(policyProfileAdmissionComposition())
	if err != nil {
		t.Fatal(err)
	}
	configs, err := compiler(t.Context(), targets.Request{}, raw)
	if err != nil || len(configs) != 1 {
		t.Fatal("finite profile fixture parent compiler", err)
	}
	a, preview := buildPolicyRecorderAdmissionFixture(t, a, configs[0].Composition, nil, true, now, endpoint)
	requirePolicyRecorderAdmissionFixture(t, a, preview, now)
	profile, _, err := planning.ProfileForContext(a.Plan)
	if err != nil || profile.MaxBytes != policyProfileAdmissionBytes || profile.DurationMillis != 10000 || profile.Type != "cpu" || profile.Mode != "interval" || profile.ForceGC || !endpoint.Matches(a.Plan.Input.Profile.Endpoints[0]) {
		t.Fatal("finite profile fixture changed reviewed acquisition", err)
	}
}
