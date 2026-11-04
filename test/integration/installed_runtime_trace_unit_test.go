package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	runtimetrace "runtime/trace"
	"testing"
	"time"

	capacity "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	capture "asservat.local/asservat/internal/domain/capture"
	plan "asservat.local/asservat/internal/domain/planning"
)

func TestInstalledManualProfileTraceNamespacePlan(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "trace")
	const cluster = "00000000-0000-4000-8000-000000000001"
	d, err := manualRuntimeTraceDefinition()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(map[string]any{"name": manualRuntimeTraceName, "version": "v1", "definition": d})
	if err != nil {
		t.Fatal(err)
	}
	p := checkManualProfilePlan(t, cluster, approvedRecordingArguments(cluster, "payments", "api"), plan.CatalogProfile{Ref: plan.ProfileRef{Catalog: "namespace", Name: manualRuntimeTraceName, Version: "v1"}, SourceClusterID: cluster, SourceNamespaceUID: "namespace", SourceUID: "trace-profile", Document: doc, Enabled: true})
	a := p.Actions[0]
	if a.ComponentID != "trace" || a.LocalID != "trace" || a.ProfileType != "runtimeTrace" || a.ProfileMode != "interval" || a.Duration != "5s" || a.Timeout != "10s" || a.MaxBytes != 32<<20 || a.ForceGC || a.EndpointDigest == "" || p.Approval == nil || p.Approval.DataClass != "raw" || p.Approval.ObservationLimits != nil || len(p.Profiles) != 1 || p.Profiles[0].SourceUID != "trace-profile" {
		t.Fatal("trace lost original bounded endpoint/raw approval/provenance", a, p.Approval)
	}
}
func TestInstalledManualProfileTraceSelector(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	for _, variant := range []string{"", "cpu", "heap", "trace"} {
		t.Setenv("ASSERVAT_PROFILE_VARIANT", variant)
		if installedRuntimeTraceVariant() != (variant == "trace") || installedHeapProfileVariant() != (variant == "heap") || installedApprovedRecordingExpiryProof("manual-profile") != (variant != "heap" && variant != "trace") {
			t.Fatal("closed selector changed CPU/heap behavior", variant)
		}
	}
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "profile-comparison")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "accepted-heavy")
	if installedRuntimeTraceVariant() || installedHeapProfileVariant() || !installedAcceptedHeavyComparison() {
		t.Fatal("trace integration changed the accepted-heavy comparison selector")
	}
	for _, tc := range []struct{ variant, focus string }{{"typo", "manual-profile"}, {"trace", "profile-comparison"}} {
		t.Run(tc.variant+tc.focus, func(t *testing.T) {
			t.Setenv("ASSERVAT_PROFILE_VARIANT", tc.variant)
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", tc.focus)
			defer func() {
				if recover() == nil {
					t.Error("invalid trace variant silently selected CPU")
				}
			}()
			installedRuntimeTraceVariant()
		})
	}
}
func TestInstalledManualProfileTraceFunding(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "trace")
	r := artifact.Registration{NativeLimit: 32 << 20}
	s := artifact.StreamingPlan{Registration: r}
	h := artifact.Registration{NativeLimit: capture.MaxHistoryParameters}
	need := capacity.BudgetAmount{Bytes: r.ReservedBytes() + s.TemporaryBytes() + h.ReservedBytes(), Objects: 4 + 1 + int64(s.PartLimit()) + 4}
	b, o := installedRegionalContextReserve()
	if need.Bytes != 70778880 || need.Objects != 14 || b != 147849216 || o != 48 || nativeCapacityProfile().Records != 12 {
		t.Fatal("trace shape changed funding", need, b, o)
	}
	q, source := installedProfileComparisonCapacityFixture(t, *nativeCapacityProfile())
	work, err := capacity.CompileContextProtocolBacking(capacity.BudgetAmount{Bytes: b, Objects: o}, q.RootBacking.ContextHistory)
	if err != nil || work.Records != 12 {
		t.Fatal(work, err)
	}
	pool, err := capacity.CompileProtectedPoolPlan(source, "capacity")
	if err != nil {
		t.Fatal(err)
	}
	base, err := capacity.CompileQualifiedRootBacking(q, pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, digest := base.Canonical()
	root := capacity.RootConfiguration{Format: capacity.RootConfigurationFormat, RootID: q.RootBacking.RootID, AttemptID: custodyID(), PlanDigest: digest, Revision: 1, InitialObservedAt: now, InitialUntil: now.Add(5 * time.Second), RevisionObservedAt: now, RevisionUntil: now.Add(5 * time.Second), PlannedUntil: now.Add(time.Duration(q.RootBacking.AdmissionSeconds) * time.Second), ReservedAt: now, CaptureBackedAt: &now, ReadyAt: &now}
	queries, err := capacity.CompileQueryBacking(q, root, base, pool, artifact.Digest{1}, custodyID())
	if err != nil {
		t.Fatal(err)
	}
	if combined := base.Totals().SystemObjects.Objects + queries.Reservation.SystemObjects.Objects; combined != 6720 || pool.System.Objects != 10000 || pool.Burst.Objects != 40000 {
		t.Fatal("original reserved query backing changed", combined, pool)
	}
	t.Logf("one trace/history: %d bytes/%d objects within unchanged %d/%d; root records12/query backing12 retained, zero query units used", need.Bytes, need.Objects, b, o)
}
func TestInstalledManualProfileTraceFiniteNativeTool(t *testing.T) {
	var raw bytes.Buffer
	if err := runtimetrace.Start(&raw); err != nil {
		t.Fatal(err)
	}
	runtimetrace.Log(context.Background(), "fixture", "synthetic local tool compatibility only")
	runtimetrace.Stop()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	out, err := validateManualRuntimeTrace(ctx, raw.Bytes(), filepath.Join(t.TempDir(), "synthetic.trace"))
	if err != nil || len(out) == 0 {
		t.Fatal("finite native tool rejected runtime trace", err)
	}
	if _, err := validateManualRuntimeTrace(ctx, raw.Bytes()[:16], filepath.Join(t.TempDir(), "bare.trace")); err == nil {
		t.Fatal("bare header accepted")
	}
	cancelled, stop := context.WithCancel(t.Context())
	stop()
	if _, err := validateManualRuntimeTrace(cancelled, raw.Bytes(), filepath.Join(t.TempDir(), "cancelled.trace")); err == nil {
		t.Fatal("cancelled tool execution succeeded")
	}
}
