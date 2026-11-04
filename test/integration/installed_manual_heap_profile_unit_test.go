package integration

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	capacity "asservat.local/asservat/internal/application/capacity"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	capture "asservat.local/asservat/internal/domain/capture"
	plan "asservat.local/asservat/internal/domain/planning"
	"github.com/google/pprof/profile"
)

func TestInstalledManualProfileHeapSelectsNamespaceSnapshot(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "heap")
	input := approvedRecordingArguments("00000000-0000-4000-8000-000000000001", "payments", "api")
	composition := input["profile_composition"].(map[string]any)
	ref := composition["components"].([]any)[0].(map[string]any)["profileRef"].(map[string]string)
	if ref["catalog"] != "namespace" || ref["name"] != "go-heap-snapshot" || ref["version"] != "v1" {
		t.Fatal("heap qualification must select the published namespace snapshot, not CPU", ref)
	}
}

func TestInstalledManualProfileHeapNamespacePlanCompiles(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "heap")
	const cluster = "00000000-0000-4000-8000-000000000001"
	definition, err := manualHeapProfileDefinition()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(map[string]any{"name": manualHeapProfileName, "version": "v1", "definition": definition})
	if err != nil {
		t.Fatal(err)
	}
	p := checkManualProfilePlan(t, cluster, approvedRecordingArguments(cluster, "payments", "api"), plan.CatalogProfile{Ref: plan.ProfileRef{Catalog: "namespace", Name: manualHeapProfileName, Version: "v1"}, SourceClusterID: cluster, SourceNamespaceUID: "namespace", SourceUID: "heap-profile", Document: doc, Enabled: true})
	a := p.Actions[0]
	if a.ComponentID != "heap" || a.LocalID != "heap" || a.ProfileType != "heap" || a.ProfileMode != "snapshot" || a.ForceGC || a.Duration != "" || a.Timeout != "5s" || a.MaxBytes != 16<<20 || a.EndpointDigest == "" || p.Approval == nil || p.Approval.DataClass != "raw" || p.Approval.ObservationLimits != nil {
		t.Fatal("namespace heap plan lost bounded snapshot/raw approval semantics", a, p.Approval)
	}
	if len(p.Profiles) != 1 || p.Profiles[0].SourceUID != "heap-profile" || p.Profiles[0].DefinitionDigest == (artifact.Digest{}) || p.Profiles[0].Ref.Catalog != "namespace" {
		t.Fatal("heap plan lost immutable namespace source provenance", p.Profiles)
	}
}

func TestInstalledManualProfileHeapSelectorPreservesCPUAndRefusesUnknown(t *testing.T) {
	t.Setenv("ASSERVAT_PROFILE_TRANSPORT", "http")
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	for _, variant := range []string{"", "cpu", "heap"} {
		t.Setenv("ASSERVAT_PROFILE_VARIANT", variant)
		heap := variant == "heap"
		if installedHeapProfileVariant() != heap || installedApprovedRecordingExpiryProof("manual-profile") == heap {
			t.Fatal("only focused heap may skip existing CPU expiry proof", variant)
		}
		if nativeCapacityProfile().Records != 12 || !installedRecordingFocus() || !installedFastFixture() {
			t.Fatal("variant changed installed backing or existing dispatcher", variant)
		}
	}
	for _, tc := range []struct{ variant, focus string }{{"typo", "manual-profile"}, {"heap", "profile-comparison"}} {
		t.Run(tc.variant+tc.focus, func(t *testing.T) {
			t.Setenv("ASSERVAT_PROFILE_VARIANT", tc.variant)
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", tc.focus)
			defer func() {
				if recover() == nil {
					t.Error("invalid variant must fail rather than fall back to CPU")
				}
			}()
			installedHeapProfileVariant()
		})
	}
}

func TestInstalledManualProfileHeapFitsExistingBacking(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "heap")
	r := artifact.Registration{NativeLimit: 16 << 20}
	s := artifact.StreamingPlan{Registration: r}
	h := artifact.Registration{NativeLimit: capture.MaxHistoryParameters}
	need := capacity.BudgetAmount{Bytes: r.ReservedBytes() + s.TemporaryBytes() + h.ReservedBytes(), Objects: 4 + 1 + int64(s.PartLimit()) + 4}
	bytes, objects := installedRegionalContextReserve()
	if need.Bytes != 36962304 || need.Objects != 12 || bytes != 147849216 || objects != 48 || bytes < need.Bytes || objects < need.Objects {
		t.Fatal("one heap capture/history must fit unchanged manual funding", need, bytes, objects)
	}
	q, source := installedProfileComparisonCapacityFixture(t, *nativeCapacityProfile())
	work, err := capacity.CompileContextProtocolBacking(capacity.BudgetAmount{Bytes: bytes, Objects: objects}, q.RootBacking.ContextHistory)
	if err != nil || work.Records != 12 || work.Records > q.RootBacking.RecordsPerAccount || q.ContextQuery.WorkloadQueries != 12 || q.ContextQuery.WorkloadQueries < query.ProfileSummaryQueryUnits || query.ProfileSummaryQueryUnits != 10 {
		t.Fatal("heap source/query must fit unchanged root ceiling", work, err)
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
	combined := base.Totals().SystemObjects.Objects + queries.Reservation.SystemObjects.Objects
	if combined != 6720 || pool.System.Objects != 10000 || pool.Burst.Objects != 40000 || pool.Capacity.Objects != 100000 {
		t.Fatal("heap variant changed/exceeded original pool partition", combined, pool)
	}
	t.Logf("heap preflight: one 16MiB capture+history needs %d bytes/%d objects, original %d/%d retained; summary 10 units/root 12; composed %d/10000 system objects,40000 burst (other footprint costs synthetic)", need.Bytes, need.Objects, bytes, objects, combined)
}

func TestInstalledManualProfileHeapNativeSummaryParity(t *testing.T) {
	fn := "main.main"
	native := func(value, duration int64) []byte {
		f := &profile.Function{ID: 1, Name: fn}
		l := &profile.Location{ID: 1, Line: []profile.Line{{Function: f}}}
		p := &profile.Profile{SampleType: []*profile.ValueType{{Type: "inuse_space", Unit: "bytes"}}, Sample: []*profile.Sample{{Location: []*profile.Location{l}, Value: []int64{value}}}, Location: []*profile.Location{l}, Function: []*profile.Function{f}, DurationNanos: duration}
		var out bytes.Buffer
		if err := p.Write(&out); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	for _, value := range []int64{4194304, -7} {
		summary := query.ProfileSummary{SampleType: "inuse_space", Unit: "bytes", Total: value, SymbolStatus: "complete", Top: []query.ProfileHotspot{{Function: &fn, Flat: value, Cumulative: value}}}
		if value > 0 {
			fraction := 1.0
			summary.Top[0].Fraction = &fraction
		}
		data := native(value, 0)
		if err := installedProfileSummaryMatchesNative(summary, data, ""); err != nil {
			t.Fatal("signed native values must survive unchanged", value, err)
		}
		for name, change := range map[string]func(*query.ProfileSummary){
			"unit":      func(s *query.ProfileSummary) { s.Unit = "count" },
			"sign":      func(s *query.ProfileSummary) { s.Total = -s.Total; s.Top[0].Fraction = nil },
			"duration":  func(s *query.ProfileSummary) { d := 1.0; s.DurationSeconds = &d },
			"selection": func(s *query.ProfileSummary) { s.SampleType = "alloc_space" },
		} {
			t.Run(name, func(t *testing.T) {
				changed := query.CloneProfileSummary(summary)
				change(&changed)
				if installedProfileSummaryMatchesNative(changed, data, "") == nil {
					t.Fatal("native parity accepted changed field", name)
				}
			})
		}
	}
}
