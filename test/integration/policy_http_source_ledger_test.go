//go:build cgo && libpcap

package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/pcap"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	authapp "asservat.local/asservat/internal/application/authorization"
	capacity "asservat.local/asservat/internal/application/capacity"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func httpSourceCompositionWire() map[string]any {
	return map[string]any{"components": []any{map[string]any{"id": "net", "profileRef": map[string]any{"catalog": "namespace", "name": "http-source", "version": "v1"}}}, "maxTotalBytes": 16 << 20, "maxDuration": "20s"}
}
func httpSourceCompiler(t *testing.T, cluster, namespace string) captureapp.PolicyRecorderCompiler {
	t.Helper()
	raw, err := os.ReadFile("../../internal/application/planning/profiles/network-connections-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("catalog fixture")
	}
	doc["name"] = "http-source"
	a := doc["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)
	a["impact"] = "sensitiveRead"
	params := a["parameters"].(map[string]any)
	params["filter"] = "tcp port 8080"
	params["profile"] = map[string]any{"kind": "httpHeaders", "protocol": "http1", "projectionRef": map[string]any{"name": "http-response-headers", "version": "v1"}, "maxFlows": 16, "maxHeaderBytes": 4096, "maxReassemblyBytesPerFlow": 65536, "maxReassemblyBytes": 1048576, "idleTimeout": "5s"}
	raw, _ = json.Marshal(doc)
	return captureapp.SingleRecorder(func(wire json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
		var c contracts.CaptureComposition
		if err := json.Unmarshal(wire, &c); err != nil {
			return planvalue.PolicyRecorderConfiguration{}, err
		}
		composition, err := conversion.CompositionFromWire(c)
		if err != nil || composition == nil {
			return planvalue.PolicyRecorderConfiguration{}, planvalue.ErrInvalid
		}
		composition.Resolved = []planvalue.CatalogProfile{{Ref: composition.Components[0].Profile, SourceClusterID: cluster, SourceNamespaceUID: namespace, SourceUID: "synthetic-http-source-profile", Document: raw, Enabled: true}}
		return planning.CompileOngoingPolicyRecorder(*composition, pcap.NewCompiler())
	})
}

// Actual protected capacity/acceptance/grant/source SQL using compiled hub
// privileges. Native target/collector/fleet origins and independent human review
// are fixture inputs; no collector, HTTP reassembly or installed proof here.
func TestHTTPSourceLedgerWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects)
		f.template.Policies[0].SourceResources = &capacity.SourceResourceLimits{Node: collector.PolicyLimits{SourceLimits: collector.SourceLimits{MaxActiveSources: 4, InputBytesPerSecond: 4 << 20, InputBurstBytes: 4 << 20}}, Workload: collector.SourceLimits{MaxActiveSources: 4, InputBytesPerSecond: 4 << 20, InputBurstBytes: 4 << 20}}
		if _, err := f.producer.InitializeCapacity(ctx, f.input, f.protection); err != nil {
			t.Fatal(err)
		}
		f.open(t)
		stop := f.keepFleetCurrent()
		defer func() {
			if err := stop(); err != nil {
				t.Error(err)
			}
		}()
		root, err := (&capacity.RootBackingCoordinator{Store: f.roots, Capture: f.captureRoots, Now: time.Now}).Reconcile(ctx, f.rootObservation(t))
		if err != nil {
			t.Fatal(err)
		}
		f.initializeManagedProcessing(t, root)
		enrollment, err := (&capacity.EnrollmentCoordinator{Store: f.enrollments, Capture: f.captureEnrollments, Accounts: f.accounts, Now: time.Now}).Reconcile(ctx, f.workloadObservation(t, 0))
		if err != nil {
			t.Fatal(err)
		}
		seed, _, _ := f.prepareManagedContext(t, root, enrollment, policySourceFixtureRetentionSeconds)
		option := policyRecorderProtectedCase{Hub: f.roles["hub-runtime"], Admissions: seed.s, Filters: pcap.NewCompiler(), Expression: "tcp port 8080", Subjects: []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "maintainers"}}, Ongoing: true, Retention: "31s", SourceComposition: httpSourceCompositionWire(), SourceCompiler: httpSourceCompiler(t, seed.a.Plan.Input.Target.Request.ClusterID, seed.a.Plan.Input.Target.Request.Namespace.UID), PermissionsAccepted: func(batch cfg.PermissionBatch) { f.batch = policyRecorderCloneBatch(batch) }}
		option.SourceAccepted = func(t *testing.T, accepted policySourceAcceptedFixture) {
			s := accepted.Scenario
			ledger, err := postgres.NewPolicySources(ctx, f.roles["hub-runtime"], s.a.RootID, s.recovery.installation, postgres.EffectTransactionGuards{Recovery: s.recovery.guard, Retention: s.retention.guard})
			if err != nil {
				t.Fatal(err)
			}
			var original captureapp.PolicySourceAdmission
			sourceID, fence, nodeID, bootID, collectorID, epoch := custodyID(), custodyID(), custodyID(), custodyID(), custodyID(), custodyID()
			fresh := func() captureapp.PolicySourceCheck {
				t.Helper()
				_, recovery := f.fresh(t)
				if err := f.enrollments.RefreshCapacityEnrollment(ctx, f.workloadObservation(t, 0), enrollment); err != nil {
					t.Fatal(err)
				}
				n := time.Now().UTC().Truncate(time.Microsecond)
				source := accepted.Source
				source.ObservedAt = n
				source.FreshUntil = n.Add(30 * time.Second)
				if err := accepted.Sources.ObservePolicy(ctx, source); err != nil {
					t.Fatal(err)
				}
				retained, err := s.retention.policies(ctx)
				if err != nil {
					t.Fatal(err)
				}
				target := s.a.Plan.Input.Target
				target.ExecutionClass = artifact.ContextAPIExecution
				target.NodeUID, target.NodeBootID, target.Pin.NodeName = "", "", ""
				target.ObservedAt, target.FreshUntil = n, n.Add(5*time.Second)
				resolved, err := privacy.Resolve(retained, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: 31, AnchorAt: n}, n)
				if err != nil {
					t.Fatal(err)
				}
				settings := identity.Policy{Revision: identity.Revision{UID: "synthetic-settings", Generation: 1, Digest: [32]byte{1}}, Issuer: accepted.Authority.Creator.Issuer, ObservedAt: n, FreshUntil: n.Add(5 * time.Second), Clients: []identity.Client{{ID: accepted.Authority.Creator.ClientID, Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"maintainers"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute}
				return captureapp.PolicySourceCheck{Policy: accepted.Compiled, Authority: accepted.Authority, Target: target, Node: targets.PacketSourceObservation{PodUID: target.Pin.UID, NodeUID: nodeID, BootID: bootID, CollectorPodUID: collectorID, CollectorEpoch: epoch, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, Recovery: recovery, Retention: resolved, Settings: settings, SourceID: sourceID, Fence: fence, BytesPerSecond: 4 << 20, SourceSlots: 4, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}
			}
			in := fresh()
			in.Initial = true
			in.InitialCredit = 1 << 20
			if _, err = ledger.AdmitSource(ctx, in); err == nil {
				t.Fatal("HTTP armed without independently approved observation grant")
			}
			canonical := captureapp.RecorderPolicyScope(accepted.Authority.PolicyUID, accepted.Record.Record.IntentVersion, accepted.Source.CollectionDigest, accepted.Compiled, accepted.Authority.NamespaceUID, accepted.Authority.WorkloadUID, accepted.Authority.Delegation, accepted.Authority.Owners, accepted.Authority.Actions, accepted.Authority.Limits)
			grantID := attachPolicyAccountingGrantMode(t, ctx, admin, f.fixturePool, s, accepted.Authority, canonical, "http-source", true, *accepted.Compiled.Recorder)
			in = fresh()
			in.Initial = true
			in.InitialCredit = 1 << 20
			original, err = ledger.AdmitSource(ctx, in)
			if err != nil {
				t.Fatal("actual reviewed HTTP source admission", err)
			}
			if !original.First || original.Permit.Binding.ObservationGrantID != grantID || original.Permit.BytesPerSecond != 1<<20 || original.Permit.HardUntil.After(original.Permit.StartedAt.Add(time.Minute)) || original.Permit.HardUntil.Sub(original.Permit.StartedAt) < 59*time.Second {
				t.Fatal("original reviewed source bounds")
			}
			snapshot := func() (int64, int64) {
				t.Helper()
				var policy, grant int64
				if err := admin.QueryRow(ctx, `SELECT p.observed_bytes_spent,g.policy_observed_bytes_spent FROM policy_acceptance p JOIN access_grant g ON g.root_id=p.root_id AND g.policy_acceptance_id=p.id WHERE p.root_id=$1 AND p.id=$2 AND g.id=$3`, s.a.RootID, accepted.Record.Record.ID, grantID).Scan(&policy, &grant); err != nil {
					t.Fatal(err)
				}
				return policy, grant
			}
			if p, g := snapshot(); p != 1<<20 || g != 1<<20 {
				t.Fatal("initial credit not charged to both pools", p, g)
			}
			replay, err := ledger.AdmitSource(ctx, in)
			if err != nil || replay.First || replay.Permit != original.Permit {
				t.Fatal("initial replay changed immutable source/credit", err)
			}
			if p, g := snapshot(); p != 1<<20 || g != 1<<20 {
				t.Fatal("replay double charged", p, g)
			}
			q := custodydb.New(f.roles["hub-runtime"])
			active, err := q.CountActiveSourceGrantObservations(ctx, custodydb.CountActiveSourceGrantObservationsParams{RootID: pgtype.UUID{Bytes: uuid.MustParse(s.a.RootID), Valid: true}, GrantID: pgtype.UUID{Bytes: uuid.MustParse(grantID), Valid: true}})
			if err != nil || active != 1 {
				t.Fatal("actual shared grant concurrency count", active, err)
			}
			renewed := fresh()
			renewed.ExpectedCredit = original.Permit.Credit
			renewed.AdditionalCredit = 1 << 20
			next, err := ledger.AdmitSource(ctx, renewed)
			if err != nil || next.Permit.Credit != 2<<20 || !next.Permit.HardUntil.Equal(original.Permit.HardUntil) {
				t.Fatal("renewal changed original session or credit", err)
			}
			if _, err = ledger.AdmitSource(ctx, renewed); err != nil {
				t.Fatal("credit retry", err)
			}
			if p, g := snapshot(); p != 2<<20 || g != 2<<20 {
				t.Fatal("credit delta not charged exactly once", p, g)
			}
			guard, err := postgres.NewRecoveryTransactionGuard(s.a.RootID, s.recovery.installation)
			if err != nil {
				t.Fatal(err)
			}
			grants, err := postgres.NewAccessGrants(ctx, f.roles["hub-runtime"], s.a.RootID, guard)
			if err != nil {
				t.Fatal(err)
			}
			fresh()
			until, err := grants.ReadLiveSourceObservation(ctx, sourceID, grantID)
			if err != nil || !time.Now().Before(until) || until.After(original.Permit.HardUntil) {
				t.Fatal("original current grant read", err)
			}
			g, err := grants.Grant(ctx, grantID)
			if err != nil {
				t.Fatal(err)
			}
			if err = authorization.CheckPolicyObservationStart(g, accepted.Authority, in.Target.Target(), time.Second, 1, active, time.Now()); err == nil {
				t.Fatal("reviewed concurrency ceiling ignored actual active source count")
			}

			proof, err := s.recovery.reader.RecoveryState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = grants.RevokeGrant(ctx, authapp.GrantRevocationInput{GrantID: grantID, Revoker: accepted.Authority.Creator, ExpectedRevision: g.Revision, IdempotencyKey: "revoke-http-source"}, proof); err != nil {
				t.Fatal(err)
			}
			if _, err = grants.ReadLiveSourceObservation(ctx, sourceID, grantID); err == nil {
				t.Fatal("live HTTP current read ignored revoked original grant")
			}
			denied := fresh()
			denied.ExpectedCredit = next.Permit.Credit
			if _, err = ledger.AdmitSource(ctx, denied); err == nil {
				t.Fatal("revoked original source renewed")
			}
			if p, g := snapshot(); p != 2<<20 || g != 2<<20 {
				t.Fatal("revocation refunded original observation spend", p, g)
			}
		}
		qualifyPolicyRecorderAdmission(t, ctx, admin, f.fixturePool, f.store, f.keys, func(*testing.T) captureAdmissionScenario { return seed }, option)
	})
}

func TestHTTPSourceFixtureUsesExactReviewedComposition(t *testing.T) {
	raw, _ := json.Marshal(httpSourceCompositionWire())
	records, err := httpSourceCompiler(t, "00000000-0000-4000-8000-000000000001", "namespace")(t.Context(), targets.Request{}, raw)
	if err != nil || len(records) != 1 || records[0].HTTP == nil || !records[0].HTTP.Valid() || records[0].Action.ExecutionMode != "ongoing" || records[0].Action.PacketProfile != "httpHeaders" || records[0].Filter == nil {
		t.Fatal("actual HTTP source fixture compiler", err)
	}
}
