//go:build cgo && libpcap

package integration

import (
	"context"
	"crypto/tls"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/pcap"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	capacity "asservat.local/asservat/internal/application/capacity"
	captureapp "asservat.local/asservat/internal/application/capture"
	configapp "asservat.local/asservat/internal/application/configuration"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// Real source admission/provenance, occurrence and snapshot custody. Original
// administrator, target, node report and packet observations are synthetic;
// this neither starts a collector nor establishes installed/native readiness.
func TestPolicySourceSnapshotWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		t.Run("empty-provenance-down-up", func(t *testing.T) {
			provider, closeProvider := source107MigrationProvider(t, admin)
			defer closeProvider()
			if _, err := provider.DownTo(ctx, 106); err != nil {
				t.Fatal("Down107 empty", err)
			}
			if _, err := provider.Up(ctx); err != nil {
				t.Fatal("Up107 empty", err)
			}
		})
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
		seed, intents, _ := f.prepareManagedContext(t, root, enrollment, policySourceFixtureRetentionSeconds)
		option := policyRecorderProtectedCase{Hub: f.roles["hub-runtime"], Admissions: seed.s, Filters: pcap.NewCompiler(), Expression: "tcp dst port 80", Subjects: []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "maintainers"}}, Ongoing: true, Retention: "31s", PermissionsAccepted: func(batch cfg.PermissionBatch) { f.batch = policyRecorderCloneBatch(batch) }}
		option.SourceAccepted = func(t *testing.T, accepted policySourceAcceptedFixture) {
			source107AddReader(t, ctx, f, "original-source-readers")
			accepted.Scenario.batch = policyRecorderCloneBatch(f.batch)
			s := accepted.Scenario
			ledger, err := postgres.NewPolicySources(ctx, f.roles["hub-runtime"], s.a.RootID, s.recovery.installation, postgres.EffectTransactionGuards{Recovery: s.recovery.guard, Retention: s.retention.guard})
			if err != nil {
				t.Fatal(err)
			}
			sourceID, fence := custodyID(), custodyID()
			var old captureapp.PolicySourceAdmission
			fresh := func(t *testing.T) captureapp.PolicySourceCheck {
				t.Helper()
				// Refresh existing observations only; immutable admission/acceptance,
				// original source identity, counters and hard policy end remain unchanged.
				_, recovery := f.fresh(t)
				if err := f.enrollments.RefreshCapacityEnrollment(ctx, f.workloadObservation(t, 0), enrollment); err != nil {
					t.Fatal("current storage binding", err)
				}
				n := time.Now().UTC().Truncate(time.Microsecond)
				src := accepted.Source
				src.ObservedAt = n
				src.FreshUntil = n.Add(30 * time.Second)
				if err := accepted.Sources.ObservePolicy(ctx, src); err != nil {
					t.Fatal("current accepted policy source", err)
				}
				retained, err := s.retention.policies(ctx)
				if err != nil {
					t.Fatal(err)
				}
				target := s.a.Plan.Input.Target
				target.ExecutionClass = artifact.ContextAPIExecution
				target.NodeUID, target.NodeBootID, target.Pin.NodeName = "", "", ""
				target.ObservedAt, target.FreshUntil = n, n.Add(5*time.Second)
				resolution, err := privacy.Resolve(retained, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: policySourceFixtureRetentionSeconds, AnchorAt: n}, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				policy := identity.Policy{Revision: identity.Revision{UID: "synthetic-settings", Generation: 1, Digest: [32]byte{1}}, Issuer: accepted.Authority.Creator.Issuer, ObservedAt: n, FreshUntil: n.Add(5 * time.Second), Clients: []identity.Client{{ID: accepted.Authority.Creator.ClientID, Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"maintainers"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute}
				node := targets.PacketSourceObservation{PodUID: target.Pin.UID, NodeUID: custodyID(), BootID: custodyID(), CollectorPodUID: custodyID(), CollectorEpoch: custodyID(), ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
				if old.Permit.Binding.SourceID != "" {
					node.NodeUID = old.Permit.Binding.NodeUID
					node.BootID = old.Permit.Binding.BootID
					node.CollectorPodUID = old.Permit.Binding.CollectorPodUID
					node.CollectorEpoch = old.Permit.Binding.CollectorEpoch
				}
				return captureapp.PolicySourceCheck{Policy: accepted.Compiled, Authority: accepted.Authority, Target: target, Node: node, Recovery: recovery, Retention: resolution, Settings: policy, SourceID: sourceID, Fence: fence, BytesPerSecond: 1 << 20, SourceSlots: 4, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}
			}
			initial := fresh(t)
			initial.Initial = true
			initial.InitialCredit = 1 << 20
			old, err = ledger.AdmitSource(ctx, initial)
			if err != nil {
				t.Fatal("real107 original source", err)
			}
			t.Run("full-original-provenance", func(t *testing.T) {
				rows, err := ledger.ListSources(ctx, accepted.Authority.PolicyUID)
				if err != nil || len(rows) != 1 || len(rows[0].Audience) != 2 || len(rows[0].Audience) <= len(accepted.Authority.Owners) || rows[0].Target == nil || rows[0].Binding != old.Permit.Binding {
					t.Fatal("full original audience/target not captured", err)
				}
				if rows[0].Target.Request != initial.Target.Request || rows[0].Target.Pin != initial.Target.Pin {
					t.Fatal("original target replaced")
				}
				var tuple int
				if err = admin.QueryRow(ctx, "SELECT pg_column_size(s) FROM policy_recording_source s WHERE root_id=$1 AND id=$2", s.a.RootID, sourceID).Scan(&tuple); err != nil || tuple > 112<<10 {
					t.Fatal("source record backing", tuple, err)
				}
				t.Logf("actual_source107_tuple_bytes=%d original_audience_refs=%d", tuple, len(rows[0].Audience))
			})
			t.Run("immutable-provenance-and-down-refusal", func(t *testing.T) {
				if _, err = admin.Exec(ctx, `UPDATE policy_recording_source SET source_target_json=jsonb_set(source_target_json,'{Request,PodName}','"replacement"'::jsonb) WHERE root_id=$1 AND id=$2`, s.a.RootID, sourceID); capacitySQLState(err) != "23514" {
					t.Fatal("original target mutated", err)
				}
				provider, closeProvider := source107MigrationProvider(t, admin)
				defer closeProvider()
				if _, err = provider.DownTo(ctx, 106); err == nil {
					t.Fatal("populated provenance discarded")
				}
			})
			source107AddReader(t, ctx, f, "later-source-readers")
			accepted.Scenario.batch = policyRecorderCloneBatch(f.batch)
			replayCheck := fresh(t)
			replayCheck.Initial = true
			replayCheck.InitialCredit = initial.InitialCredit
			replay, err := ledger.AdmitSource(ctx, replayCheck)
			if err != nil || replay.First || replay.Permit != old.Permit {
				t.Fatal("initial replay renewed audience/target/grant", err)
			}
			renewalCheck := fresh(t)
			renewalCheck.ExpectedCredit = old.Permit.Credit
			renewal, err := ledger.AdmitSource(ctx, renewalCheck)
			if err != nil || renewal.First || renewal.Permit.Binding != old.Permit.Binding || renewal.Permit.Credit != old.Permit.Credit {
				t.Fatal("quiet renewal replaced original provenance", err)
			}
			originalRows, err := ledger.ListSources(ctx, accepted.Authority.PolicyUID)
			if err != nil || len(originalRows) != 1 || len(originalRows[0].Audience) != 2 {
				t.Fatal("new readers adopted old source", err)
			}
			snapshotCheck := fresh(t)
			snapshot := admitPolicySourceSnapshotFixture(t, ctx, f.roles["hub-runtime"], seed.s, accepted, renewal, snapshotCheck, 64<<10, func(t *testing.T, a value.Admission, p value.ContextPreview) {
				source107RejectChangedSelections(t, ctx, f, seed.s, accepted.Authority, a, p)
			})
			t.Run("original-occurrence-t0", func(t *testing.T) {
				var created time.Time
				if err = admin.QueryRow(ctx, "SELECT created_at FROM policy_occurrence WHERE root_id=$1 AND id=$2", s.a.RootID, snapshot.Occurrence.ID).Scan(&created); err != nil || !created.Equal(snapshot.Occurrence.TriggeredAt) || !created.Equal(snapshot.Accepted.Expectation.Snapshot.T0) {
					t.Fatal("snapshot resampled original occurrence", err)
				}
			})
			t.Run("encrypted-completion-publication-native", func(t *testing.T) {
				qualifySourceSnapshotCompletion(t, ctx, f, accepted, snapshot, intents)
				r := snapshot.Accepted.Expectation.Registration
				var artifactID string
				var anchor, deleteBy time.Time
				if err := admin.QueryRow(ctx, "SELECT artifact_id::text,anchor_at,delete_by FROM context_processing WHERE root_id=$1 AND capture_id=$2", s.a.RootID, snapshot.Accepted.CaptureID).Scan(&artifactID, &anchor, &deleteBy); err != nil || artifactID != r.Location.ArtifactID || !anchor.Equal(r.AnchorAt) || !deleteBy.Equal(r.DeleteBy) {
					t.Fatal("snapshot processing lineage changed original acquisition or deletion bounds", artifactID, anchor, deleteBy, err)
				}
			})
		}
		qualifyPolicyRecorderAdmission(t, ctx, admin, f.fixturePool, f.store, f.keys, func(*testing.T) captureAdmissionScenario { return seed }, option)
	})
}

func source107MigrationProvider(t *testing.T, admin *pgxpool.Pool) (*goose.Provider, func()) {
	t.Helper()
	db := stdlib.OpenDB(*admin.Config().ConnConfig)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	return provider, func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}
}

func source107AddReader(t *testing.T, ctx context.Context, f *capacitySQLFixture, subject string) {
	t.Helper()
	batch := policyRecorderCloneBatch(f.batch)
	reader := batch.Bases[0]
	reader.Resource.UID, reader.Resource.Generation, reader.Resource.ResourceVersion, reader.Resource.SpecDigest = custodyID(), 1, "source-reader-1", artifact.Digest{77}
	reader.Subjects = []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: subject}}
	reader.Roles = []string{"evidence-reader"}
	reader.Automation = nil
	reader.Continuous = true
	reader.ScopeDigest = configapp.PermissionScopeDigest(reader)
	batch.Bases = append(batch.Bases, reader)
	batch.Initial = nil
	batch.RequestID = custodyID()
	batch.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	batch.FreshUntil = batch.ObservedAt.Add(5 * time.Second)
	batch.InputDigest[0]++
	result, err := f.permission.AcceptPermissions(ctx, batch)
	if err != nil {
		t.Fatal("real reader acceptance", err)
	}
	batch.ExpectedSequence = result.Sequence
	f.batch = batch
	for range 2 {
		if err = (auditapp.AuthorityPublisher{Ledger: f.permission, Objects: &objectstore.AuthorityObjects{Store: f.store, Seal: f.keys, Open: f.keys}}).PublishAuthority(ctx); err != nil {
			t.Fatal("reader acceptance audit", err)
		}
	}
}

func source107RejectChangedSelections(t *testing.T, ctx context.Context, f *capacitySQLFixture, admissions *postgres.ContextAdmissions, authority authorization.AcceptedPolicyAuthority, a value.Admission, p value.ContextPreview) {
	t.Helper()
	count := func(t *testing.T) int {
		var n int
		if err := f.admin.QueryRow(ctx, "SELECT count(*) FROM context_capture WHERE root_id=$1", a.RootID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count(t)
	if !t.Run("reject-changed-occurrence-t0", func(t *testing.T) {
		bad := a
		bad.Plan.Input.Snapshot = a.Plan.Input.Snapshot.Clone()
		bad.Plan.Input.Snapshot.Request.T0 = bad.Plan.Input.Snapshot.Request.T0.Add(-time.Millisecond)
		plan, err := compiler.CompileContext(bad.Plan.Input, time.Now())
		if err != nil || plan.ScopeDigest != a.Plan.ScopeDigest {
			t.Fatal("changedT0 must retain reviewed nonclock scope", err)
		}
		bad.Plan = plan
		if _, err = admissions.AdmitReviewedContext(ctx, p.ID, bad); err == nil {
			t.Fatal("automatic Save changed persisted occurrence T0")
		}
		if count(t) != before {
			t.Fatal("refused T0 created capture")
		}
	}) {
		t.FailNow()
	}
	if !t.Run("reject-new-reader-passive-preview", func(t *testing.T) {
		current, err := postgres.NewAutomationAuthorities(ctx, f.roles["hub-runtime"], a.RootID, a.Recovery.InstallationID)
		if err != nil {
			t.Fatal(err)
		}
		projection, err := current.PolicyAutomationAuthority(ctx, authority, a.Plan.Input.Target.Target())
		if err != nil {
			t.Fatal(err)
		}
		full, _, reason := authorization.PolicyDefaultAudience(projection.Permissions, time.Now())
		if reason != "" || len(full) != 3 {
			t.Fatal("three real current readers unavailable", reason)
		}
		bad := a
		input := a.Plan.Input
		input.Snapshot = a.Plan.Input.Snapshot.Clone()
		input.CaptureID, input.CaseID = custodyID(), custodyID()
		input.Snapshot.Request.SnapshotID = custodyID()
		input.Snapshot.SourceAudience = slices.Clone(full)
		input.Snapshot.SourceAudienceDigest, err = compiler.SourceAudienceDigest(full)
		if err != nil {
			t.Fatal(err)
		}
		bad.Plan, err = compiler.CompileContext(input, time.Now())
		if err != nil {
			t.Fatal("self-consistent passive source selection", err)
		}
		bad.CaseID = input.CaseID
		bad.Registration.Location.ArtifactID, bad.Registration.Location.AttemptID = custodyID(), custodyID()
		bad.Eligibility.DefaultAudience = slices.Clone(full)
		preview := p.Clone()
		preview.ID = custodyID()
		preview.CaptureID, preview.CaseID = input.CaptureID, input.CaseID
		preview.ArtifactID, preview.AttemptID = bad.Registration.Location.ArtifactID, bad.Registration.Location.AttemptID
		preview.Intent.Snapshot = input.Snapshot.Clone()
		preview.Audience = slices.Clone(full)
		preview.CanonicalScope = slices.Clone(bad.Plan.CanonicalScope)
		preview.ScopeDigest = bad.Plan.ScopeDigest
		if !captureapp.ValidContextPreview(preview) {
			t.Fatal("negative passive preview invalid before SQL provenance guard")
		}
		previews, err := postgres.NewContextPreviews(ctx, f.roles["hub-runtime"], a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		if err = previews.CreateContextPreview(ctx, preview); err != nil {
			t.Fatal("store passive negative selection", err)
		}
		bad.SubmissionDigest = captureapp.ContextRequestDigest(preview.ID)
		if _, err = admissions.AdmitReviewedContext(ctx, preview.ID, bad); err == nil {
			t.Fatal("new current reader acquired original source bytes through passive preview")
		}
		if count(t) != before {
			t.Fatal("refused audience widening created capture")
		}
	}) {
		t.FailNow()
	}
}

func TestSourceSnapshotFixtureFitsExistingStorage(t *testing.T) {
	_, template := capacityNativeQualification(t, custodyID(), custodyID(), custodyID(), custodyID(), "fixture-version")
	protected := template.Policies[0].Budget.Protected
	bytes := (artifact.Registration{NativeLimit: 64 << 10}).ReservedBytes()
	if bytes < 1 || bytes > protected.Bytes || protected.Objects < 3 {
		t.Fatal("64KiB snapshot cannot fit unchanged configured fixture backing", bytes, protected)
	}
	t.Logf("configured64KiB_snapshot_reserved_bytes=%d existing_workload_protected_bytes=%d; arithmetic only, not measured native overhead", bytes, protected.Bytes)
}
