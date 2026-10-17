package integration

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// No SQL, Kubernetes, provider or environment input is opened by these tests.
// Accepted source/recovery/permission facts below are explicitly synthetic;
// this preflight only prevents malformed fixture recipes reaching a native lab.
func TestCapacityNativeInputsProtectedBacking(t *testing.T) {
	q, source := capacityNativeQualification(t, custodyID(), custodyID(), custodyID(), custodyID(), "synthetic-account-v1")
	if !q.Valid() || !app.ValidateRootBackingInput(q.RootBacking) || !source.Valid(time.Now()) {
		t.Fatal("native qualification/static root/source invalid")
	}
	pool, err := app.CompileProtectedPoolPlan(source, "capacity")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := app.CompileQualifiedRootBacking(q, pool)
	if err != nil {
		t.Fatal(err)
	}
	total := plan.Totals()
	if total.Accounts != capacityNativeAccounts || total.Records != capacityNativeAccounts*3 || total.SQLBytes <= 0 || total.BackupBytes <= 0 || total.WALBytes <= 0 || total.KeyAttempts <= 0 {
		t.Fatal("native root omitted fixed/protocol/history dimensions")
	}
	for _, name := range []string{"missing-safety", "missing-burst"} {
		t.Run(name, func(t *testing.T) {
			bad := source
			bad.Pools = append([]app.PoolObservation(nil), source.Pools...)
			budget := *bad.Pools[0].Budget
			if name == "missing-safety" {
				budget.Safety = app.BudgetAmount{}
			} else {
				budget.Burst = app.BudgetAmount{}
			}
			bad.Pools[0].Budget = &budget
			if _, err := app.CompileProtectedPoolPlan(bad, "capacity"); err != app.ErrBudgetInvalid {
				t.Fatal("incomplete original fixture budget accepted", err)
			}
		})
	}
	t.Logf("provisional_accounts=%d records=%d system_bytes=%d sql_bytes=%d backup_bytes=%d wal_bytes=%d key_attempts=%d; arithmetic only, no timing qualification", total.Accounts, total.Records, total.SystemObjects.Bytes, total.SQLBytes, total.BackupBytes, total.WALBytes, total.KeyAttempts)
}

func TestCapacityNativeInputsSourceEnrollmentAndRenewal(t *testing.T) {
	q, template := capacityNativeQualification(t, custodyID(), custodyID(), custodyID(), custodyID(), "synthetic-account-v1")
	n := time.Now().UTC().Truncate(time.Microsecond)
	until := n.Add(5 * time.Second)
	root, installation, cluster := q.RootBacking.RootID, q.RootBacking.InstallationID, template.ClusterID
	recovery := artifact.RecoveryProof{InstallationID: installation, IssuerEpoch: custodyID(), Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{1}}, ObservedAt: n, FreshUntil: until}
	observation := capacityNativeSource(t, template, n, until)
	guard := app.CapacitySourceProtection{ClusterID: cluster, ControlNamespaceUID: template.ControlNamespace.UID, Digest: artifact.Digest{14}, ObservedAt: n, FreshUntil: until}
	acceptance := app.CapacitySourceAcceptance{RootID: root, InstallationID: installation, QualificationID: q.ID, QualificationDigest: q.Digest, Observation: observation, Protection: guard, Recovery: recovery}
	if !acceptance.Valid(n) {
		t.Fatal("native source acceptance shape invalid")
	}
	source := app.AcceptedCapacitySource{Format: app.CapacityAcceptedSourceFormat, RootID: root, InstallationID: installation, QualificationID: q.ID, QualificationDigest: q.Digest, ProtectionDigest: guard.Digest, Revision: 1, Observation: observation, ObservedAt: n, FreshUntil: until}
	if !source.Valid(n) {
		t.Fatal("native accepted source shape invalid")
	}
	policy := capacityNativeProcessingPolicy(q, recovery.IssuerEpoch)
	policy.ObservedAt, policy.FreshUntil = n, until
	if !policy.Valid(n) {
		t.Fatal("native independent processing policy shape invalid")
	}
	original, err := app.NewRootBackingObservation(q, source, policy, recovery, n)
	if err != nil || !original.Valid(n) {
		t.Fatal("native root observation invalid", err)
	}
	cutoff, ok := original.ConfigurationUntil()
	if !ok || !cutoff.Equal(n.Add(time.Duration(q.RootBacking.AdmissionSeconds)*time.Second)) {
		t.Fatal("configuration did not derive first date from original current observation")
	}
	namespace := cfg.NamespaceRef{Name: "applications", UID: custodyID()}
	permissions := app.AcceptedCapacityPermissions{RootID: root, Epoch: custodyID(), Sequence: 1, TrustDigest: artifact.Digest{1}, ObservedAt: n, FreshUntil: until, Scopes: []app.AcceptedCapacityScope{{BasisKey: "synthetic-maintainer", BasisUID: custodyID(), ClusterID: cluster, NamespaceUID: namespace.UID, ScopeDigest: artifact.Digest{2}}}}
	metadataGuard := app.CapacityNamespaceProtection{ClusterID: cluster, Digest: q.NamespaceGuards[0].Digest, Keys: []string{"team"}, ObservedAt: n, FreshUntil: until}
	var first app.EnrollmentObservation
	for i := 0; i < capacityNativeAccounts; i++ {
		kind := "Deployment"
		if i == 1 {
			kind = "StatefulSet"
		}
		t.Run(fmt.Sprintf("account-%02d-%s", i, kind), func(t *testing.T) {
			work := capacityNativeWorkload(cluster, namespace, cfg.WorkloadRef{Kind: kind, Name: fmt.Sprintf("envelope-%d", i), UID: custodyID()}, n, until)
			enrolled, selected, err := app.ComposeEnrollmentObservation(source, metadataGuard, work, permissions, recovery, q.RootBacking.AccountVersion, n)
			if err != nil || !enrolled.Valid(n) {
				t.Fatal("native workload composition invalid", err)
			}
			backing, err := app.CompileContextProtocolBacking(selected.Budget.Context, q.RootBacking.ContextHistory)
			if err != nil || backing.Records != 3 {
				t.Fatal("native workload protocol backing invalid", err)
			}
			if i == 0 {
				first = enrolled
			}
			if enrolled.Valid(until) {
				t.Fatal("expired original workload observation accepted")
			}
		})
	}
	if first.Key.RootID == "" {
		t.Fatal("first workload preflight did not complete")
	}
	// Later observations may select a new configuration. They must leave the
	// immutable funding bytes and every original observation deadline unchanged.
	later := cutoff.Add(time.Second)
	source.Observation = capacityNativeSource(t, template, later, later.Add(5*time.Second))
	source.ObservedAt, source.FreshUntil = later, later.Add(5*time.Second)
	recovery.ObservedAt, recovery.FreshUntil = later, source.FreshUntil
	policy.ObservedAt, policy.FreshUntil = later, source.FreshUntil
	renewal, err := app.NewRootBackingObservation(q, source, policy, recovery, later)
	if err != nil {
		t.Fatal("native renewal observation invalid", err)
	}
	a, ad := original.Plan.Canonical()
	b, bd := renewal.Plan.Canonical()
	next, ok := renewal.ConfigurationUntil()
	if !ok || !next.After(cutoff) || ad != bd || !bytes.Equal(a, b) || !original.FreshUntil.Equal(until) || !first.FreshUntil.Equal(until) || original.Valid(later) {
		t.Fatal("renewal changed original funding/authority")
	}
}

func TestCapacityNativeInputsContextAndSession(t *testing.T) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	cluster, root, installation := custodyID(), custodyID(), custodyID()
	target := capacityNativeTarget(cluster, cfg.NamespaceRef{Name: "applications", UID: custodyID()}, cfg.WorkloadRef{Kind: "Deployment", Name: "first", UID: custodyID()}, n)
	if !target.Valid(n) {
		t.Fatal("native target shape invalid")
	}
	revision := identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{1}}
	// Current retention below is synthetic solely for pure compiler preflight;
	// the native fixture still obtains its actual SQL-backed retention proof.
	retained, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: revision, ObservedAt: n, FreshUntil: n.Add(5 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: revision, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 7200, DeletionBudgetSeconds: 60}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: 3600, AnchorAt: n}, n)
	if err != nil {
		t.Fatal(err)
	}
	actor := identity.Principal{Issuer: "https://id.example.test", Subject: "capacity-developer", ClientID: "console", Kind: identity.Human}
	input := capacityNativeContextInput(target, retained, actor, custodyID(), n)
	plan, err := planning.CompileContext(input, n)
	if err != nil || !planning.VerifyContextPlan(plan, n) {
		t.Fatal("native context plan shape invalid", err)
	}
	scope := artifact.DownloadScope{RootID: root, ArtifactID: custodyID(), CaptureID: input.CaptureID, ClusterID: cluster, NamespaceUID: target.Request.Namespace.UID, WorkloadUID: target.Request.Workload.UID, PodUID: target.Request.PodUID, Version: artifact.Digest{1}, Principal: actor}
	session := capacityNativeSession(scope, custodyID(), custodyID(), n, n.Add(time.Minute))
	unit := (artifact.Registration{NativeLimit: artifact.MaxContextBytes}).ReservedBytes()
	backing, err := app.CompileContextProtocolBacking(app.BudgetAmount{Bytes: 3 * unit, Objects: 12}, capacityNativeHistory(root, installation))
	if err != nil || !session.Valid() {
		t.Fatal("native session shape invalid", err)
	}
	if session.RequestLimit > backing.RequestsPerSession || session.OutputLimit > backing.OutputBytes/backing.Sessions || session.ReadLimit > backing.ReadBytes/backing.Sessions {
		t.Fatal("native session exceeds original per-session protocol backing")
	}
	if _, err = planning.CompileContext(input, n.Add(5*time.Second)); err == nil {
		t.Fatal("expired synthetic proof compiled")
	}
}

func TestCapacityNativeInputsInstalledWorkerRecipe(t *testing.T) {
	input := contracts.PublicRuntimeRoles{Format: contracts.PublicRuntimeRolesFormat, InstallationID: custodyID(), InitialClaimID: custodyID(), OwnerConfigurationUID: custodyID(), ClusterID: custodyID(), Namespace: contracts.WorkerObjectReference{Name: "control", UID: custodyID()}, LayoutDigest: postgres.PublicRuntimeRoleLayoutDigest()}
	worker := capacityNativeWorkerScope(t, input)
	if worker.WorkerLayout != contracts.HubWorkerInstalledLayout {
		t.Fatal("native worker recipe selected legacy layout")
	}
}
