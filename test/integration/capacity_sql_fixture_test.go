package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/capacity"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type capacitySQLFixture struct {
	ctx                context.Context
	admin              *pgxpool.Pool
	root               *capacitySQLRoot
	producer           *postgres.PublicRuntimeSQLRoles
	input              contracts.CapacityRootSetup
	protection         capacitySyntheticProtection
	qualification      app.CapacityQualification
	template           app.CapacitySnapshot
	permission         *postgres.Permissions
	batch              cfg.PermissionBatch
	observer           *postgres.FleetObservation
	administration     fleet.Administration
	roles              map[string]*pgxpool.Pool
	accounts           *auditapp.CaptureAccounts
	source             *postgres.CapacitySourceJournal
	permissionRead     *postgres.CapacityPermissions
	roots              *postgres.CapacityRootBacking
	captureRoots       *postgres.CapacityRootCaptureBacking
	enrollments        *postgres.CapacityEnrollments
	captureEnrollments *postgres.CapacityCaptureEnrollments
	namespace          cfg.NamespaceRef
	workloads          []cfg.WorkloadRef
	legacy             *postgres.Ledger
	registered         map[string]artifact.Registration
	fixturePool        func(string, string) *pgxpool.Pool
	store              *objectstore.Store
	authority          *objectstore.AuthorityObjects
	keys               authorityTestKeys
	processingPolicy   privacy.DownloadPolicy
	additional         []app.Enrollment
}

func newCapacitySQLFixture(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects, configure ...func(*capacitySQLFixture)) *capacitySQLFixture {
	t.Helper()
	input := contracts.PublicRuntimeRoles{Format: contracts.PublicRuntimeRolesFormat, InstallationID: scope.InstallationID, InitialClaimID: claim, OwnerConfigurationUID: custodyID(), ClusterID: scope.ClusterID, Namespace: contracts.WorkerObjectReference{Name: scope.Namespace, UID: scope.NamespaceUID}, LayoutDigest: postgres.PublicRuntimeRoleLayoutDigest()}
	input.Worker = capacityNativeWorkerScope(t, input)
	f := &capacitySQLFixture{ctx: ctx, admin: admin, root: newCapacitySQLRoot(t, input), administration: administration, roles: map[string]*pgxpool.Pool{}, namespace: cfg.NamespaceRef{Name: "applications", UID: custodyID()}, workloads: []cfg.WorkloadRef{{Kind: "Deployment", Name: "first", UID: custodyID()}, {Kind: "StatefulSet", Name: "second", UID: custodyID()}}}
	for len(f.workloads) < capacityNativeAccounts {
		f.workloads = append(f.workloads, cfg.WorkloadRef{Kind: "Deployment", Name: "envelope-" + strconv.Itoa(len(f.workloads)), UID: custodyID()})
	}
	c := publicRoleTLSConfig(t, admin, address, tlsConfig)
	poolFor := func(user, password string) *pgxpool.Pool {
		t.Helper()
		p, e := pgxpool.ParseConfig("")
		if e != nil {
			t.Fatal(e)
		}
		p.ConnConfig = c.Copy()
		p.ConnConfig.User, p.ConnConfig.Password = user, password
		p.MaxConns = 1
		p.MinConns = 0
		out, e := pgxpool.NewWithConfig(ctx, p)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(out.Close)
		return out
	}
	f.fixturePool = poolFor
	f.store = objects.Store
	f.authority = objects
	// The original installation activation above uses real OpenBao. These
	// subsequent synthetic context fixtures share the existing test key port;
	// their SQL roles, encrypted objects and independent verification are real.
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		t.Fatal(e)
	}
	block, e := aes.NewCipher(raw)
	clear(raw)
	if e != nil {
		t.Fatal(e)
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	f.keys = authorityTestKeys{a: aead}
	observerName := "capacity_observer_" + strings.ReplaceAll(custodyID(), "-", "")
	qname := pgx.Identifier{observerName}.Sanitize()
	if _, e := admin.Exec(ctx, "CREATE ROLE "+qname+" LOGIN PASSWORD 'synthetic-observer'; GRANT USAGE ON SCHEMA public TO "+qname+"; GRANT SELECT ON goose_db_version,fleet_trust,fleet_current_trust TO "+qname+"; GRANT UPDATE(installation_id) ON fleet_current_trust TO "+qname+"; GRANT EXECUTE ON FUNCTION observe_fleet_administration(uuid,bigint,timestamptz,oid,timestamptz,uuid,text,bigint,bytea,boolean,timestamptz,timestamptz),fence_fleet_observation(uuid,bigint,timestamptz,oid,timestamptz) TO "+qname); e != nil {
		t.Fatal("fixture observation role unavailable", e)
	}
	var err error
	f.observer, err = postgres.NewFleetObservation(ctx, poolFor(observerName, "synthetic-observer"), scope.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	f.refreshFleet(t)
	f.producer, err = postgres.NewPublicRuntimeSQLRoles(ctx, c, f.root, input)
	if err != nil {
		t.Fatal("actual post-activation role constructor", err)
	}
	t.Cleanup(f.producer.Close)
	if !t.Run("actual-postgres-function-type-alias", func(t *testing.T) {
		var same bool
		var display string
		if err := admin.QueryRow(ctx, `SELECT p.oid=to_regprocedure('public.capacity_managed_admission_until(uuid,uuid,text,timestamp with time zone)')::oid,replace(oidvectortypes(p.proargtypes),' ','') FROM pg_proc p WHERE p.oid=to_regprocedure('public.capacity_managed_admission_until(uuid,uuid,text,timestamptz)')::oid`).Scan(&same, &display); err != nil || !same || display != "uuid,uuid,text,timestampwithtimezone" {
			t.Fatal("actual PostgreSQL exact overload/display qualification unavailable")
		}
		t.Log("same_function_oid=true display_uses_timestamp_with_time_zone=true")
	}) {
		t.FailNow()
	}
	// Production observes fleet trust continuously; this fixture's single
	// observation lasts five seconds, shorter than producing all public roles
	// (eighty with ADR-197). Keep it current, as the observer would.
	stopFleet := f.keepFleetCurrent()
	start := time.Now()
	_, err = f.producer.Provision(ctx)
	if failure := stopFleet(); failure != nil {
		t.Fatal("fixture fleet observation during role production", failure)
	}
	if err != nil {
		// The stop names its step only; say which closed cause ended it.
		cause := "other"
		switch {
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			cause = "deadline"
		case errors.Is(err, cfg.ErrChanged):
			cause = "changed"
		case errors.Is(err, cfg.ErrInvalid):
			cause = "invalid"
		case errors.Is(err, cfg.ErrUnavailable):
			cause = "unavailable"
		}
		t.Fatal("actual fixed role production", err, cause, time.Since(start).Round(time.Millisecond))
	}
	t.Logf("fixed_role_production_ms=%d", time.Since(start).Milliseconds())
	// Original protected material comes only from the fixture root whose claims
	// the actual SQL producer completed. No catalogue-discovered role is adopted.
	for _, m := range f.root.value.State.Roles {
		if m.Receipt == nil {
			t.Fatal("actual original role receipt missing")
		}
		f.roles[m.Purpose] = poolFor(m.Receipt.RoleName, m.Password)
	}
	rootID, epoch := custodyID(), custodyID()
	f.permission, err = postgres.NewPermissions(ctx, poolFor("authority_runtime", "synthetic-authority"), rootID)
	if err != nil {
		t.Fatal(err)
	}
	trust := artifact.Digest{1}
	if _, err = f.permission.BeginPermissions(ctx, rootID, epoch, trust); err != nil {
		t.Fatal(err)
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	bases := []cfg.PermissionBasis{{Resource: cfg.Resource{Kind: "AccessBinding", UID: custodyID(), Generation: 1, ResourceVersion: "synthetic-1", SpecDigest: artifact.Digest{2}}, Scope: cfg.Scope{ClusterID: scope.ClusterID, Namespace: f.namespace}, Effect: "Allow", Subjects: []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "maintainers"}}, Roles: []string{"workload-maintainer"}}}
	bases[0].ScopeDigest = configapp.PermissionScopeDigest(bases[0])
	review := cfg.BootstrapReview{Resource: cfg.Resource{ClusterID: scope.ClusterID, Namespace: scope.Namespace, NamespaceUID: scope.NamespaceUID, Kind: "ConfigMap", UID: custodyID(), ResourceVersion: "synthetic-review-1", SpecDigest: artifact.Digest{9}}, Reviewer: "synthetic-administrator", BindingsDigest: artifact.Digest{8}, ReviewedAt: n.Add(-time.Minute), ExpiresAt: n.Add(10 * time.Minute), ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
	f.batch = cfg.PermissionBatch{RootID: rootID, Epoch: epoch, RequestID: custodyID(), TrustDigest: trust, InputDigest: artifact.Digest{4}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second), Bases: bases, Initial: &cfg.PermissionInitialization{ClusterID: scope.ClusterID, Control: cfg.NamespaceRef{Name: scope.Namespace, UID: scope.NamespaceUID}, BindingCount: 1, BindingsDigest: review.BindingsDigest, Review: &review}}
	accepted, err := f.permission.AcceptPermissions(ctx, f.batch)
	if err != nil {
		t.Fatal("actual permission acceptance", err)
	}
	f.batch.ExpectedSequence = accepted.Sequence
	for i := 0; i < 2; i++ {
		if err = (auditapp.AuthorityPublisher{Ledger: f.permission, Objects: objects}).PublishAuthority(ctx); err != nil {
			t.Fatal("actual encrypted permission audit", err)
		}
	}
	f.qualification, f.template = capacityNativeQualification(t, rootID, scope.InstallationID, scope.ClusterID, scope.NamespaceUID, f.root.value.State.MAC.AccountVersion)
	for _, option := range configure {
		option(f)
	}
	f.processingPolicy = capacityNativeProcessingPolicy(f.qualification, scope.IssuerEpoch)
	raw, err = json.Marshal(f.qualification)
	if err != nil {
		t.Fatal(err)
	}
	f.protection = capacitySyntheticProtection{cluster: scope.ClusterID, namespace: scope.NamespaceUID, digest: artifact.Digest{14}}
	f.input = contracts.CapacityRootSetup{Format: contracts.CapacityRootSetupFormat, InstallationID: scope.InstallationID, InitialClaimID: claim, PermissionRootID: rootID, RoleRootUID: f.root.value.UID, RoleSetupID: f.root.value.State.OperationID, ControlClusterID: scope.ClusterID, ControlNamespaceUID: scope.NamespaceUID, SourceGuardDigest: capacityGuardHex(f.protection.digest), AccountVersion: f.root.value.State.MAC.AccountVersion, Qualification: raw}
	f.legacy, err = postgres.New(ctx, poolFor("custody_runtime", "synthetic-runtime"))
	if err != nil {
		t.Fatal(err)
	}
	f.registered = map[string]artifact.Registration{}
	f.refreshBase(t)
	return f
}

func (f *capacitySQLFixture) refreshFleet(t *testing.T) {
	t.Helper()
	a := f.administration
	a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	a.FreshUntil = a.ObservedAt.Add(5 * time.Second)
	if err := f.observer.ObserveAdministration(f.ctx, fleetBasisFixture(t, f.ctx, f.observer), a); err != nil {
		t.Fatal("current original fleet source", err)
	}
}

// keepFleetCurrent renews the fixture's fleet observation every second until
// stopped; it returns the first renewal failure.
func (f *capacitySQLFixture) keepFleetCurrent() func() error {
	stop, done := make(chan struct{}), make(chan error, 1)
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				done <- nil
				return
			case <-tick.C:
				b, err := f.observer.ReadAdministrationBasis(f.ctx)
				a := f.administration
				a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
				a.FreshUntil = a.ObservedAt.Add(5 * time.Second)
				if err == nil {
					err = f.observer.ObserveAdministration(f.ctx, b, a)
				}
				if err != nil {
					done <- err
					return
				}
			}
		}
	}()
	return func() error { close(stop); return <-done }
}

func (f *capacitySQLFixture) refreshBase(t *testing.T) {
	t.Helper()
	f.refreshFleet(t)
	fence := cfg.PermissionFence{RootID: f.batch.RootID, Epoch: f.batch.Epoch, TrustDigest: f.batch.TrustDigest, Sequence: f.batch.ExpectedSequence}
	if _, err := f.permission.RenewPermissions(f.ctx, fence); err != nil {
		t.Fatal("original permission controller lease", err)
	}
	f.batch.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	f.batch.FreshUntil = f.batch.ObservedAt.Add(5 * time.Second)
	if f.batch.Initial != nil && f.batch.Initial.Review != nil {
		f.batch.Initial.Review.ObservedAt = f.batch.ObservedAt
		f.batch.Initial.Review.FreshUntil = f.batch.FreshUntil
	}
	if err := f.permission.RefreshPermissions(f.ctx, f.batch); err != nil {
		t.Fatal("current original permission source", err)
	}
}

func (f *capacitySQLFixture) open(t *testing.T) {
	t.Helper()
	var err error
	f.accounts, err = auditapp.NewCaptureAccounts(f.input.InstallationID, f.input.AccountVersion, f.root.value.State.MAC.AccountKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.accounts.Close)
	general, capture := f.roles["capacity"], f.roles["capacity-capture"]
	f.source, err = postgres.NewCapacitySourceJournal(f.ctx, general, f.input.PermissionRootID, f.input.InstallationID, f.qualification.ID, f.qualification.Digest)
	if err != nil {
		t.Fatal(err)
	}
	f.permissionRead, err = postgres.NewCapacityPermissions(f.ctx, general, f.input.PermissionRootID, f.input.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	f.roots, err = postgres.NewCapacityRootBacking(f.ctx, general, f.input.PermissionRootID, f.input.InstallationID, f.qualification.ID, f.qualification.Digest)
	if err != nil {
		t.Fatal(err)
	}
	f.captureRoots, err = postgres.NewCapacityRootCaptureBacking(f.ctx, capture, f.input.PermissionRootID, f.input.InstallationID, f.qualification.ID, f.qualification.Digest)
	if err != nil {
		t.Fatal(err)
	}
	f.enrollments, err = postgres.NewCapacityEnrollments(f.ctx, general, f.input.PermissionRootID, f.input.InstallationID, f.accounts)
	if err != nil {
		t.Fatal(err)
	}
	f.captureEnrollments, err = postgres.NewCapacityCaptureEnrollments(f.ctx, capture, f.input.PermissionRootID, f.input.InstallationID, f.accounts)
	if err != nil {
		t.Fatal(err)
	}
}

func (f *capacitySQLFixture) fresh(t *testing.T) (app.AcceptedCapacitySource, artifact.RecoveryProof) {
	t.Helper()
	f.refreshBase(t)
	recovery, err := f.source.RecoveryState(f.ctx)
	if err != nil {
		t.Fatal("actual recovery read", err)
	}
	revision, err := f.source.ReadCapacitySourceRevision(f.ctx, recovery)
	if err != nil {
		t.Fatal("actual source revision read", err)
	}
	protection, err := f.protection.CapacityProtection(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	observation := capacityNativeSource(t, f.template, n, identity.Earlier(n.Add(5*time.Second), recovery.FreshUntil))
	accepted, err := f.source.AcceptCapacitySource(f.ctx, app.CapacitySourceAcceptance{RootID: f.input.PermissionRootID, InstallationID: f.input.InstallationID, QualificationID: f.qualification.ID, QualificationDigest: f.qualification.Digest, ExpectedRevision: revision, Observation: observation, Protection: protection, Recovery: recovery})
	if err != nil {
		t.Fatal("actual source acceptance", err)
	}
	return accepted, recovery
}

func (f *capacitySQLFixture) rootObservation(t *testing.T) app.RootBackingObservation {
	t.Helper()
	source, recovery := f.fresh(t)
	n := time.Now().UTC().Truncate(time.Microsecond)
	p := f.processingPolicy
	p.ObservedAt, p.FreshUntil = n, n.Add(5*time.Second)
	o, err := app.NewRootBackingObservation(f.qualification, source, p, recovery, time.Now())
	if err != nil {
		t.Fatal("composed root observation", err)
	}
	return o
}

// addPermissionScope accepts a further permission batch whose bases add one
// maintainer scope in another cluster, and publishes its authority audit.
func (f *capacitySQLFixture) addPermissionScope(t *testing.T, cluster string, namespace cfg.NamespaceRef) {
	t.Helper()
	base := f.batch.Bases[0]
	base.Resource.UID = custodyID()
	base.Scope = cfg.Scope{ClusterID: cluster, Namespace: namespace}
	base.ScopeDigest = configapp.PermissionScopeDigest(base)
	next := f.batch
	next.Bases = append(slices.Clone(f.batch.Bases), base)
	next.RequestID, next.InputDigest, next.Initial = custodyID(), artifact.Digest{byte(len(next.Bases)), 4}, nil
	f.refreshFleet(t)
	next.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	next.FreshUntil = next.ObservedAt.Add(5 * time.Second)
	accepted, err := f.permission.AcceptPermissions(f.ctx, next)
	if err != nil {
		t.Fatal("regional permission scope acceptance", err)
	}
	next.ExpectedSequence = accepted.Sequence
	f.batch = next
	for i := 0; i < 2; i++ {
		if err = (auditapp.AuthorityPublisher{Ledger: f.permission, Objects: f.authority}).PublishAuthority(f.ctx); err != nil {
			t.Fatal("regional permission audit", err)
		}
	}
	f.refreshBase(t)
}

// regionalObservation composes a workload observation in another cluster
// under that cluster's qualified namespace guard (ADR-197).
func (f *capacitySQLFixture) regionalObservation(t *testing.T, cluster string, digest artifact.Digest, namespace cfg.NamespaceRef, workload cfg.WorkloadRef) app.EnrollmentObservation {
	t.Helper()
	source, recovery := f.fresh(t)
	permissions, err := f.permissionRead.ReadCapacityPermissions(f.ctx, recovery)
	if err != nil {
		t.Fatal("regional maintainer scope", err)
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	until := identity.Earlier(n.Add(5*time.Second), recovery.FreshUntil)
	guard := app.CapacityNamespaceProtection{ClusterID: cluster, Digest: digest, Keys: []string{"team"}, ObservedAt: n, FreshUntil: until}
	o, _, err := app.ComposeEnrollmentObservation(source, guard, capacityNativeWorkload(cluster, namespace, workload, n, until), permissions, recovery, f.input.AccountVersion, time.Now())
	if err != nil {
		t.Fatal("composed regional workload observation", err)
	}
	return o
}

func (f *capacitySQLFixture) workloadObservation(t *testing.T, index int) app.EnrollmentObservation {
	t.Helper()
	source, recovery := f.fresh(t)
	permissions, err := f.permissionRead.ReadCapacityPermissions(f.ctx, recovery)
	if err != nil {
		t.Fatal("actual accepted maintainer scope", err)
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	until := identity.Earlier(n.Add(5*time.Second), recovery.FreshUntil)
	guard := app.CapacityNamespaceProtection{ClusterID: f.input.ControlClusterID, Digest: f.qualification.NamespaceGuards[0].Digest, Keys: []string{"team"}, ObservedAt: n, FreshUntil: until}
	workload := capacityNativeWorkload(f.input.ControlClusterID, f.namespace, f.workloads[index], n, until)
	o, _, err := app.ComposeEnrollmentObservation(source, guard, workload, permissions, recovery, f.input.AccountVersion, time.Now())
	if err != nil {
		t.Fatal("composed exact workload observation", err)
	}
	return o
}
