package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"strconv"
	"strings"
	"sync"
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
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// capacityFixtureInput names the fixture installation's capacity scope.
type capacityFixtureInput struct {
	InstallationID, PermissionRootID, ControlClusterID, ControlNamespaceUID, AccountVersion string
}

// capacityRoot is the applied root: the standing date and revision 1 that
// capacity_apply writes for capture and processing backing.
type capacityRoot struct {
	PlannedUntil time.Time
	Revision     int64
}

// capacityEnrollment is one on-demand enrolled workload account.
type capacityEnrollment struct {
	AllocationID, DownloadAllocationID string
}

var capacityStanding = time.Date(9970, 1, 1, 0, 0, 0, 0, time.UTC)

type capacitySQLFixture struct {
	fleetRefreshMu   sync.Mutex
	ctx              context.Context
	admin            *pgxpool.Pool
	root             *capacitySQLRoot
	producer         *postgres.PublicRuntimeSQLRoles
	input            capacityFixtureInput
	qualification    app.CapacityQualification
	values           app.CapacityValues
	permission       *postgres.Permissions
	batch            cfg.PermissionBatch
	observer         *postgres.FleetObservation
	administration   fleet.Administration
	roles            map[string]*pgxpool.Pool
	accounts         *auditapp.OperationMAC
	namespace        cfg.NamespaceRef
	workloads        []cfg.WorkloadRef
	legacy           *postgres.Ledger
	registered       map[string]artifact.Registration
	fixturePool      func(string, string) *pgxpool.Pool
	store            *objectstore.Store
	authority        *objectstore.AuthorityObjects
	keys             authorityTestKeys
	processingPolicy privacy.DownloadPolicy
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
	// SeedInstallation (Helm-native setup) records no initial activation; the
	// role producer still requires one for its installation claim.
	if _, e := admin.Exec(ctx, `INSERT INTO fleet_initial_activation(installation_id,claim_id,record_json,audit_receipt_json,activated_at) VALUES($1,$2,'{}','{}',clock_timestamp()) ON CONFLICT DO NOTHING`, scope.InstallationID, claim); e != nil {
		t.Fatal("fixture initial activation", e)
	}
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
	f.qualification, f.values = capacityNativeQualification(t, rootID, scope.InstallationID, scope.ClusterID, f.root.value.State.MAC.AccountVersion), capacityNativeValues()
	for _, option := range configure {
		option(f)
	}
	f.processingPolicy = capacityNativeProcessingPolicy(f.qualification, scope.IssuerEpoch)
	f.input = capacityFixtureInput{InstallationID: scope.InstallationID, PermissionRootID: rootID, ControlClusterID: scope.ClusterID, ControlNamespaceUID: scope.NamespaceUID, AccountVersion: f.root.value.State.MAC.AccountVersion}
	material := f.root.value.State.MAC
	f.accounts, err = auditapp.NewOperationMAC(material.InputVersion, material.InputKey, material.AccountVersion, material.AccountKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.accounts.Close)
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
	f.fleetRefreshMu.Lock()
	defer f.fleetRefreshMu.Unlock()
	basis := fleetBasisFixture(t, f.ctx, f.observer)
	a := f.administration
	a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	a.FreshUntil = a.ObservedAt.Add(5 * time.Second)
	if err := f.observer.ObserveAdministration(f.ctx, basis, a); err != nil {
		t.Fatal("current original fleet source", err)
	}
}

// keepFleetCurrent renews the fixture's fleet observation every second until
// stopped; it returns the first renewal failure.
func (f *capacitySQLFixture) keepFleetCurrent() func() error {
	return keepFixtureFleetCurrent(f.ctx, f.observer, f.administration, &f.fleetRefreshMu)
}

func keepFixtureFleetCurrent(ctx context.Context, observer *postgres.FleetObservation, administration fleet.Administration, serialized ...*sync.Mutex) func() error {
	var refreshMu *sync.Mutex
	if len(serialized) > 0 {
		refreshMu = serialized[0]
	}
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
				err := func() error {
					if refreshMu != nil {
						refreshMu.Lock()
						defer refreshMu.Unlock()
					}
					// One fixture producer owns basis, observation clock and persistence.
					// Sampling outside this lock could backdate against the other refresher.
					b, err := observer.ReadAdministrationBasis(ctx)
					if err != nil {
						return err
					}
					a := administration
					a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
					a.FreshUntil = a.ObservedAt.Add(5 * time.Second)
					return observer.ObserveAdministration(ctx, b, a)
				}()
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

// setup applies the fixture capacity values and enrolls the first workload.
func (f *capacitySQLFixture) setup(t *testing.T) (capacityRoot, capacityEnrollment) {
	t.Helper()
	f.refreshBase(t)
	if _, err := postgres.ApplyCapacity(f.ctx, f.roles["capacity"], f.input.ControlClusterID, f.input.ControlNamespaceUID, f.qualification, f.values); err != nil {
		t.Fatal("actual capacity apply", err)
	}
	return capacityRoot{PlannedUntil: capacityStanding, Revision: 1}, f.enroll(t, f.input.ControlClusterID, f.namespace, f.workloads[0])
}

// enroll reads the workload's storage once under the enrolling metadata
// login, which creates its account on first use.
func (f *capacitySQLFixture) enroll(t *testing.T, cluster string, namespace cfg.NamespaceRef, workload cfg.WorkloadRef) capacityEnrollment {
	t.Helper()
	reader, err := postgres.NewContextStorageReader(f.ctx, f.roles["hub-metadata-read"], f.input.PermissionRootID)
	if err != nil {
		t.Fatal(err)
	}
	o, err := reader.WithEnrollment(f.input.InstallationID, f.accounts).ContextStorage(f.ctx, capacityNativeStorageTarget(cluster, namespace, workload))
	if err != nil {
		t.Fatal("on-demand capacity enrollment", err)
	}
	e := capacityEnrollment{AllocationID: o.Selection.AllocationID}
	if err = f.admin.QueryRow(f.ctx, `SELECT download_allocation_id::text FROM capacity_account WHERE allocation_id=$1`, e.AllocationID).Scan(&e.DownloadAllocationID); err != nil {
		t.Fatal("enrolled capacity account", err)
	}
	return e
}

// recoveryState reads the current recovery proof through the peer reader.
func (f *capacitySQLFixture) recoveryState(t *testing.T) artifact.RecoveryProof {
	t.Helper()
	reader, err := postgres.NewRecoveryReader(f.ctx, f.fixturePool("peer_read_runtime", "synthetic-peer-read"), f.input.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := reader.RecoveryState(f.ctx)
	if err != nil {
		t.Fatal("actual recovery read", err)
	}
	return proof
}

// fund raises the per-workload share to at least bytes, keeping the burst
// limit and evidence size above it for every fixture workload.
func (f *capacitySQLFixture) fund(bytes int64) {
	f.values.ShareBytes = max(f.values.ShareBytes, bytes)
	f.values.LimitBytes = max(f.values.LimitBytes, 4*f.values.ShareBytes)
	f.values.EvidenceBytes = max(f.values.EvidenceBytes, f.values.ReserveBytes+capacityNativeAccounts*f.values.ShareBytes)
}
