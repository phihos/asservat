package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgconn"
)

// Actual generated role70 reads the existing current owner graph. Configuration,
// enrollment, encrypted object audit and activation use the existing separate
// fixture effect roles. Original Kubernetes pool/process proof and fixture CA
// are synthetic. This is SQL role qualification, not installed TLS/Ready proof.
func (f *capacitySQLFixture) checkCapacityOwnerRegistry(t *testing.T) {
	t.Helper()
	ctx := f.ctx
	// Fixture provisioning is separate from every current-read assertion below.
	// No root/workload capacity observation has started when this helper runs.
	setup, stopSetup := context.WithTimeout(ctx, 30*time.Second)
	defer stopSetup()
	setupStarted := time.Now()
	in := f.root.value.State.Input
	ca, key := connectorSQLCA(t)
	c := value.OwnerConfiguration{Pool: value.OwnerPool{InstallationID: in.InstallationID, ClusterID: in.ClusterID, IssuerEpoch: f.administration.IssuerEpoch,
		Namespace: in.Namespace.Name, NamespaceUID: in.Namespace.UID, Service: "synthetic-owner", ServiceUID: custodyID(), Deployment: "synthetic-owner", DeploymentUID: custodyID(), ServiceAccount: "synthetic-owner", AccountUID: custodyID(), Port: 9443, NativePort: 9444},
		Revision: identity.Revision{UID: in.OwnerConfigurationUID, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{ca.Raw}}
	if !c.Valid() {
		t.Fatal("synthetic original owner scope invalid")
	}
	l := &ownerConfigLab{admin: f.admin, writerPool: f.fixturePool("owner_configuration_runtime", "synthetic-owner-configuration"), ackPool: f.fixturePool("owner_configuration_audit_runtime", "synthetic-owner-configuration-audit"), readerPool: f.roles["capacity"], audit: &objectstore.OwnerConfigurationAuditObjects{Store: f.store, Seal: f.keys, Open: f.keys}}
	var err error
	l.observation, err = readSyntheticFleetObservationBinding(setup, f.admin, in.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	l.writer, err = postgres.NewOwnerConfigurations(setup, l.writerPool, in.InstallationID, in.ClusterID, in.Namespace.UID, in.OwnerConfigurationUID)
	if err != nil {
		t.Fatal("fixture owner configuration writer", err)
	}
	l.ack, err = postgres.NewOwnerConfigurations(setup, l.ackPool, in.InstallationID, in.ClusterID, in.Namespace.UID, in.OwnerConfigurationUID)
	if err != nil {
		t.Fatal("fixture owner configuration acknowledgement", err)
	}
	l.reader, err = postgres.NewOwnerConfigurations(setup, l.readerPool, in.InstallationID, in.ClusterID, in.Namespace.UID, in.OwnerConfigurationUID)
	if err != nil {
		t.Fatal("actual capacity owner configuration reader", err)
	}
	s := newContextStartOwnerSQL(t, setup, l, c, contextStartOwnerIssuer{ca: ca, key: key})
	defer s.closeEffects()
	s.reader, err = postgres.NewOwnerEnrollments(setup, f.roles["capacity"], in.InstallationID, in.ClusterID, in.Namespace.UID, in.OwnerConfigurationUID, custodyID)
	if err != nil {
		t.Fatal("actual capacity owner registry constructor", err)
	}
	if _, err = s.refresh(setup, 5*time.Second); err != nil {
		t.Fatal("fixture owner source acceptance/audit", err)
	}
	stopSetup()
	t.Logf("owner_configuration_setup_ms=%d", time.Since(setupStarted).Milliseconds())
	refresh := func(t *testing.T) {
		t.Helper()
		observe, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		if _, e := s.refresh(observe, 5*time.Second); e != nil {
			t.Fatal("current original fixture owner source observation", e)
		}
	}
	read := func(t *testing.T, want int) value.APIContextOwnerCandidates {
		t.Helper()
		refresh(t)
		call, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		original, _ := call.Deadline()
		started := time.Now()
		candidates, e := s.reader.ReadContextStartOwners(call)
		if e != nil || call.Err() != nil || !candidates.Valid(time.Now()) || candidates.ValidUntil.After(original) || candidates.Pool != c.Pool || len(candidates.Owners) != want {
			t.Fatal("actual role70 current candidate read", e)
		}
		t.Logf("owner_candidates_read_ms=%d original_remaining_ms=%d count=%d", time.Since(started).Milliseconds(), time.Until(original).Milliseconds(), len(candidates.Owners))
		return candidates
	}
	if !t.Run("role70-empty-current-owner-candidates", func(t *testing.T) { read(t, 0) }) {
		return
	}
	binding := value.OwnerBinding{InstallationID: in.InstallationID, ClusterID: in.ClusterID, IssuerEpoch: c.Pool.IssuerEpoch, PodUID: custodyID(), ProcessEpoch: custodyID()}
	// The enrollment coordinator obtains fresh original five-second proofs for
	// its own bounded phases; this outer fixture ceiling extends none of them.
	enrollment, stopEnrollment := context.WithTimeout(ctx, 30*time.Second)
	enrollmentStarted := time.Now()
	issued, err := s.coordinator().Enroll(enrollment, value.OwnerEnrollmentRequest{Binding: binding, Usage: "server", CSRDER: connectorSQLCSR(t)})
	stopEnrollment()
	if err != nil {
		t.Fatal("independent fixture owner activation", err)
	}
	t.Logf("owner_enrollment_setup_ms=%d", time.Since(enrollmentStarted).Milliseconds())
	if !t.Run("role70-exact-current-owner-candidates", func(t *testing.T) {
		if candidates := read(t, 1); candidates.Owners[0] != binding {
			t.Fatal("actual owner candidates changed registered identity")
		}
	}) {
		return
	}
	if !t.Run("role70-exact-active-leaf-registration", func(t *testing.T) {
		refresh(t)
		call, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		started := time.Now()
		registration, e := s.reader.ReadOwnerRegistration(call, issued.Certificate)
		if e != nil || call.Err() != nil || !registration.Valid(time.Now()) || registration.Certificate != issued.Certificate || registration.Enrollment.Binding != binding {
			t.Fatal("actual role70 exact leaf registration read", e)
		}
		original, _ := call.Deadline()
		t.Logf("owner_registration_read_ms=%d original_remaining_ms=%d", time.Since(started).Milliseconds(), time.Until(original).Milliseconds())
	}) {
		return
	}
	for purpose, queries := range map[string][]string{
		"capacity":         {"INSERT INTO hub_owner_enrollment SELECT * FROM hub_owner_enrollment WHERE false", "UPDATE hub_owner_enrollment SET retired_at=clock_timestamp() WHERE false", "UPDATE hub_owner_certificate SET activated_at=clock_timestamp() WHERE false", "UPDATE hub_owner_configuration SET fresh_until=fresh_until WHERE false"},
		"capacity-capture": {"SELECT * FROM hub_owner_configuration LIMIT 0", "SELECT * FROM hub_owner_enrollment LIMIT 0", "SELECT * FROM hub_owner_certificate LIMIT 0"},
	} {
		if !t.Run(purpose+"-owner-purpose-denials", func(t *testing.T) {
			call, stop := context.WithTimeout(ctx, 5*time.Second)
			defer stop()
			for _, query := range queries {
				_, e := f.roles[purpose].Exec(call, query)
				var sql *pgconn.PgError
				if !errors.As(e, &sql) || sql.Code != "42501" {
					t.Fatalf("unexpected owner effect/read privilege purpose=%s sqlstate=%s", purpose, capacitySQLState(e))
				}
			}
		}) {
			return
		}
	}
	if !t.Run("role70-original-source-replacement-denied", func(t *testing.T) {
		refresh(t)
		call, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		wrong, e := postgres.NewOwnerEnrollments(call, f.roles["capacity"], in.InstallationID, in.ClusterID, in.Namespace.UID, custodyID(), custodyID)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = wrong.ReadContextStartOwners(call); e == nil || call.Err() != nil {
			t.Fatal("wrong original owner source did not fail while current", e)
		}
	}) {
		return
	}
	t.Run("original-owner-read-deadline-after-lock", func(t *testing.T) {
		refresh(t)
		tx, e := f.admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		var source string
		if e = tx.QueryRow(ctx, "SELECT source_uid::text FROM hub_owner_configuration WHERE installation_id=$1 AND cluster_id=$2 FOR UPDATE", in.InstallationID, in.ClusterID).Scan(&source); e != nil || source != in.OwnerConfigurationUID {
			t.Fatal("original owner lock", e)
		}
		call, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
		defer cancel()
		result := make(chan error, 1)
		joined := make(chan struct{})
		defer func() { cancel(); <-joined }()
		go func() { defer close(joined); _, e := s.reader.ReadContextStartOwners(call); result <- e }()
		f.waitBlocked(t, f.roles["capacity"].Config().ConnConfig.User, call)
		select {
		case e = <-result:
			if e == nil || !errors.Is(call.Err(), context.DeadlineExceeded) {
				t.Fatal("owner lock did not preserve the original assertion deadline", e)
			}
		case <-ctx.Done():
			t.Fatal("owner read did not join")
		}
	})
	if t.Failed() {
		t.FailNow()
	}
	f.refreshBase(t)
}
