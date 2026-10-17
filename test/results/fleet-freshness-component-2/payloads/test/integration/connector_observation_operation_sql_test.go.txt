package integration

import (
	"context"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The source values below are deliberately synthetic, with one fixed original
// native interval. PostgreSQL, scoped SQL49 reads, enrolled/activated leaves,
// current recovery and encrypted S3 audit are real. This does not qualify a
// native observation producer, TLS channel, installed routing or availability.
type connectorOperationSQLSource struct {
	prototype value.ConnectorObservationOperationValue
	ordinals  []int
	deadlines []time.Time
	changeAt  int
}

func (s *connectorOperationSQLSource) ReadConnectorObservationValue(ctx context.Context, ordinal int) (value.ConnectorObservationOperationValue, error) {
	var zero value.ConnectorObservationOperationValue
	deadline, finite := ctx.Deadline()
	if ctx.Err() != nil || !finite || ordinal != len(s.ordinals)+1 {
		return zero, value.ErrUnavailable
	}
	s.ordinals = append(s.ordinals, ordinal)
	s.deadlines = append(s.deadlines, deadline)
	out := s.prototype.Clone()
	out.Native.Ordinal, out.Native.Final = ordinal, ordinal == 4
	out.Native.ValueObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	out.Native.Source.Observation.ObservedAt = out.Native.ValueObservedAt
	out.Native.Source.Observation.FreshUntil = identity.Earlier(out.Native.Source.Observation.FreshUntil, deadline)
	if ordinal == s.changeAt {
		out.Native.Source.Roles.Source += "_changed"
	}
	// Carry actual shortening into the next synthetic value; never reset it
	// from the request's longer original end or manufacture a new native proof.
	s.prototype.Native.Source.Observation.FreshUntil = out.Native.Source.Observation.FreshUntil
	return out, nil
}

func newConnectorOperationSQLSource(t *testing.T, f *connectorSQLFixture, leaf value.ConnectorCredentialCertificate) (value.ConnectorObservationPin, value.OwnerObservationRequest, *connectorOperationSQLSource) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	end := now.Add(4 * time.Second)
	profile := f.configuration.Source.Observation.Profile.Clone()
	pin := value.ConnectorObservationPin{Profile: profile, Roles: f.configuration.Source.Roles, TemplateDigest: artifact.Digest{71}, ImageDigest: artifact.Digest{72}, ProtectionDigest: artifact.Digest{73}}
	request := value.OwnerObservationRequest{RootID: profile.RootID, ID: custodyID(), Challenge: custodyID(), RequestedAt: now, NotAfter: end}
	source := f.configuration.Source
	source.Observation.Profile = source.Observation.Profile.Clone()
	source.Observation.ObservedAt, source.Observation.FreshUntil = now, end
	workload := value.ConnectorObservationWorkload{Process: f.request.Process, Pod: "synthetic-regional", ReplicaSetUID: custodyID(), TemplateDigest: pin.TemplateDigest, ImageDigest: pin.ImageDigest, ProtectionDigest: pin.ProtectionDigest, WorkloadDigest: artifact.Digest{74}, ObservedAt: now, FreshUntil: end}
	prototype := value.ConnectorObservationOperationValue{
		Native:    value.ConnectorObservationNativeValue{Request: request, Ordinal: 1, Source: source, Workload: workload, NativeStartedAt: now, NativeUntil: end, ValueObservedAt: now},
		BracketID: custodyID(), ConnectionBinding: artifact.Digest{75}, Certificate: leaf,
	}
	if !prototype.Matches(pin, request, 1, now) {
		t.Fatal("invalid explicitly synthetic operation source")
	}
	return pin, request, &connectorOperationSQLSource{prototype: prototype}
}

func qualifyConnectorObservationOperation(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T, int64) captureAdmissionScenario) {
	t.Run("connector-observation-operation", func(t *testing.T) {
		for _, mode := range []string{"both-pairs", "first-post-sql-source-change", "final-post-sql-source-change", "source-fence-between-pairs", "recovery-between-pairs", "database-incarnation-between-pairs", "sql-shortens-final-source", "original-deadline-during-sql-wait"} {
			t.Run(mode, func(t *testing.T) {
				f := newConnectorSQLFixture(t, ctx, admin, poolFor, store, keys, create(t, 1), 10800)
				leaf := f.issue(t, "client")
				// A process becomes serving only after both purpose-separated
				// leaves are activated; a client-only setup must remain denied.
				f.issue(t, "server")
				f.refresh(t)
				if _, err := f.registry.ConnectorLeafRegistration(ctx, leaf.Certificate); err != nil {
					t.Fatal("complete serving fixture before operation reads", err)
				}
				pin, request, source := newConnectorOperationSQLSource(t, f, leaf.Certificate)
				registry, err := postgres.NewConnectorObservationOperationRegistry(ctx, f.pools["read"], pin)
				if err != nil {
					t.Fatal("scoped SQL49 registry", err)
				}
				call, stop := context.WithDeadline(ctx, request.NotAfter)
				defer stop()
				read := func(ordinal int) (app.ConnectorObservationOperationRegistration, error) {
					return registry.ReadConnectorObservationOperation(call, request, source, leaf.Certificate, ordinal)
				}
				if mode == "original-deadline-during-sql-wait" {
					qualifyConnectorObservationSQLWait(t, ctx, f, registry, pin, request, source, leaf.Certificate)
					return
				}
				if mode == "first-post-sql-source-change" {
					source.changeAt = 2
					got, err := read(1)
					if err == nil || got.Last.BracketID != "" || got.Registration != (app.ConnectorLeafRegistration{}) || !reflect.DeepEqual(source.ordinals, []int{1, 2}) {
						t.Fatal("post-SQL source change disclosed registration", err, source.ordinals)
					}
					return
				}
				var sqlEnd time.Time
				if mode == "sql-shortens-final-source" {
					sqlEnd = time.Now().UTC().Truncate(time.Microsecond).Add(time.Second)
					if _, err = admin.Exec(ctx, "UPDATE fleet_observation SET fresh_until=$2 WHERE installation_id=$1", f.scenario.recovery.installation, sqlEnd); err != nil {
						t.Fatal("fixture shorten already accepted recovery observation", err)
					}
				}
				first, err := read(1)
				if err != nil || first.Last.Native.Ordinal != 2 || first.FinalMatches(pin, request, time.Now()) || first.Registration.Certificate != leaf.Certificate || first.Registration.Process != f.request.Process {
					t.Fatal("first real SQL pair must remain incomplete", err)
				}
				switch mode {
				case "source-fence-between-pairs":
					if err = f.source.FenceConnectorIdentity(ctx, pin.Profile.Binding, time.Now().UTC()); err != nil {
						t.Fatal("actual scoped source fence", err)
					}
				case "recovery-between-pairs":
					if _, err = admin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", f.scenario.recovery.installation); err != nil {
						t.Fatal("fixture recovery transition", err)
					}
				case "database-incarnation-between-pairs":
					if _, err = admin.Exec(ctx, "UPDATE fleet_trust SET activated_postmaster_at=activated_postmaster_at-interval '1 microsecond' WHERE installation_id=$1", f.scenario.recovery.installation); err != nil {
						t.Fatal("fixture changed accepted database incarnation", err)
					}
				case "final-post-sql-source-change":
					source.changeAt = 4
				}
				last, err := read(3)
				switch mode {
				case "source-fence-between-pairs", "recovery-between-pairs", "database-incarnation-between-pairs", "final-post-sql-source-change":
					want := []int{1, 2, 3}
					if mode == "final-post-sql-source-change" {
						want = append(want, 4)
					}
					if err == nil || last.Last.BracketID != "" || last.Registration != (app.ConnectorLeafRegistration{}) || !reflect.DeepEqual(source.ordinals, want) {
						t.Fatal("changed SQL/source authority returned final registration", err, source.ordinals)
					}
					return
				}
				if err != nil || !last.FinalMatches(pin, request, time.Now()) || !last.Last.Continues(first.Last) || !reflect.DeepEqual(source.ordinals, []int{1, 2, 3, 4}) {
					t.Fatal("two exact real SQL pairs did not preserve original operation", err, source.ordinals)
				}
				if mode == "sql-shortens-final-source" {
					if !first.Registration.FreshUntil.Equal(sqlEnd) || !last.Registration.FreshUntil.Equal(sqlEnd) || !source.deadlines[1].Equal(sqlEnd) || !source.deadlines[3].Equal(sqlEnd) {
						t.Fatal("SQL shortened deadline was lost before actual last source")
					}
				}
				// The original EXECUTE-only role does not acquire ambient row
				// reads or source/recovery writes through the new adapter.
				for _, query := range []string{"SELECT * FROM connector_identity_process LIMIT 1", "SELECT * FROM connector_identity_profile LIMIT 1", "UPDATE fleet_trust SET recovery_blocked=false", "SELECT fence_connector_identity(NULL,NULL,clock_timestamp())"} {
					if _, err = f.pools["read"].Exec(ctx, query); err == nil {
						t.Fatal("read role acquired unrelated authority", query)
					}
				}
			})
		}
	})
}

func qualifyConnectorObservationSQLWait(t *testing.T, ctx context.Context, f *connectorSQLFixture, registry *postgres.ConnectorObservationOperationRegistry, pin value.ConnectorObservationPin, request value.OwnerObservationRequest, source *connectorOperationSQLSource, leaf value.ConnectorCredentialCertificate) {
	t.Helper()
	blocker, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(ctx) }()
	if _, err = blocker.Exec(ctx, "LOCK TABLE connector_identity_root IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(750 * time.Millisecond)
	call, stop := context.WithDeadline(ctx, end)
	defer stop()
	type result struct {
		value app.ConnectorObservationOperationRegistration
		err   error
	}
	done := make(chan result, 1)
	go func() {
		got, err := registry.ReadConnectorObservationOperation(call, request, source, leaf, 1)
		done <- result{got, err}
	}()
	// Observe this role's actual lock wait, not an assumed delay. The locked
	// table belongs only to this disposable SQL fixture, never another lab.
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	blocked := false
	for !blocked && call.Err() == nil {
		if err = f.admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usename=$1 AND cardinality(pg_blocking_pids(pid))>0)", f.pools["read"].Config().ConnConfig.User).Scan(&blocked); err != nil {
			stop()
			<-done
			t.Fatal(err)
		}
		if !blocked {
			select {
			case <-ticker.C:
			case <-call.Done():
			}
		}
	}
	joined := time.NewTimer(3 * time.Second)
	defer joined.Stop()
	select {
	case got := <-done:
		if !blocked || got.err == nil || got.value.Last.BracketID != "" || got.value.Registration != (app.ConnectorLeafRegistration{}) || !reflect.DeepEqual(source.ordinals, []int{1}) || !source.deadlines[0].Equal(end) {
			t.Fatal("original deadline did not cancel an actual blocked SQL read", blocked, got.err, source.ordinals)
		}
	case <-joined.C:
		t.Fatal("cancelled SQL read did not join")
	}
	if err = blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	// A new request may read after cancellation; no previous final registration
	// is reused, and the existing scoped pool must recover without replacement.
	f.refresh(t)
	_, fresh, next := newConnectorOperationSQLSource(t, f, leaf)
	freshCall, cancel := context.WithDeadline(ctx, fresh.NotAfter)
	defer cancel()
	got, err := registry.ReadConnectorObservationOperation(freshCall, fresh, next, leaf, 1)
	if err != nil || got.FinalMatches(pin, fresh, time.Now()) || !reflect.DeepEqual(next.ordinals, []int{1, 2}) {
		t.Fatal("scoped reader failed a separate request after cancelled wait", err)
	}
}
