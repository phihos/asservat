package integration

import (
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"testing"
	"time"
)

// One fixed independently selected synthetic source, not a reader that refreshes
// time on access. SQL observation, original activation and bridge are actual.
type fixedContentionAdministration struct{ value fleet.Administration }

func (s fixedContentionAdministration) FleetAdministration(context.Context) (fleet.Administration, error) {
	return s.value, nil
}

type countedContentionProjection struct {
	actual               *postgres.FleetObservation
	fences               int
	lost                 *fleetObservationCommitLoss
	admin                *pgxpool.Pool
	expected             fleet.Administration
	committedBeforeFence bool
	basis                fleet.ObservationBasis
	fenceStarted         time.Time
}

func (p *countedContentionProjection) ReadAdministrationBasis(ctx context.Context) (fleet.ObservationBasis, error) {
	b, err := p.actual.ReadAdministrationBasis(ctx)
	p.basis = b
	return b, err
}
func (p *countedContentionProjection) ObserveAdministration(ctx context.Context, basis fleet.ObservationBasis, a fleet.Administration) error {
	return p.actual.ObserveAdministration(ctx, basis, a)
}
func (p *countedContentionProjection) FenceAdministration(ctx context.Context, basis fleet.ObservationBasis, started time.Time) error {
	p.fences++
	p.fenceStarted = started
	if p.lost != nil && p.lost.lost.Load() {
		// Read the committed actual row before applying the existing failure fence.
		// This is test evidence, never accepted authority or a retry of COMMIT.
		_ = p.admin.QueryRow(ctx, `SELECT NOT suspended AND observed_at=$2 AND fresh_until=$3 FROM public.fleet_current_trust WHERE installation_id=$1`, p.expected.InstallationID, p.expected.ObservedAt, p.expected.ObservedAt.Add(30*time.Second)).Scan(&p.committedBeforeFence)
	}
	return p.actual.FenceAdministration(ctx, basis, started)
}

func qualifyFleetObservationContention(t *testing.T, ctx context.Context, admin *pgxpool.Pool, config *pgx.ConnConfig, root *ownerIdentitySQLRoot, input contracts.OwnerIdentityRoles, observer *postgres.FleetObservation, a fleet.Administration, mode string, lostCommit *fleetObservationCommitLoss) {
	t.Helper()
	var recordRaw, receiptRaw []byte
	if err := admin.QueryRow(ctx, `SELECT record_json,audit_receipt_json FROM public.fleet_initial_activation WHERE installation_id=$1`, input.InstallationID).Scan(&recordRaw, &receiptRaw); err != nil {
		t.Fatal("original activation read", err)
	}
	var record audit.InitialInstallation
	var receipt audit.Receipt
	if json.Unmarshal(recordRaw, &record) != nil || json.Unmarshal(receiptRaw, &receipt) != nil || !record.Valid() || !receipt.ValidInitialInstallation(record.Scope.InstallationID, record.Claim.ID) {
		t.Fatal("original activation invalid")
	}
	if mode == "observation-contention-final-expired" {
		// Choose this finite original stored interval before either competing call.
		a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		a.FreshUntil = a.ObservedAt.Add(2 * time.Second)
		if e := observer.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, observer), a); e != nil {
			t.Fatal("short original stored interval", e)
		}
	}
	var err error
	var before string
	var until time.Time
	if err = admin.QueryRow(ctx, `SELECT to_jsonb(t)::text,t.fresh_until FROM public.fleet_current_trust t WHERE installation_id=$1`, input.InstallationID).Scan(&before, &until); err != nil {
		t.Fatal(err)
	}
	a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	a.FreshUntil = a.ObservedAt.Add(5 * time.Second)
	switch mode {
	case "observation-contention", "observation-unknown-commit", "observation-contention-final-change", "observation-contention-final-renewed", "observation-contention-final-recovery", "observation-contention-final-expired":
	case "observation-contention-changed":
		a.Revision.Generation++
	case "observation-contention-expired":
		a.FreshUntil = a.ObservedAt.Add(750 * time.Millisecond)
	default:
		t.Fatal("unknown contention mode")
	}
	p := &countedContentionProjection{actual: observer, lost: lostCommit, admin: admin, expected: a}
	o := app.TrustObserver{Settings: fixedContentionAdministration{a}, Projection: p, Now: time.Now}
	if mode == "observation-unknown-commit" {
		o.Settings = nativeStartedContentionAdministration{value: a, onRead: func(v fleet.Administration) { p.expected = v }}
	}
	var observed error
	if strings.HasPrefix(mode, "observation-contention-final-") {
		if lostCommit == nil {
			t.Fatal("missing exact lock-abort reply control")
		}
		observationCtx, cancel := context.WithDeadline(ctx, a.FreshUntil)
		defer cancel()
		result := make(chan error, 1)
		started, joined := false, false
		defer func() {
			lostCommit.release()
			if started && !joined {
				cancel()
				<-result
			}
		}()
		err = withFleetExclusiveFixture(ctx, admin, input.InstallationID, func(call context.Context) error {
			lostCommit.holdLock.Store(true)
			started = true
			// Independent observer lifetime: ending the bridge's actual callback does
			// not cancel this separately running original source observation.
			go func() { result <- o.Reconcile(observationCtx) }()
			select {
			case <-lostCommit.lockAborted:
				return nil
			case observed = <-result:
				joined = true
				return errors.New("observer returned before actual server lock abort")
			case <-call.Done():
				return call.Err()
			}
		})
		if err != nil {
			t.Fatal("original bridge lock-abort ordering", err)
		}
		switch mode {
		case "observation-contention-final-expired":
			timer := time.NewTimer(time.Until(until))
			select {
			case <-ctx.Done():
				timer.Stop()
				t.Fatal("fixture cancelled before original expiry")
			case <-timer.C:
			}
		case "observation-contention-final-change":
			_, err = admin.Exec(ctx, `UPDATE public.fleet_trust SET source_generation=source_generation+1 WHERE installation_id=$1`, input.InstallationID)
		case "observation-contention-final-recovery":
			_, err = admin.Exec(ctx, `UPDATE public.fleet_trust SET recovery_blocked=true WHERE installation_id=$1`, input.InstallationID)
		case "observation-contention-final-renewed":
			// An independently newer stored observation is a fixture mutation, not a
			// retry of the failed source. The existing failure CAS must leave it intact.
			_, err = admin.Exec(ctx, `WITH n AS MATERIALIZED(SELECT clock_timestamp() AS at) UPDATE public.fleet_observation SET observed_at=n.at,fresh_until=n.at+interval '5 seconds' FROM n WHERE installation_id=$1`, input.InstallationID)
		}
		if err != nil {
			t.Fatal("controlled post-abort row mutation", err)
		}
		if err = admin.QueryRow(ctx, `SELECT to_jsonb(t)::text FROM public.fleet_current_trust t WHERE installation_id=$1`, input.InstallationID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		lostCommit.release()
		observed = <-result
		joined = true
	} else if mode == "observation-unknown-commit" {
		if lostCommit == nil {
			t.Fatal("missing exact commit reply fault")
		}
		lostCommit.armed.Store(true)
		observed = o.Reconcile(ctx)
	} else if err = withFleetExclusiveFixture(ctx, admin, input.InstallationID, func(call context.Context) error { observed = o.Reconcile(call); return nil }); err != nil {
		t.Fatal("original bridge", err)
	}
	var after string
	if err = admin.QueryRow(ctx, `SELECT to_jsonb(t)::text FROM public.fleet_current_trust t WHERE installation_id=$1`, input.InstallationID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if mode == "observation-contention" {
		if !errors.Is(observed, fleet.ErrObservationPersistenceContended) || !errors.Is(observed, fleet.ErrUnavailable) || p.fences != 0 || before != after {
			t.Fatal("unchanged lock contention wrote/refreshed/fenced original SQL or reported success")
		}
		accepted, e := postgres.NewOwnerIdentitySQLRoles(ctx, config, root, input)
		if e != nil {
			t.Fatal("original unextended observation unavailable", e)
		}
		accepted.Close()
		// Only the retained original interval remains. No retry/refresh is made.
		timer := time.NewTimer(time.Until(until))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal("fixture cancelled")
		case <-timer.C:
		}
		denied, e := postgres.NewOwnerIdentitySQLRoles(ctx, config, root, input)
		if denied != nil {
			denied.Close()
		}
		if !errors.Is(e, cfg.ErrUnavailable) {
			t.Fatal("old deadline was extended", e)
		}
	} else if strings.HasPrefix(mode, "observation-contention-final-") {
		if observed == nil || errors.Is(observed, fleet.ErrObservationPersistenceContended) || p.fences != 1 {
			t.Fatal("post-abort change suppressed ordinary failure fence")
		}
		var suspended bool
		if err = admin.QueryRow(ctx, `SELECT suspended FROM public.fleet_current_trust WHERE installation_id=$1`, input.InstallationID).Scan(&suspended); err != nil {
			t.Fatal(err)
		}
		if mode == "observation-contention-final-renewed" || mode == "observation-contention-final-change" || mode == "observation-contention-final-recovery" {
			if before != after {
				t.Fatal("older failure overwrote newer observation or semantic version")
			}
		} else if !suspended {
			t.Fatal("same-version expired observation was not fenced")
		}
	} else if mode == "observation-unknown-commit" {
		if observed == nil || errors.Is(observed, fleet.ErrObservationPersistenceContended) || p.fences != 1 || !lostCommit.lost.Load() || !p.committedBeforeFence || !p.expected.ObservedAt.After(p.basis.ObservedAt) || !p.fenceStarted.Equal(p.expected.ObservedAt) {
			t.Fatal("unknown actual COMMIT suppressed fence or fixture did not commit")
		}
		var suspended bool
		if err = admin.QueryRow(ctx, `SELECT suspended FROM public.fleet_current_trust WHERE installation_id=$1`, input.InstallationID).Scan(&suspended); err != nil || !suspended {
			t.Fatal("unknown COMMIT failure fence missing", err)
		}
	} else {
		if observed == nil || errors.Is(observed, fleet.ErrObservationPersistenceContended) || p.fences != 1 {
			t.Fatal("changed/expired observation suppressed original fence")
		}
		// Its attempted fence competed with the same original bridge, so actual
		// successful persistence is checked only after that operation releases.
		if err = observer.FenceAdministration(ctx, fleetBasisFixture(t, ctx, observer), a.ObservedAt); err != nil {
			t.Fatal("post-operation exact failure fence", err)
		}
		var suspended bool
		if err = admin.QueryRow(ctx, `SELECT suspended FROM public.fleet_current_trust WHERE installation_id=$1`, input.InstallationID).Scan(&suspended); err != nil || !suspended {
			t.Fatal("negative source fence missing", err)
		}
	}
	if root.claims != 0 || root.receipts != 0 {
		t.Fatal("classification consumed owner role authority")
	}
}

// Unlike the historical fixed source above, this fixture samples native start
// inside Settings, after Reconcile and the actual SQL basis read have begun.
// Only the native source is synthetic; COMMIT loss and SQL fence are actual.
type nativeStartedContentionAdministration struct {
	value  fleet.Administration
	onRead func(fleet.Administration)
}

func (s nativeStartedContentionAdministration) FleetAdministration(context.Context) (fleet.Administration, error) {
	a := s.value
	a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	a.FreshUntil = a.ObservedAt.Add(5 * time.Second)
	s.onRead(a)
	return a, nil
}
