package bootstrap

import (
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"context"
	"errors"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
)

// retire runs in a separate ordered init process after initial-prepare has
// exited and joined its pools. Its current handover and SQL checks never treat
// a local phase marker or the seed Closing field as credential revocation.
func (d *initialBootstrapProcess) retire() error {
	if d.passiveCompleted {
		if err := d.files.removeMaintenance(d.root); err != nil {
			return err
		}
		if d.passiveHistory != nil && contracts.InitialBootstrapHasCopyClosure(d.passiveHistory.Bundle.Observation.Desired.Format) && !d.passiveHistory.Copies.CopiesClosed() {
			return d.retireCopies()
		}
		return nil
	}
	if d.state.Projection == nil || d.state.Manager == nil || d.state.Manager.Receipt == nil {
		return mounts.ErrUnavailable
	}
	c, err := d.projection()
	if err != nil {
		return err
	}
	if err = d.projectCommon(c); err != nil {
		return err
	}
	files, err := d.files.root.OpenRoot("preparer")
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer files.Close()
	p, _, in, observer, err := initialBootstrapPreparer(d.root, files)
	if err != nil {
		return err
	}
	defer in.closeHTTP()
	defer observer.Close()
	defer p.Close()
	completed, err := initialBootstrapCompleted(d.root, p, c, files)
	if err != nil || !completed {
		return mounts.ErrUnavailable
	}
	if err = d.files.removeMaintenance(d.root); err != nil {
		return err
	}
	// Fully retired replay is historical only. Do not reopen an expired or
	// absent SQL administrator credential merely to reproduce an old result.
	if d.state.Manager.RetiredAt != nil {
		// Another original retirement can commit after this process classified
		// the active path. V3 still owes copy closure; do not report full phase
		// success merely because the manager is now positively retired.
		if d.state.Prelude.CopyMarker != nil {
			history, pool, err := initialBootstrapHistory(d.root, files, p, c)
			if err != nil {
				return err
			}
			defer pool.Close()
			return d.advanceCopies(history)
		}
		return nil
	}
	history, pool, err := initialBootstrapHistory(d.root, files, p, c)
	if err != nil {
		return err
	}
	defer pool.Close()
	// The concrete seed independently checks complete native handover before
	// the original 30-second close claim. No new close ID after uncertainty.
	if _, err = d.producer.BeginManagerClose(d.root); err != nil {
		return err
	}
	config, err := d.inputs.sqlConfig(d.root, "postgres-administrator.json")
	if err != nil {
		return err
	}
	manager, err := postgres.NewInitialSQLManager(d.root, config.ConnConfig, d.producer)
	if err != nil {
		return err
	}
	defer manager.Close()
	at, err := manager.Retire(d.root, history)
	manager.Close() // Positive joined closure before any managed copy deletion.
	if err != nil {
		return err
	}
	// A fresh current root observation may acknowledge the original positive
	// SQL completion; it cannot change the original close interval or timestamp.
	claim, err := d.producer.BeginManagerClose(d.root)
	if err != nil {
		return err
	}
	if err = d.producer.CompleteManagerClose(d.root, claim, at); err != nil {
		return err
	}
	observed, err := history.ObserveInitialInstallation(d.root)
	if err != nil || observed.Disposition != fleetapp.InitialInstallationActivated || d.root.Err() != nil || !time.Now().Before(observed.ValidUntil) {
		return mounts.ErrUnavailable
	}
	if d.state.Prelude.CopyMarker != nil {
		return d.advanceCopies(history)
	}
	return nil
}

// A restarted copy-only phase opens only the original passive SQL reader and
// public observation pins. It never opens administrator SQL/provider inputs.
func (d *initialBootstrapProcess) retireCopies() error {
	if d.passiveHistory == nil || !d.passiveHistory.ManagerRetired {
		return mounts.ErrUnavailable
	}
	files, err := d.files.root.OpenRoot("preparer")
	if err != nil {
		return err
	}
	defer files.Close()
	p, c, in, observer, err := initialBootstrapPreparer(d.root, files)
	if err != nil {
		return err
	}
	defer in.closeHTTP()
	defer observer.Close()
	defer p.Close()
	done, err := initialBootstrapCompleted(d.root, p, c, files)
	if err != nil || !done {
		return mounts.ErrUnavailable
	}
	history, pool, err := initialBootstrapHistory(d.root, files, p, c)
	if err != nil {
		return err
	}
	defer pool.Close()
	return d.advanceCopies(history)
}
func (d *initialBootstrapProcess) advanceCopies(history fleetapp.InitialInstallationHistory) error {
	for {
		complete, err := d.producer.AdvanceManagedCopies(d.root, history)
		if errors.Is(err, kube.ErrInitialPreparationPolicyPending) {
			if err = waitInitialBootstrapPolicy(d.root); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if complete {
			return nil
		}
		if d.root.Err() != nil {
			return mounts.ErrUnavailable
		}
	}
}

func RunInitialBootstrapRetire(ctx context.Context) error {
	input, err := os.OpenRoot(InitialBootstrapRoot)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer input.Close()
	output, err := openInitialBootstrapProjectionRoot(ctx)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer output.Close()
	d, err := newInitialBootstrapProcess(ctx, input, output, false)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.retire()
}
