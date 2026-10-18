package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5/pgxpool"
)

// initialBootstrapProcess is one finite trusted phase. Its actual Kubernetes
// seed and SQL facets retain original effect identities/deadlines across runs;
// a new process budget does not renew any of them.
type initialBootstrapProcess struct {
	root             context.Context
	cancel           context.CancelFunc
	inputs           *providerInputs
	producer         *kube.InitialBootstrap
	files            *bootstrapProjectionFiles
	state            contracts.InitialBootstrapState
	passiveCompleted bool
	passiveHistory   *kube.InitialBootstrapPassiveRead
}

func newInitialBootstrapProcess(ctx context.Context, input, output *os.Root, creation bool) (_ *initialBootstrapProcess, err error) {
	if ctx == nil || ctx.Err() != nil || input == nil || output == nil || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	root, cancel := context.WithTimeout(ctx, 2*time.Minute)
	d := &initialBootstrapProcess{root: root, cancel: cancel}
	complete := false
	defer func() {
		if !complete {
			d.Close()
		}
	}()
	desired, err := readInitialBootstrapDesired(root, input)
	if err != nil || desired.Format != contracts.InitialBootstrapFormat && !contracts.InitialBootstrapHasPassiveHistory(desired.Format) {
		return nil, mounts.ErrUnavailable
	}
	// This internal persisted capability is installer-selected. Operators do
	// not author dynamic replay pins or choose a weaker completed path.
	d.inputs = &providerInputs{files: input, kubernetesEndpoint: desired.Kubernetes, postgresEndpoint: desired.Postgres}
	d.producer, err = kube.OpenInitialBootstrap(root, d.inputs.kubernetes("administrator-token"), desired)
	if err != nil {
		return nil, err
	}
	d.files, err = openBootstrapProjectionFiles(output)
	if err != nil {
		return nil, err
	}
	passive, err := d.producer.ReadPassiveHistory(root)
	if err != nil {
		return nil, err
	}
	if passive != nil {
		d.passiveHistory = passive
		if err = d.projectPassive(passive); err != nil {
			return nil, err
		}
		files, openErr := d.files.root.OpenRoot("preparer")
		if openErr != nil {
			return nil, mounts.ErrUnavailable
		}
		p, c, in, observer, openErr := initialBootstrapPreparer(root, files)
		if openErr != nil {
			files.Close()
			return nil, openErr
		}
		done, readErr := initialBootstrapCompleted(root, p, c, files)
		p.Close()
		observer.Close()
		in.closeHTTP()
		files.Close()
		if readErr != nil {
			return nil, readErr
		}
		if done && (creation || passive.ManagerRetired) {
			d.passiveCompleted = true
			complete = true
			return d, nil
		}
		if passive.ManagerRetired || !creation && !done {
			return nil, mounts.ErrUnavailable
		}
	} else if !creation {
		return nil, mounts.ErrUnavailable
	}
	// Existing protected state is checked before any supplied provider material
	// or SQL credential is opened. Only exact first-creation absence requests
	// private source data; all other failure classes stop the phase.
	for {
		d.state, err = d.producer.Open(root, nil)
		if errors.Is(err, kube.ErrInitialBootstrapMaterialRequired) && creation {
			b, readErr := mounts.Read(root, input, "provider-material.json", 8192)
			if readErr != nil {
				return nil, mounts.ErrUnavailable
			}
			material, decodeErr := contracts.DecodeInitialBootstrapMaterial(bytes.NewReader(b))
			clear(b)
			if decodeErr != nil || len(material.RegistryConfig) != 0 {
				return nil, mounts.ErrUnavailable
			}
			// Only original fresh admission consumes this separate explicit
			// registry input. Completed replay never opens or copies it.
			if desired.RegistryAuthentication != "" {
				if desired.RegistryAuthentication != contracts.InitialRegistryAuthentication {
					return nil, mounts.ErrUnavailable
				}
				supplied, registryErr := mounts.Read(root, input, ".dockerconfigjson", contracts.InitialRegistryMaxBytes)
				if registryErr != nil {
					return nil, mounts.ErrUnavailable
				}
				material.RegistryConfig, registryErr = providerconfig.NormalizeInitialRegistry(desired.Image, supplied)
				clear(supplied)
				if registryErr != nil {
					return nil, registryErr
				}
			}
			d.state, err = d.producer.Open(root, &material)
			clear(material.RegistryConfig)
		}
		if !errors.Is(err, kube.ErrInitialPreparationPolicyPending) {
			break
		}
		if err = waitInitialBootstrapPolicy(root); err != nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	complete = true
	return d, nil
}

func (d *initialBootstrapProcess) projectPassive(p *kube.InitialBootstrapPassiveRead) error {
	if p == nil || !time.Now().Before(p.ValidUntil) {
		return mounts.ErrUnavailable
	}
	ctx, end := context.WithDeadline(d.root, p.ValidUntil)
	defer end()
	administrator, err := d.inputs.token("administrator-token")(ctx)
	if err != nil {
		return err
	}
	defer clear(administrator)
	return d.files.common(ctx, p.Bundle.Configuration, p.Bundle.Observation, administrator, p.Bundle.History)
}
func (d *initialBootstrapProcess) Close() {
	if d == nil {
		return
	}
	if d.cancel != nil {
		d.cancel()
	}
	if d.producer != nil {
		d.producer.Close()
	}
	if d.inputs != nil {
		d.inputs.closeHTTP()
	}
	if d.files != nil {
		d.files.Close()
	}
}
func waitInitialBootstrapPolicy(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return mounts.ErrUnavailable
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

func (d *initialBootstrapProcess) projection() (contracts.InitialPreparer, error) {
	var zero contracts.InitialPreparer
	for {
		c, ready, err := d.producer.PrepareProjection(d.root)
		if errors.Is(err, kube.ErrInitialPreparationPolicyPending) {
			if err = waitInitialBootstrapPolicy(d.root); err != nil {
				return zero, err
			}
			continue
		}
		if err != nil {
			return zero, err
		}
		if ready {
			return c, nil
		}
		// At most nine fixed original creates/receipt writes are advanced. A
		// missing or uncertain create never retries automatically in the adapter.
		if d.root.Err() != nil {
			return zero, mounts.ErrUnavailable
		}
	}
}

func (d *initialBootstrapProcess) projectCommon(c contracts.InitialPreparer) error {
	state, until, err := d.producer.ReadBootstrapSQLManager(d.root)
	if err != nil {
		return err
	}
	d.state = state
	ctx, end := context.WithDeadline(d.root, until)
	defer end()
	observation, err := d.producer.ObservationProjection(ctx)
	if err != nil {
		return err
	}
	administrator, err := d.inputs.token("administrator-token")(ctx)
	if err != nil {
		return err
	}
	defer clear(administrator)
	name, err := postgres.InitialSQLHistoryRoleName(state.InstallationID)
	if err != nil {
		return err
	}
	return d.files.common(ctx, c, observation, administrator, contracts.OwnerSQLCredential{Username: name, Password: state.Passwords.History})
}

// history obtains the exact existing passive reader under native protection.
// No setup SQL/provider file is consulted, even if the independent read fails.
func initialBootstrapHistory(ctx context.Context, files *os.Root, p *kube.InitialPreparer, c contracts.InitialPreparer) (*postgres.InitialInstallationReader, *pgxpool.Pool, error) {
	return initialBootstrapHistoryBounded(ctx, files, p, c, 0)
}

// A positive maximum narrows only this reader's pool, never the protected plan.
// The continuation reads once before runtime provisioning and needs one slot;
// other bootstrap phases retain the independently selected pool limit.
func initialBootstrapHistoryBounded(ctx context.Context, files *os.Root, p *kube.InitialPreparer, c contracts.InitialPreparer, maximum int32) (*postgres.InitialInstallationReader, *pgxpool.Pool, error) {
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	in := &providerInputs{files: files, postgresEndpoint: c.Services.Postgres}
	config, err := in.sqlConfig(ctx, "sql-history.json")
	if err != nil {
		return nil, nil, mounts.ErrUnavailable
	}
	if !postgres.ValidInitialSQLHistoryLogin(c.Plan.InstallationID, postgres.InitialSQLLogin{Username: config.ConnConfig.User, Password: config.ConnConfig.Password}) {
		return nil, nil, mounts.ErrUnavailable
	}
	if maximum > 0 {
		config.MaxConns = min(config.MaxConns, maximum)
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, nil, mounts.ErrUnavailable
	}
	complete := false
	defer func() {
		if !complete {
			pool.Close()
		}
	}()
	protection, err := p.NewHistoryProtection(ctx)
	if err != nil {
		return nil, nil, err
	}
	scope, plan := protection.Scope()
	if err = postgres.CheckInitialSQLHistoryRole(ctx, pool, scope.InstallationID, *c.Plan.HistoryManager); err != nil {
		return nil, nil, err
	}
	reader, err := postgres.NewInitialInstallationReader(ctx, pool, scope, plan, protection)
	if err != nil || ctx.Err() != nil {
		return nil, nil, mounts.ErrUnavailable
	}
	complete = true
	return reader, pool, nil
}

func initialBootstrapCompleted(ctx context.Context, p *kube.InitialPreparer, c contracts.InitialPreparer, files *os.Root) (bool, error) {
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	w, passive, err := p.ReadHandover(ctx)
	if err != nil {
		return false, err
	}
	if !passive || !p.HandoverCleanupComplete(w) {
		return false, nil
	}
	history, pool, err := initialBootstrapHistory(ctx, files, p, c)
	if err != nil {
		return false, err
	}
	defer pool.Close()
	observed, err := history.ObserveInitialInstallation(ctx)
	if err != nil || observed.Disposition != fleetapp.InitialInstallationActivated || observed.Record == nil || observed.Record.Claim.ID != w.Activation.Handover.Cleanup.ActivatedClaimID || ctx.Err() != nil || !time.Now().Before(observed.ValidUntil) {
		return false, mounts.ErrUnavailable
	}
	return true, nil
}

func (d *initialBootstrapProcess) prepare() error {
	if d.passiveCompleted {
		return d.files.removeMaintenance(d.root)
	}
	// Once the immutable projection exists, classify original handover/history
	// before opening a setup administrator or manager credential.
	if d.state.Projection == nil && (d.state.Manager == nil || d.state.Manager.Receipt == nil) {
		config, err := d.inputs.sqlConfig(d.root, "postgres-administrator.json")
		if err != nil {
			return err
		}
		manager, err := postgres.NewInitialSQLManager(d.root, config.ConnConfig, d.producer)
		if err != nil {
			return err
		}
		_, err = manager.Provision(d.root)
		manager.Close()
		if err != nil {
			return err
		}
	}
	c, err := d.projection()
	if err != nil {
		return err
	}
	if err = d.producer.PreparePassiveHistory(d.root); err != nil {
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
	if err != nil {
		return err
	}
	if completed {
		return d.files.removeMaintenance(d.root)
	}
	// Setup password projection is a fixed retained value, never new issuance.
	// Actual consumers authenticate and check original SQL/schema authority.
	m := d.state.Manager
	if m == nil || m.Receipt == nil || m.Closing != nil || m.RetiredAt != nil || d.state.Retired || !time.Now().Before(m.Until) {
		return mounts.ErrUnavailable
	}
	b, err := json.Marshal(contracts.OwnerSQLCredential{Username: m.Receipt.Name, Password: d.state.Passwords.Manager})
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer clear(b)
	return d.files.write(d.root, "preparer", "sql-maintenance.json", b)
}

func RunInitialBootstrap(ctx context.Context) error {
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
	d, err := newInitialBootstrapProcess(ctx, input, output, true)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.prepare()
}
