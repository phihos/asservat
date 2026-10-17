package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/apimachinery/pkg/util/validation"
)

const InitialPreparerRoot = "/run/asservat/initial-preparer"

// InitialPreparationDeployment is the finite declarative phase of the private
// installer. Its result is setup provenance only. The explicit private-state
// continuation can issue its original bounded probe token; it does not activate
// SQL, schedule the installation Pod or enable public collection.
type InitialPreparationDeployment struct {
	configuration  contracts.InitialPreparer
	root           context.Context
	cancel         context.CancelFunc
	once           sync.Once
	running        atomic.Bool
	inputs         *providerInputs
	preparer       *kube.InitialPreparer
	sqlMaterial    *contracts.WorkerObjectReference
	sqlPool        *pgxpool.Pool
	sqlRoles       *postgres.InitialSQLRoles
	providerIssuer *kms.InitialProviderIssuer
	historyPool    *pgxpool.Pool
	historyLogin   postgres.InitialSQLLogin
	history        *postgres.InitialInstallationReader
	passive        bool
	historical     fleetapp.InitialInstallationObservation
}

type initialPreparerLoadFailure struct {
	phase string
	cause error
}

func (e initialPreparerLoadFailure) Error() string {
	stage := "initial preparation loader " + e.phase + ": unavailable"
	if provider := kms.InitialProviderCheckStage(e.cause); provider != "" {
		stage += " (provider " + provider + ")"
	}
	return stage
}
func (e initialPreparerLoadFailure) Unwrap() error { return e.cause }

func NewInitialPreparationDeployment(ctx context.Context, files *os.Root) (*InitialPreparationDeployment, error) {
	return newInitialPreparationDeployment(ctx, files, nil)
}
func newInitialPreparationDeployment(ctx context.Context, files *os.Root, observer *kube.InitialBootstrapObserver) (_ *InitialPreparationDeployment, err error) {
	phase := "process-inputs"
	defer func() {
		if err != nil {
			err = initialPreparerLoadFailure{phase, err}
		}
	}()
	if ctx == nil || ctx.Err() != nil || files == nil || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	phase = "deployment-projection"
	raw, e := mounts.Read(ctx, files, "deployment.json", contracts.InitialPreparationMaxBytes)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	phase = "deployment-contract"
	c, e := contracts.DecodeInitialPreparer(bytes.NewReader(raw))
	if e != nil || c.Format != contracts.InitialPreparerFormat || c.Plan.PrivateState != nil && c.Services == nil {
		return nil, mounts.ErrUnavailable
	}
	if c.SQLMaterial != nil && (c.Plan.PrivateState == nil || c.Services == nil || !authorization.UUID(c.SQLMaterial.UID) || len(validation.IsDNS1123Subdomain(c.SQLMaterial.Name)) != 0 || c.SQLMaterial.Name == c.Plan.PrivateState.Name) {
		return nil, mounts.ErrUnavailable
	}
	if observer != nil && !observer.MatchesInitialPreparer(c) {
		return nil, mounts.ErrUnavailable
	}
	phase = "kubernetes-endpoint"
	h, e := ownerHTTP(c.Kubernetes.Endpoint, c.Kubernetes.Roots)
	if e != nil {
		return nil, mounts.ErrUnavailable
	}
	h.CloseIdleConnections()
	root, cancel := context.WithCancel(ctx)
	in := &providerInputs{files: files, kubernetesEndpoint: c.Kubernetes}
	d := &InitialPreparationDeployment{root: root, cancel: cancel, inputs: in, configuration: c}
	complete := false
	defer func() {
		if !complete {
			d.Close()
		}
	}()
	control := cfg.NamespaceRef{Name: c.Plan.BootstrapNamespace.Name, UID: c.Plan.BootstrapNamespace.UID}
	adminConfig, probeConfig := in.kubernetes("administrator-token"), in.kubernetes("probe-token")
	if observer != nil {
		probeConfig = in.kubernetesToken(observer.ReadToken)
	}
	admin, e := kube.NewPermissionClient(adminConfig, c.Plan.ClusterID, control, time.Now)
	if e != nil {
		return nil, e
	}
	probe, e := kube.NewPermissionClient(probeConfig, c.Plan.ClusterID, control, time.Now)
	if e != nil {
		return nil, e
	}
	phase = "native-preparer"
	d.preparer, e = kube.NewInitialPreparer(adminConfig, admin, probe, c)
	if e != nil {
		return nil, e
	}
	if d.preparer.HandoverEnabled() {
		phase = "history-credential-inputs"
		in.postgresEndpoint = c.Services.Postgres
		config, e := in.sqlConfig(root, "sql-history.json")
		if e != nil {
			return nil, e
		}
		d.historyLogin = postgres.InitialSQLLogin{Username: config.ConnConfig.User, Password: config.ConnConfig.Password}
		if !postgres.ValidInitialSQLHistoryLogin(c.Plan.InstallationID, d.historyLogin) {
			return nil, mounts.ErrUnavailable
		}
		d.historyPool, e = pgxpool.NewWithConfig(root, config)
		if e != nil {
			return nil, mounts.ErrUnavailable
		}
		phase = "handover-disposition"
		_, d.passive, e = d.preparer.ReadHandover(root)
		if e != nil {
			return nil, e
		}
		if d.passive {
			phase = "history-reader"
			if e = d.prepareHistory(root); e != nil {
				return nil, e
			}
			complete = true
			return d, nil
		}
	}
	if c.SQLMaterial != nil {
		material := *c.SQLMaterial
		d.sqlMaterial = &material
		reader, e := kube.NewInitialSQLMaterialReader(d.preparer, material)
		if e != nil {
			return nil, e
		}
		phase = "sql-material"
		if d.preparer.HandoverEnabled() {
			e = reader.CheckInitialSQLHistoryPassword(root, d.historyLogin.Password)
		} else {
			e = reader.CheckInitialSQLMaterial(root)
		}
		if e != nil {
			return nil, e
		}
		in.postgresEndpoint = c.Services.Postgres
		// The existing connection builder reads the fixed protected credential and
		// validates all local fields before any preparation mutation. This maintenance
		// connection is confined to this bootstrap and never projected into the Pod.
		phase = "sql-connection-inputs"
		config, e := in.sqlConfig(root, "sql-maintenance.json")
		if e != nil {
			return nil, e
		}
		phase = "schema-completion"
		if e = initialPreparationSchemaPreflight(root, c.Plan.SchemaInitialization, func(ctx context.Context) (time.Time, error) {
			_, until, err := postgres.VerifyInitialSchemaCompletion(ctx, config.ConnConfig, d.preparer)
			return until, err
		}, time.Now); e != nil {
			return nil, e
		}
		phase = "sql-pool"
		d.sqlPool, e = pgxpool.NewWithConfig(root, config)
		if e != nil {
			return nil, mounts.ErrUnavailable
		}
		phase = "sql-maintenance-scope"
		d.sqlRoles, e = postgres.NewInitialSQLRoles(root, d.sqlPool, c.Plan.InstallationID)
		if e != nil {
			return nil, e
		}
		if d.preparer.HandoverEnabled() {
			phase = "history-manager-identity"
			if e = d.sqlRoles.CheckHistoryManager(root, *c.Plan.HistoryManager); e != nil {
				return nil, e
			}
		}
	}
	if c.Providers != nil {
		phase = "provider-material"
		material, until, e := d.preparer.ReadInitialProviderMaterial(root)
		if e != nil {
			return nil, e
		}
		phase = "provider-endpoint"
		h, e := ownerHTTP(c.Services.KeyService.Endpoint, c.Services.KeyService.Roots)
		if e != nil {
			return nil, e
		}
		defer h.CloseIdleConnections()
		phase = "provider-constructor"
		d.providerIssuer, e = kms.NewInitialProviderIssuer(c.Services.KeyService.Endpoint, material.IssuerToken, c.Services.KeyService.AuditMount, c.Services.KeyService.AuditKey, c.Plan.InstallationID, c.Plan.RequestID, *c.Providers, h, time.Now)
		if e != nil {
			return nil, e
		}
		phase = "provider-preflight"
		bounded, done := context.WithDeadline(root, until)
		_, _, e = d.providerIssuer.Check(bounded, time.Now().Add(15*time.Minute))
		done()
		if e != nil {
			return nil, e
		}
	}
	phase = "final-cancellation"
	if root.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	complete = true
	return d, nil
}

// initialPreparerRunFailure carries only compiler-selected phase labels. The
// underlying cause remains available for errors.Is without rendering provider,
// Kubernetes, SQL, token or mounted content.
type initialPreparerRunFailure struct {
	phase string
	cause error
}

func (e initialPreparerRunFailure) Error() string {
	phase := e.phase
	var inner initialPreparerRunFailure
	if errors.As(e.cause, &inner) {
		phase += "/" + inner.phase
	}
	out := "initial preparation run " + phase + ": unavailable"
	if provider := kube.InitialPreparationProviderDiagnostic(e.cause); provider != "" {
		out += " (" + provider + ")"
	}
	if history := postgres.InitialSQLHistoryDiagnostic(e.cause); history != "" {
		out += " (" + history + ")"
	}
	return out
}
func (e initialPreparerRunFailure) Unwrap() error { return e.cause }

func (d *InitialPreparationDeployment) Run() (_ contracts.InitialPreparationRoot, err error) {
	phase := "run-inputs"
	defer func() {
		if err != nil {
			err = initialPreparerRunFailure{phase, err}
		}
	}()
	if d == nil || d.root == nil || d.cancel == nil || d.inputs == nil || d.preparer == nil || !d.running.CompareAndSwap(false, true) {
		return contracts.InitialPreparationRoot{}, mounts.ErrUnavailable
	}
	defer d.Close()
	// This is a process/run budget, not a durable root deadline. A later run uses
	// the same plan and journal; it never renews an issued credential or effect.
	budget := time.Minute
	if d.preparer.HandoverEnabled() {
		budget = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(d.root, budget)
	defer cancel()
	if d.passive {
		return d.continueHandover(ctx)
	}
	phase = "declare"
	out, e := d.preparer.Declare(ctx)
	if e == nil && d.preparer.ActivationPreparationEnabled() {
		phase = "gated-pod"
		out, e = d.preparer.PrepareGatedPod(ctx)
		if e == nil && d.preparer.FinalInputsEnabled() {
			phase = "final-inputs"
			for {
				out, e = d.preparer.PrepareFinalInputs(ctx)
				if !errors.Is(e, kube.ErrInitialPreparationPolicyPending) {
					break
				}
				// Only original policy readiness is polled automatically. Every call
				// reacquires current protection and resolves the existing journal entry.
				select {
				case <-ctx.Done():
					return contracts.InitialPreparationRoot{}, mounts.ErrUnavailable
				case <-time.After(50 * time.Millisecond):
				}
			}
		}
		if e == nil && d.preparer.PrivateInputsEnabled() && d.sqlMaterial == nil {
			phase = "probe"
			probe, err := d.preparer.PrepareProbe(ctx)
			clear(probe.Token)
			e = err
		}
		if e == nil && d.sqlMaterial != nil {
			phase = "sql-and-providers"
			e = d.prepareSQL(ctx)
		}
		if e == nil {
			phase = "request-drain"
			e = d.preparer.DrainPodCreateRequests(ctx)
		}
	}
	if e == nil && d.preparer.HandoverEnabled() {
		return d.continueHandover(ctx)
	}
	if e == nil && ctx.Err() != nil {
		phase = "final-cancellation"
		return contracts.InitialPreparationRoot{}, mounts.ErrUnavailable
	}
	return out, e
}
func (d *InitialPreparationDeployment) Close() {
	if d == nil {
		return
	}
	d.once.Do(func() {
		if d.cancel != nil {
			d.cancel()
		}
		if d.preparer != nil {
			d.preparer.Close()
		}
		if d.providerIssuer != nil {
			d.providerIssuer.Close()
		}
		if d.historyPool != nil {
			d.historyPool.Close()
		}
		if d.sqlPool != nil {
			d.sqlPool.Close()
		}
		if d.inputs != nil {
			d.inputs.closeHTTP()
		}
	})
}
func RunInitialPreparer(ctx context.Context) error {
	files, e := os.OpenRoot(InitialPreparerRoot)
	if e != nil {
		return mounts.ErrUnavailable
	}
	defer files.Close()
	d, e := NewInitialPreparationDeployment(ctx, files)
	if e != nil {
		return e
	}
	defer d.Close()
	_, e = d.Run()
	return e
}

// InitialPreparationRemedy is safe fixed CLI copy. Never append raw Kubernetes
// or provider errors, tokens, configuration bodies or request metadata.
func InitialPreparationRemedy(err error) string {
	switch {
	case errors.Is(err, providerconfig.ErrInitialRegistry):
		return providerconfig.ErrInitialRegistry.Error()
	case errors.Is(err, kube.ErrInitialPreparationRequestsUnresolved):
		return "setup retains an unresolved original Pod create: keep the saved installation and occupied Pod name; resume its original supervisor for completion or use qualified request recovery before removing it"
	case errors.Is(err, cfg.ErrChanged):
		return "setup differs from the saved installation: restore the original release inputs or requalify the changed protection; do not delete retained setup resources or edit journal UIDs"
	case errors.Is(err, cfg.ErrDenied):
		return "installation administration was denied: restore this release's preparation credential, then resume the same release and plan"
	case errors.Is(err, cfg.ErrInvalid):
		return "protected installation inputs are invalid: correct the release configuration without replacing its saved plan or journal"
	default:
		return "setup could not finish: any saved progress is retained; resume the same Helm release and plan when its protected inputs and Kubernetes API are available"
	}
}
