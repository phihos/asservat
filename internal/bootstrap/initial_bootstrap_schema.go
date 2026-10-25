package bootstrap

import (
	"bytes"
	"context"
	"os"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

const InitialBootstrapSchemaPrivateRoot = "/run/asservat/initial-schema-private"

// initialBootstrapSchemaSource is an internal testing seam. Production always
// constructs the concrete native preparer from the original fixed projection.
type initialBootstrapSchemaSource interface {
	ReadHandover(context.Context) (contracts.InitialPreparationRoot, bool, error)
	ReadInitialSchema(context.Context) (contracts.InitialPreparationRoot, time.Time, error)
	Open(context.Context) (contracts.InitialPreparationRoot, error)
}

// initialBootstrapSchemaNeeded makes a no-effect scheduling decision. A saved
// completion is not current SQL readiness: active preparation and final SQL
// effects independently verify its original database incarnation and bundle.
func initialBootstrapSchemaNeeded(ctx context.Context, source initialBootstrapSchemaSource, c contracts.InitialPreparer, bundle postgres.InitialSchemaBundle, now func() time.Time) (bool, error) {
	if ctx == nil || ctx.Err() != nil || source == nil || c.Plan.SchemaInitialization != contracts.InitialSchemaProtocol || c.Plan.HistoryManager == nil || bundle.Head < 1 || bundle.Digest == "" {
		return false, mounts.ErrUnavailable
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	first, handover, err := source.ReadHandover(ctx)
	if err != nil || ctx.Err() != nil {
		return false, mounts.ErrUnavailable
	}
	if first.RootUID == "" {
		if handover || c.RootUID != "" || first.Schema != nil || first.Activation != nil {
			return false, cfg.ErrChanged
		}
		// This is the existing guarded create-only root operation. It is never
		// called after an original root or immutable external UID is observed.
		first, err = source.Open(ctx)
		if err != nil || first.RootUID == "" || ctx.Err() != nil {
			return false, mounts.ErrUnavailable
		}
	}
	current, until, err := source.ReadInitialSchema(ctx)
	if err != nil || ctx.Err() != nil || !now().Before(until) || current.RootUID != first.RootUID || current.InstallationID != c.Plan.InstallationID || current.RequestID != c.Plan.RequestID || current.PlanDigest == "" || current.PlanDigest != first.PlanDigest {
		return false, cfg.ErrChanged
	}
	if current.Schema == nil {
		if first.Schema != nil || handover || len(current.Creates) != 0 || current.Activation != nil {
			return false, cfg.ErrChanged
		}
		return true, nil
	}
	schema := current.Schema
	if schema.BundleDigest != bundle.Digest || schema.Head != bundle.Head || schema.Manager != *c.Plan.HistoryManager || first.Schema != nil && !sameInitialBootstrapSchema(*first.Schema, *schema) {
		return false, cfg.ErrChanged
	}
	if schema.CompletedAt == nil {
		if handover || len(current.Creates) != 0 || current.Activation != nil {
			return false, cfg.ErrChanged
		}
		return true, nil
	}
	return false, nil
}

// Completion may advance between two current observations; none of the
// immutable original schema/SQL/manager fields may change or disappear.
func sameInitialBootstrapSchema(a, b contracts.InitialPreparationSchema) bool {
	aCompleted, bCompleted := a.CompletedAt, b.CompletedAt
	a.CompletedAt, b.CompletedAt = nil, nil
	return a == b && (aCompleted == nil || bCompleted != nil && aCompleted.Equal(*bCompleted))
}

// initialBootstrapObservation loads only generated public inputs and the
// administrator's current Kubernetes credential. Missing observation input
// denies; there is no legacy fixed-token or administrator-as-probe fallback.
func initialBootstrapObservation(ctx context.Context, files *os.Root) (contracts.InitialPreparer, *providerInputs, *kube.InitialBootstrapObserver, error) {
	return initialBootstrapObservationTokens(ctx, files, files)
}

// initialBootstrapObservationTokens reads Kubernetes tokens from a separate
// root: a long-running caller uses its own kubelet-rotated projection instead
// of the one-time copy in the preparer projection.
func initialBootstrapObservationTokens(ctx context.Context, files, tokens *os.Root) (contracts.InitialPreparer, *providerInputs, *kube.InitialBootstrapObserver, error) {
	var zero contracts.InitialPreparer
	if ctx == nil || ctx.Err() != nil || files == nil {
		return zero, nil, nil, mounts.ErrUnavailable
	}
	raw, err := mounts.Read(ctx, files, "deployment.json", contracts.InitialPreparationMaxBytes)
	if err != nil {
		return zero, nil, nil, mounts.ErrUnavailable
	}
	defer clear(raw)
	c, err := contracts.DecodeInitialPreparer(bytes.NewReader(raw))
	if err != nil || c.Plan.SchemaInitialization != contracts.InitialSchemaProtocol || c.Plan.HistoryManager == nil || c.Services == nil {
		return zero, nil, nil, mounts.ErrUnavailable
	}
	observed, err := mounts.Read(ctx, files, "observation.json", contracts.InitialBootstrapObservationMaxBytes)
	if err != nil {
		return zero, nil, nil, mounts.ErrUnavailable
	}
	v, err := contracts.DecodeInitialBootstrapObservation(bytes.NewReader(observed))
	if err != nil {
		return zero, nil, nil, mounts.ErrUnavailable
	}
	in := &providerInputs{oneShot: true, files: tokens, kubernetesEndpoint: c.Kubernetes, postgresEndpoint: c.Services.Postgres}
	observer, err := kube.NewInitialBootstrapObserver(ctx, in.kubernetes("administrator-token"), v, c)
	if err != nil {
		in.closeHTTP()
		return zero, nil, nil, mounts.ErrUnavailable
	}
	return c, in, observer, nil
}
func initialBootstrapPreparer(ctx context.Context, files *os.Root) (*kube.InitialPreparer, contracts.InitialPreparer, *providerInputs, *kube.InitialBootstrapObserver, error) {
	return initialBootstrapPreparerTokens(ctx, files, files)
}

func initialBootstrapPreparerTokens(ctx context.Context, files, tokens *os.Root) (*kube.InitialPreparer, contracts.InitialPreparer, *providerInputs, *kube.InitialBootstrapObserver, error) {
	var zero contracts.InitialPreparer
	c, in, observer, err := initialBootstrapObservationTokens(ctx, files, tokens)
	if err != nil {
		return nil, zero, nil, nil, err
	}
	complete := false
	defer func() {
		if !complete {
			observer.Close()
			in.closeHTTP()
		}
	}()
	ns := cfg.NamespaceRef{Name: c.Plan.BootstrapNamespace.Name, UID: c.Plan.BootstrapNamespace.UID}
	adminConfig := in.kubernetes("administrator-token")
	admin, err := kube.NewPermissionClient(adminConfig, c.Plan.ClusterID, ns, time.Now)
	if err != nil {
		return nil, zero, nil, nil, err
	}
	probe, err := kube.NewPermissionClient(in.kubernetesToken(observer.ReadToken), c.Plan.ClusterID, ns, time.Now)
	if err != nil {
		return nil, zero, nil, nil, err
	}
	preparer, err := kube.NewInitialPreparer(adminConfig, admin, probe, c)
	if err != nil {
		return nil, zero, nil, nil, err
	}
	complete = true
	return preparer, c, in, observer, nil
}

// RunInitialBootstrapSchema opens no setup credential until current native
// protection establishes that the original embedded schema needs work. A
// completed whole installation or interrupted post-schema preparation therefore
// skips DDL without opening the retired setup manager or provider inputs.
func RunInitialBootstrapSchema(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || disableWorkerCoreDumps() != nil {
		return mounts.ErrUnavailable
	}
	files, err := os.OpenRoot(InitialSchemaRoot)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer files.Close()
	phase, end := context.WithTimeout(ctx, 15*time.Minute)
	defer end()
	p, c, in, observer, err := initialBootstrapPreparer(phase, files)
	if err != nil {
		return err
	}
	defer in.closeHTTP()
	defer observer.Close()
	defer p.Close()
	bundle, err := postgres.EmbeddedInitialSchema()
	if err != nil {
		return err
	}
	needed, err := initialBootstrapSchemaNeeded(phase, p, c, bundle, time.Now)
	if err != nil || !needed {
		return err
	}
	// Separate process mount contains only postgres-ddl.json. Neither schema
	// constructor receives sql-maintenance.json or provider material.
	ddlFiles, err := os.OpenRoot(InitialBootstrapSchemaPrivateRoot)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer ddlFiles.Close()
	d, err := newInitialSchemaDeployment(phase, files, ddlFiles, observer)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Run(phase)
}

// RunInitialBootstrapPreparer uses the existing effect supervisor and current
// schema binding. The renewable source serves only the independent public
// observation probe; target activation credentials retain their one-use rules.
func RunInitialBootstrapPreparer(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || disableWorkerCoreDumps() != nil {
		return mounts.ErrUnavailable
	}
	phase, end := context.WithTimeout(ctx, 15*time.Minute)
	defer end()
	files, err := os.OpenRoot(InitialPreparerRoot)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer files.Close()
	_, in, observer, err := initialBootstrapObservation(phase, files)
	if err != nil {
		return err
	}
	defer in.closeHTTP()
	defer observer.Close()
	deployment, err := newInitialPreparationDeployment(phase, files, observer)
	if err != nil {
		return err
	}
	defer deployment.Close()
	_, err = deployment.Run()
	return err
}
