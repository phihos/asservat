package bootstrap

import (
	"bytes"
	"context"
	"os"
	"sync"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

const InitialSchemaRoot = "/run/asservat/initial-schema"

// InitialSchemaDeployment is the trusted, finite pre-install DDL process. It
// reads no activation, maintenance, history, S3 or key-provider credential file.
// Its public configuration/root is the same immutable installation plan used by
// the later preparation supervisor.
type InitialSchemaDeployment struct {
	root     context.Context
	cancel   context.CancelFunc
	once     sync.Once
	inputs   *providerInputs
	preparer *kube.InitialPreparer
	schema   *postgres.InitialSchema
}

func NewInitialSchemaDeployment(ctx context.Context, files *os.Root) (*InitialSchemaDeployment, error) {
	return newInitialSchemaDeployment(ctx, files, files, nil)
}

// The automatic bootstrap mounts the DDL credential separately from generated
// public inputs. This constructor is reached only after its protected no-effect
// completion check; it retains the legacy command's exact active checks.
func newInitialSchemaDeployment(ctx context.Context, files, ddlFiles *os.Root, observer *kube.InitialBootstrapObserver) (_ *InitialSchemaDeployment, err error) {
	if ctx == nil || ctx.Err() != nil || files == nil || ddlFiles == nil || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	b, e := mounts.Read(ctx, files, "deployment.json", contracts.InitialPreparationMaxBytes)
	if e != nil {
		return nil, mounts.ErrUnavailable
	}
	defer clear(b)
	c, e := contracts.DecodeInitialPreparer(bytes.NewReader(b))
	if e != nil || c.Plan.SchemaInitialization != contracts.InitialSchemaProtocol || c.Plan.HistoryManager == nil || c.Services == nil {
		return nil, mounts.ErrUnavailable
	}
	if observer != nil && !observer.MatchesInitialPreparer(c) {
		return nil, mounts.ErrUnavailable
	}
	h, e := ownerHTTP(c.Kubernetes.Endpoint, c.Kubernetes.Roots)
	if e != nil {
		return nil, mounts.ErrUnavailable
	}
	h.CloseIdleConnections()
	root, cancel := context.WithTimeout(ctx, 15*time.Minute)
	d := &InitialSchemaDeployment{root: root, cancel: cancel}
	complete := false
	defer func() {
		if !complete {
			d.Close()
		}
	}()
	in := &providerInputs{files: files, kubernetesEndpoint: c.Kubernetes, postgresEndpoint: c.Services.Postgres}
	d.inputs = in
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
	d.preparer, e = kube.NewInitialPreparer(adminConfig, admin, probe, c)
	if e != nil {
		return nil, e
	}
	ddl := &providerInputs{files: ddlFiles, postgresEndpoint: c.Services.Postgres}
	sql, e := ddl.sqlConfig(root, "postgres-ddl.json")
	if e != nil {
		return nil, mounts.ErrUnavailable
	}
	d.schema, e = postgres.NewInitialSchema(sql.ConnConfig, d.preparer, *c.Plan.HistoryManager)
	if e != nil {
		return nil, e
	}
	if e = d.schema.CheckManager(root); e != nil {
		return nil, e
	}
	complete = true
	return d, nil
}
func (d *InitialSchemaDeployment) Run(ctx context.Context) error {
	if d == nil || ctx == nil || d.root.Err() != nil {
		return mounts.ErrUnavailable
	}
	ctx, end := context.WithCancel(ctx)
	defer end()
	stop := context.AfterFunc(d.root, end)
	defer stop()
	if _, e := d.preparer.Open(ctx); e != nil {
		return e
	}
	return d.schema.Run(ctx)
}
func (d *InitialSchemaDeployment) Close() {
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
		if d.schema != nil {
			_ = d.schema.Close()
		}
		if d.inputs != nil {
			d.inputs.closeHTTP()
		}
	})
}
func RunInitialSchema(ctx context.Context) error {
	files, e := os.OpenRoot(InitialSchemaRoot)
	if e != nil {
		return mounts.ErrUnavailable
	}
	defer files.Close()
	d, e := NewInitialSchemaDeployment(ctx, files)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Run(ctx)
}
