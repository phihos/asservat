package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/configuration"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// retentionWorker is the ADR-195 hub retention source inside the permission
// worker: the reconciler, the checkpoint acceptance publisher and the
// catch-up pager, for the same stream root. The lifecycle decision publisher
// needs its signing key and follows separately (ADR-195 step 5b); until then
// a shortening of retained evidence leaves the source unavailable.
type retentionWorker struct {
	reconciler app.RetentionReconciler
	acceptance app.RetentionAcceptancePublisher
	catchup    privacyapp.RetentionCatchup
	source     privacy.PolicySourceRef
}

func newRetentionWorker(ctx context.Context, c contracts.PermissionDeployment, pools map[string]*pgxpool.Pool, observer, probe *kube.PermissionClient, writer *installedConfigurationAudit) (*retentionWorker, error) {
	r := c.Retention
	if r == nil || r.Guard.Name != contracts.RetentionGuardName(c.InstallationID) || writer == nil {
		return nil, mounts.ErrUnavailable
	}
	g := r.Guard
	guard, err := kube.NewRetentionGuard(observer, probe, kube.RetentionAdministrationOf(c.Control, g.Name), kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion})
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	policies, err := kube.NewRetentionClient(observer, true)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	store, err := postgres.NewRetentionSources(ctx, pools["retention-source"], c.RootID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	journal, err := postgres.NewRetentionSources(ctx, pools["retention-source-audit"], c.RootID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	catchup, err := postgres.NewRetention(ctx, pools["retention-catchup"], c.RootID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	source := privacy.PolicySourceRef{ClusterID: c.Control.ClusterID, ControlNamespaceUID: c.Control.Namespace.UID, Hub: true, ProtectionDigest: guard.Digest()}
	return &retentionWorker{source: source, catchup: catchup,
		reconciler: app.RetentionReconciler{RootID: c.RootID, Source: source, Reader: stagedRetentionPolicies{policies}, Watcher: stagedRetentionPolicies{policies}, Protection: guard, Store: stagedRetentionStore{store}, Now: time.Now, NewID: uuid.NewString},
		acceptance: app.RetentionAcceptancePublisher{Journal: journal, Writer: &installedRetentionAcceptance{root: c.RootID, audit: writer}}}, nil
}

// run keeps the reconciler and the catch-up pager going until the Lease
// ends; acceptance records are published by the permission worker's audit
// loop, one per admitted lease.
func (r *retentionWorker) run(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.page(ctx)
	}()
	// Like the permission stream: a failed epoch retries after the SQL lease.
	for ctx.Err() == nil {
		if err := r.reconciler.Run(ctx); err != nil && ctx.Err() == nil {
			retentionDiagnostic("reconciler", err)
		}
		if !sleepContext(ctx, 31*time.Second) {
			break
		}
	}
	<-done
}

// page applies outstanding checkpoints to retained evidence, one atomic page
// at a time, and waits a second whenever the source is idle or unavailable.
func (r *retentionWorker) page(ctx context.Context) {
	for ctx.Err() == nil {
		p, err := r.catchup.ReconcileRetentionPage(ctx, r.source, 16)
		if err == nil && !p.Idle {
			continue
		}
		if !sleepContext(ctx, time.Second) {
			return
		}
	}
}

// installedRetentionAcceptance writes one checkpoint acceptance record under
// one provider audit operation, scoped to its own stream root. It shares the
// authority audit admission: the same audit-only principal and material.
type installedRetentionAcceptance struct {
	root  string
	audit *installedConfigurationAudit
}

func (s *installedRetentionAcceptance) WriteRetentionAcceptance(ctx context.Context, r audit.RetentionAcceptance) (audit.Receipt, error) {
	if s == nil || s.audit == nil || ctx == nil || ctx.Err() != nil || !r.Valid() || r.RootID != s.root {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	operation, err := s.audit.providers.BeginAuthorityAudit(ctx)
	if err != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	defer operation.Close()
	call := operation.Context()
	material, err := operation.Credentials()
	if err != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	store, err := s.audit.storage(material)
	if err != nil {
		return audit.Receipt{}, err
	}
	defer store.Close()
	writer := &objectstore.RetentionAcceptanceObjects{Store: store, Seal: s.audit.providers.Sealer(), Open: s.audit.providers.Opener()}
	receipt, err := writer.WriteRetentionAcceptance(call, r)
	if err != nil || call.Err() != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	if err = operation.Finish(); err != nil || call.Err() != nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return receipt, nil
}

// retentionDiagnostic reports a retried retention failure on stderr: fixed
// stage and check names and the error class only, never SQL, Kubernetes or
// provider text.
func retentionDiagnostic(stage string, err error) {
	var inner interface{ FixedStep() string }
	if errors.As(err, &inner) {
		stage += "/" + inner.FixedStep()
	}
	fmt.Fprintln(os.Stderr, "hub-worker retention: "+stage+" ("+errorClass(err)+")")
}

// stagedRetentionStore and stagedRetentionPolicies name the reconciler call
// that failed, for the diagnostic above; they change no behavior.
type stagedRetentionStore struct{ app.RetentionCheckpointStore }

func (s stagedRetentionStore) BeginRetention(ctx context.Context, root string, source privacy.PolicySourceRef, epoch string) (app.RetentionStart, error) {
	out, err := s.RetentionCheckpointStore.BeginRetention(ctx, root, source, epoch)
	return out, stagedRetention("store.begin", err)
}
func (s stagedRetentionStore) AcceptRetention(ctx context.Context, t app.RetentionTransition) (app.RetentionCheckpoint, error) {
	out, err := s.RetentionCheckpointStore.AcceptRetention(ctx, t)
	return out, stagedRetention("store.accept", err)
}
func (s stagedRetentionStore) ObserveRetention(ctx context.Context, o app.RetentionObservation) error {
	return stagedRetention("store.observe", s.RetentionCheckpointStore.ObserveRetention(ctx, o))
}
func (s stagedRetentionStore) RenewRetention(ctx context.Context, f app.RetentionFence) (app.RetentionFence, error) {
	out, err := s.RetentionCheckpointStore.RenewRetention(ctx, f)
	return out, stagedRetention("store.renew", err)
}

type stagedRetentionPolicies struct{ *kube.RetentionClient }

func (s stagedRetentionPolicies) RetentionPolicyList(ctx context.Context) (app.PolicyList, error) {
	out, err := s.RetentionClient.RetentionPolicyList(ctx)
	return out, stagedRetention("policies.list", err)
}
func (s stagedRetentionPolicies) WatchRetentionPolicies(ctx context.Context, rv string) (app.RetentionWatch, error) {
	out, err := s.RetentionClient.WatchRetentionPolicies(ctx, rv)
	return out, stagedRetention("policies.watch", err)
}

func stagedRetention(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &fixedStepError{stage, err}
}
