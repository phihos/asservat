package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
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

// retentionWorker owns policy observation, catch-up and audit publication for
// the same retention stream root.
type retentionWorker struct {
	reconciler           app.RetentionReconciler
	acceptance           app.RetentionAcceptancePublisher
	lifecycle            *privacyapp.LifecyclePublisher
	catchup              privacyapp.RetentionCatchup
	source               privacy.PolicySourceRef
	lastLifecycleOutcome string
}

func newRetentionWorker(ctx context.Context, c contracts.PermissionDeployment, pools map[string]*pgxpool.Pool, observer *kube.PermissionClient, writer *installedConfigurationAudit, deletionSection func() (contracts.ContextDeletionDeployment, string, bool)) (*retentionWorker, error) {
	r := c.Retention
	if r == nil || r.Guard.Name != contracts.RetentionGuardName(c.InstallationID) || writer == nil {
		return nil, mounts.ErrUnavailable
	}
	g := r.Guard
	guard, err := kube.NewRetentionGuard(observer, kube.RetentionAdministrationOf(c.Control, g.Name), kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion})
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
	worker := &retentionWorker{source: source, catchup: catchup,
		reconciler: app.RetentionReconciler{RootID: c.RootID, Source: source, Reader: stagedRetentionPolicies{policies}, Watcher: stagedRetentionPolicies{policies}, Protection: guard, Store: stagedRetentionStore{store}, Now: time.Now, NewID: uuid.NewString},
		acceptance: app.RetentionAcceptancePublisher{Journal: journal, Writer: &installedRetentionAcceptance{root: c.RootID, audit: writer}}}
	// The installer enables deletion with every evidence publisher. Its
	// verified capacity projection supplies the existing Transit signing pin.
	if c.ContextDeletion {
		if deletionSection == nil {
			return nil, mounts.ErrUnavailable
		}
		lifecycle, err := postgres.NewRetention(ctx, pools["retention-lifecycle-audit"], c.RootID)
		if err != nil {
			return nil, err
		}
		worker.lifecycle = &privacyapp.LifecyclePublisher{Ledger: lifecycle,
			Objects: &installedRetentionLifecycle{root: c.RootID, audit: writer, deletionSection: deletionSection}}
	}
	return worker, nil
}

// publish is called only by the permission worker's authority-audit loop.
// Reserve at most one provider invocation per lease, and give acceptance
// every retention turn when there is no pending lifecycle work.
func (r *retentionWorker) publish(ctx context.Context, lifecycleTurn bool) {
	if lifecycleTurn && r.lifecycle != nil {
		attempted, err := r.lifecycle.PublishOne(ctx)
		if ctx.Err() == nil {
			outcome := regionalOutcome(err)
			if outcome != r.lastLifecycleOutcome {
				r.lastLifecycleOutcome = outcome
				if err != nil {
					retentionDiagnostic("lifecycle.publish", err)
				}
			}
		}
		if attempted || err != nil {
			return
		}
	}
	_ = r.acceptance.Publish(ctx, 1)
}

// run keeps the reconciler and the catch-up pager going until the Lease
// ends. The permission worker publishes one audit record per admitted lease.
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
	if s == nil || ctx == nil || ctx.Err() != nil || !r.Valid() || r.RootID != s.root {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return s.audit.writeRetentionAudit(ctx, func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		writer := &objectstore.RetentionAcceptanceObjects{Store: store, Seal: s.audit.providers.Sealer(), Open: s.audit.providers.Opener()}
		return writer.WriteRetentionAcceptance(call, r)
	})
}

// installedRetentionLifecycle signs the typed retention decision and verifies
// the exact versioned ciphertext before the application acknowledges it.
type installedRetentionLifecycle struct {
	root            string
	audit           *installedConfigurationAudit
	deletionSection func() (contracts.ContextDeletionDeployment, string, bool)
}

func (s *installedRetentionLifecycle) WriteLifecycleDecision(ctx context.Context, r privacy.LifecycleDecision) (audit.Receipt, error) {
	if s == nil || s.audit == nil || s.audit.providers == nil || s.deletionSection == nil || ctx == nil || ctx.Err() != nil || !r.Valid() || r.RootID != s.root {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	section, _, ok := s.deletionSection()
	if !ok {
		return audit.Receipt{}, stagedRetention("signing.pin", mounts.ErrUnavailable)
	}
	pin := section.Signing
	public := make(map[string]ed25519.PublicKey, len(pin.PublicKeys))
	for id, key := range pin.PublicKeys {
		public[id] = ed25519.PublicKey(key)
	}
	key, err := s.audit.providers.ContextDeletionSigningKey(pin.Mount, pin.Key, pin.Version, public[pin.KeyID])
	if err != nil {
		return audit.Receipt{}, stagedRetention("signing.key", err)
	}
	defer key.Close()
	signatures, err := jose.NewRemoteLifecycleSignatures(s.root, pin.KeyID, public, key.ForContext)
	if err != nil {
		return audit.Receipt{}, stagedRetention("signing.type", err)
	}
	return s.audit.writeRetentionAudit(ctx, func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		writer := &objectstore.LifecycleObjects{Store: store, Seal: s.audit.providers.Sealer(), Open: s.audit.providers.Opener(), Signer: signatures, Verifier: signatures}
		return writer.WriteLifecycleDecision(call, r)
	})
}

// Both retention record types share the exact authority audit admission,
// provider material, versioned storage and final provider proof.
func (s *installedConfigurationAudit) writeRetentionAudit(ctx context.Context, write func(context.Context, *objectstore.Store) (audit.Receipt, error)) (audit.Receipt, error) {
	if s == nil || s.providers == nil {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	operation, err := s.providers.BeginAuthorityAudit(ctx)
	if err != nil {
		return audit.Receipt{}, stagedRetention("audit.begin", err)
	}
	defer operation.Close()
	call := operation.Context()
	material, err := operation.Credentials()
	if err != nil {
		return audit.Receipt{}, stagedRetention("audit.credentials", err)
	}
	store, err := s.storage(material)
	if err != nil {
		return audit.Receipt{}, stagedRetention("audit.storage", err)
	}
	defer store.Close()
	receipt, err := write(call, store)
	if err != nil || call.Err() != nil {
		return audit.Receipt{}, stagedRetention("audit.write", mounts.ErrUnavailable)
	}
	if err = operation.Finish(); err != nil || call.Err() != nil {
		return audit.Receipt{}, stagedRetention("audit.finish", mounts.ErrUnavailable)
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
