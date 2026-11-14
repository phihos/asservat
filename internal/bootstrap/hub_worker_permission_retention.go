package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/configuration"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// retentionWorker owns policy observation, catch-up and audit publication for
// the hub retention source of the permission root (ADR-195).
type retentionWorker struct {
	reconciler           app.RetentionReconciler
	acceptance           app.RetentionAcceptancePublisher
	lifecycle            *privacyapp.LifecyclePublisher
	catchup              privacyapp.RetentionCatchup
	source               privacy.PolicySourceRef
	lastLifecycleOutcome string
	// recovery logs the first current observation after a reported
	// reconciler failure.
	recovery *retentionRecovery
}

// retentionRecovery makes a retried reconciler's recovery visible: after a
// logged failure, the next successful source observation logs one line. It
// reports source reachability, not accepted-history progress.
type retentionRecovery struct {
	failed atomic.Bool
	out    io.Writer // nil is stderr
}

func (r *retentionRecovery) fail() {
	if r != nil {
		r.failed.Store(true)
	}
}

func (r *retentionRecovery) observed() {
	if r != nil && r.failed.CompareAndSwap(true, false) {
		out := r.out
		if out == nil {
			out = os.Stderr
		}
		fmt.Fprintln(out, "hub-worker retention: source observation ok")
	}
}

// newRetentionWorker composes the source with the deterministic retention
// source digest. With context deletion (signing non-nil) it also publishes
// signed lifecycle decisions.
func newRetentionWorker(ctx context.Context, root, cluster string, control cfg.NamespaceRef, pools map[string]*pgxpool.Pool, observer *kube.PermissionClient, writer *installedConfigurationAudit, signing *permissionDeletionSigning) (*retentionWorker, error) {
	if writer == nil || observer == nil {
		return nil, mounts.ErrUnavailable
	}
	protection, err := kube.NewPlainRetentionSource(observer)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	policies, err := kube.NewRetentionClient(observer, true)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	store, err := postgres.NewRetentionSources(ctx, pools["retention-source"], root)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	journal, err := postgres.NewRetentionSources(ctx, pools["retention-source-audit"], root)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	catchup, err := postgres.NewRetention(ctx, pools["retention-catchup"], root)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	source := privacy.PolicySourceRef{ClusterID: cluster, ControlNamespaceUID: control.UID, Hub: true, ProtectionDigest: protection.Digest()}
	recovery := &retentionRecovery{}
	worker := &retentionWorker{source: source, catchup: catchup, recovery: recovery,
		reconciler: app.RetentionReconciler{RootID: root, Source: source, Reader: stagedRetentionPolicies{policies}, Watcher: stagedRetentionPolicies{policies}, Protection: protection, Store: stagedRetentionStore{store, recovery}, Now: time.Now, NewID: uuid.NewString},
		acceptance: app.RetentionAcceptancePublisher{Journal: journal, Writer: &installedRetentionAcceptance{root: root, audit: writer}}}
	if signing != nil {
		lifecycle, err := postgres.NewRetention(ctx, pools["retention-lifecycle-audit"], root)
		if err != nil {
			return nil, err
		}
		worker.lifecycle = &privacyapp.LifecyclePublisher{Ledger: lifecycle, Objects: &installedRetentionLifecycle{root: root, audit: writer, signing: signing}}
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

// run keeps the reconciler and the catch-up pager going until the Lease ends.
func (r *retentionWorker) run(ctx context.Context) {
	wait := goJoined(func() { r.page(ctx) })
	defer wait()
	// Like the permission stream: a failed epoch retries after the SQL lease.
	for ctx.Err() == nil {
		if err := r.reconciler.Run(ctx); err != nil && ctx.Err() == nil {
			retentionDiagnostic("reconciler", err)
			r.recovery.fail()
		}
		if !sleepContext(ctx, 31*time.Second) {
			return
		}
	}
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
// the authority audit admission and material (ADR-195).
type installedRetentionAcceptance struct {
	root  string
	audit *installedConfigurationAudit
}

func (s *installedRetentionAcceptance) WriteRetentionAcceptance(ctx context.Context, r audit.RetentionAcceptance) (audit.Receipt, error) {
	if s == nil || s.audit == nil || ctx == nil || ctx.Err() != nil || !r.Valid() || r.RootID != s.root {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return s.audit.writeAuthorityAudit(ctx, func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		writer := &objectstore.RetentionAcceptanceObjects{Store: store, Seal: s.audit.providers.Sealer(), Open: s.audit.providers.Opener()}
		return writer.WriteRetentionAcceptance(call, r)
	})
}

// installedRetentionLifecycle signs the typed retention decision and verifies
// the exact versioned ciphertext before the application acknowledges it.
type installedRetentionLifecycle struct {
	root    string
	audit   *installedConfigurationAudit
	signing *permissionDeletionSigning
}

func (s *installedRetentionLifecycle) WriteLifecycleDecision(ctx context.Context, r privacy.LifecycleDecision) (audit.Receipt, error) {
	if s == nil || s.audit == nil || s.audit.providers == nil || s.signing == nil || ctx == nil || ctx.Err() != nil || !r.Valid() || r.RootID != s.root {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	pin, err := s.signing.get(ctx)
	if err != nil {
		return audit.Receipt{}, err
	}
	public := make(map[string]ed25519.PublicKey, len(pin.PublicKeys))
	for id, key := range pin.PublicKeys {
		public[id] = ed25519.PublicKey(key)
	}
	key, err := s.audit.providers.ContextDeletionSigningKey(pin.Mount, pin.Key, pin.Version, public[pin.KeyID])
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"signing.key", err}
	}
	defer key.Close()
	signatures, err := jose.NewRemoteLifecycleSignatures(s.root, pin.KeyID, public, key.ForContext)
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"signing.type", err}
	}
	return s.audit.writeAuthorityAudit(ctx, func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		writer := &objectstore.LifecycleObjects{Store: store, Seal: s.audit.providers.Sealer(), Open: s.audit.providers.Opener(), Signer: signatures, Verifier: signatures}
		return writer.WriteLifecycleDecision(call, r)
	})
}

// retentionDiagnostic reports a retried retention failure on stderr: fixed
// stage and check names and the error class only.
func retentionDiagnostic(stage string, err error) {
	var inner interface{ FixedStep() string }
	if errors.As(err, &inner) {
		stage += "/" + inner.FixedStep()
	}
	fmt.Fprintln(os.Stderr, "hub-worker retention: "+stage+" ("+errorClass(err)+")")
}

// stagedRetentionStore and stagedRetentionPolicies name the reconciler call
// that failed, for the diagnostic above; they change no behavior.
type stagedRetentionStore struct {
	app.RetentionCheckpointStore
	recovery *retentionRecovery
}

func (s stagedRetentionStore) BeginRetention(ctx context.Context, root string, source privacy.PolicySourceRef, epoch string) (app.RetentionStart, error) {
	out, err := s.RetentionCheckpointStore.BeginRetention(ctx, root, source, epoch)
	return out, stagedRetention("store.begin", err)
}
func (s stagedRetentionStore) AcceptRetention(ctx context.Context, t app.RetentionTransition) (app.RetentionCheckpoint, error) {
	out, err := s.RetentionCheckpointStore.AcceptRetention(ctx, t)
	return out, stagedRetention("store.accept", err)
}
func (s stagedRetentionStore) ObserveRetention(ctx context.Context, o app.RetentionObservation) error {
	err := s.RetentionCheckpointStore.ObserveRetention(ctx, o)
	if err == nil {
		s.recovery.observed()
	}
	return stagedRetention("store.observe", err)
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
