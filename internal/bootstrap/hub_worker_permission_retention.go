package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"asservat.local/asservat/internal/adapters/jose"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// retentionWorker follows the EvidenceRetentionPolicy objects of the hub
// control namespace into stored deadlines (ADR-330 D12) and publishes the
// signed lifecycle decisions of early erasure.
type retentionWorker struct {
	follower             privacyapp.RetentionFollower
	lifecycle            *privacyapp.LifecyclePublisher
	lastLifecycleOutcome string
}

func newRetentionWorker(ctx context.Context, root string, pools map[string]*pgxpool.Pool, observer *kube.PermissionClient, writer *installedConfigurationAudit, signing *permissionDeletionSigning) (*retentionWorker, error) {
	if writer == nil || observer == nil {
		return nil, mounts.ErrUnavailable
	}
	policies, err := kube.NewRetentionClient(observer)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	store, err := postgres.NewRetentionPolicies(ctx, pools["retention-source"])
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	worker := &retentionWorker{follower: privacyapp.RetentionFollower{Source: policies, Store: store, Report: func(stage string, err error) {
		retentionDiagnostic(stage, err)
	}}}
	if signing != nil {
		lifecycle, err := postgres.NewRetention(ctx, pools["retention-lifecycle-audit"], root)
		if err != nil {
			return nil, err
		}
		worker.lifecycle = &privacyapp.LifecyclePublisher{Ledger: lifecycle, Objects: &installedRetentionLifecycle{root: root, audit: writer, signing: signing}}
	}
	return worker, nil
}

// publish is called only by the permission worker's authority-audit loop:
// at most one provider invocation per lease.
func (r *retentionWorker) publish(ctx context.Context) {
	if r.lifecycle == nil {
		return
	}
	_, err := r.lifecycle.PublishOne(ctx)
	if ctx.Err() == nil {
		if outcome := regionalOutcome(err); outcome != r.lastLifecycleOutcome {
			r.lastLifecycleOutcome = outcome
			if err != nil {
				retentionDiagnostic("lifecycle.publish", err)
			}
		}
	}
}

// run follows the policies until the Lease ends.
func (r *retentionWorker) run(ctx context.Context) { r.follower.Run(ctx) }

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
