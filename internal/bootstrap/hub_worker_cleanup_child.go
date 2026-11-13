package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"strconv"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// hubWorkerCleanupRetry is the pause between startup attempts while setup,
// capacity initialization or the provider are not ready yet.
const hubWorkerCleanupRetry = 5 * time.Second

// runCleanup is the capture/normal/resolution operation audit retirement
// child. It retries startup until SQL, the stored capacity qualification and
// OpenBao are available, then runs the serial cleanup loop. SQL locks/leases,
// the recovery fence and positive object verification authorize each effect.
func (w *hubWorker) runCleanup(ctx context.Context) error {
	if w == nil || ctx == nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	if err := w.validCleanupConfig(); err != nil {
		return err
	}
	report := eventLog(os.Stderr, "operation cleanup")
	for {
		d, err := w.openCleanup(ctx)
		if err == nil {
			defer d.close()
			return d.run(ctx)
		}
		var config *cleanupConfigError
		if errors.As(err, &config) {
			return err
		}
		report(cleanupRuntimeEvent(err))
		timer := time.NewTimer(hubWorkerCleanupRetry)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// cleanupConfigError is a startup failure that retrying cannot fix.
type cleanupConfigError struct{ step string }

func (e *cleanupConfigError) Error() string     { return "operation cleanup: " + e.step }
func (e *cleanupConfigError) Unwrap() error     { return mounts.ErrUnavailable }
func (e *cleanupConfigError) FixedStep() string { return "cleanup/" + e.step }

func (w *hubWorker) validCleanupConfig() error {
	p := w.config.Provider
	r := p.Roles
	for _, role := range []string{r.CleanupWrap, r.CleanupOpen, r.CleanupVerify, r.CleanupSign} {
		if !ownerProviderName.MatchString(role) {
			return &cleanupConfigError{"roles"}
		}
	}
	if !ownerProviderName.MatchString(p.ContextDeletionSigning.Mount) || !ownerProviderName.MatchString(p.ContextDeletionSigning.Key) {
		return &cleanupConfigError{"signing"}
	}
	for _, purpose := range contracts.PublicRuntimeCaptureCleanupPurposes() {
		if _, known := postgres.PublicRuntimeRoleName(w.ids.InstallationID, purpose); !known {
			return &cleanupConfigError{"sql-role"}
		}
	}
	return nil
}

// openCleanup builds one cleanup deployment or returns a retryable error
// naming its stage; a failed attempt closes everything it opened.
func (w *hubWorker) openCleanup(ctx context.Context) (_ *hubWorkerCleanupDeployment, err error) {
	step := "start"
	d := &hubWorkerCleanupDeployment{admission: w.admission, providers: w.providers}
	defer func() {
		if err != nil {
			d.close()
			var config *cleanupConfigError
			if !errors.As(err, &config) {
				err = &cleanupRuntimeError{step, err}
			}
		}
	}()
	if w.admission == nil || w.providers == nil || w.inputs == nil {
		return nil, &cleanupConfigError{"start"}
	}
	startup, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	root, installation := w.ids.PermissionRootID, w.ids.InstallationID
	recovery, err := postgres.NewRecoveryTransactionGuard(root, installation)
	if err != nil {
		return nil, &cleanupConfigError{"ids"}
	}
	step = "sql"
	purposes := contracts.PublicRuntimeCaptureCleanupPurposes()
	var store string
	ledgers := make([]*postgres.OperationLifecycles, 0, len(purposes))
	for i, purpose := range purposes {
		role, _ := postgres.PublicRuntimeRoleName(installation, purpose)
		pool, e := w.pool(startup, "sql-"+purpose+".json", role, "asservat-capture-cleanup")
		if e != nil {
			return nil, e
		}
		d.closers = append(d.closers, pool.Close)
		if i == 0 {
			// Setup writes the capacity source row; wait for it.
			step = "store"
			if store, e = postgres.ReadCaptureCleanupStoreID(startup, pool, root); e != nil {
				return nil, e
			}
			step = "sql"
		}
		ledger, e := postgres.NewScopedWorkerOperationLifecycles(startup, pool, root, installation, store, recovery)
		if e != nil {
			return nil, e
		}
		ledgers = append(ledgers, ledger)
	}
	d.journal, d.verifier, d.finalizer = ledgers[0], ledgers[1], ledgers[2]

	step = "provider-refresh"
	if err = w.providers.RefreshCleanup(startup); err != nil {
		return nil, err
	}
	step = "signing-keys"
	latest, versions, err := w.providers.CleanupSigningPublicKeys(startup)
	if err != nil {
		return nil, err
	}
	public := make(map[string]ed25519.PublicKey, len(versions))
	for version, key := range versions {
		public[contextDeletionKeyID(version)] = key
	}
	keyID := contextDeletionKeyID(latest)
	step = "keys"
	c := w.config
	seal, open, verifyOpen, sign, err := w.providers.CleanupKeys(c.KeyService.AuditMount, c.KeyService.AuditKey, c.Provider.ContextDeletionSigning.Mount, c.Provider.ContextDeletionSigning.Key, latest, public[keyID])
	if err != nil {
		return nil, err
	}
	d.closers = append(d.closers, seal.Close, open.Close, verifyOpen.Close, sign.Close)
	signer, err := jose.NewRemoteOperationRetirementSignatures(root, keyID, public, sign.ForContext)
	if err != nil {
		return nil, err
	}
	verifier, err := jose.NewOperationRetirementSignatures(root, "", nil, public)
	if err != nil {
		return nil, err
	}
	step = "stores"
	stores := make([]*objectstore.Store, 0, 2)
	for _, file := range []string{contracts.HubWorkerCleanupStorageFile, contracts.HubWorkerCleanupVerifyStorageFile} {
		h, e := ownerHTTP(w.auditStore.Endpoint, w.auditStore.Roots)
		if e != nil {
			return nil, &cleanupConfigError{"audit-store"}
		}
		d.closers = append(d.closers, h.CloseIdleConnections)
		s, e := objectstore.NewVersionedAudit(w.auditStore.Endpoint, w.auditStore.Region, w.auditStore.Bucket, cleanupStorageCredential{w.inputs, file}, h)
		if e != nil {
			return nil, &cleanupConfigError{"audit-store"}
		}
		d.closers = append(d.closers, s.Close)
		stores = append(stores, s)
	}
	objects, err := objectstore.NewOperationAuditCleanupObjects(stores[0], store, seal, open, signer, verifier)
	if err != nil {
		return nil, err
	}
	checks, err := objectstore.NewOperationAuditCleanupVerifier(stores[1], store, verifyOpen, verifier)
	if err != nil {
		return nil, err
	}
	d.healthy = app.OperationCleanup{Journal: d.journal, Acknowledgements: d.verifier, Finalizer: d.finalizer, Objects: objects, Verifier: checks}
	d.overdue = app.OperationOverdueCleanup{Journal: d.journal, Acknowledgements: d.verifier, Finalizer: d.finalizer, Objects: objects, Verifier: checks}
	d.history = app.OperationHistoryCleanup{Journal: d.journal, Finalizer: d.finalizer}
	if startup.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	return d, nil
}

// cleanupStorageCredential reads one of the two distinct object-store
// principals on every request; a read error never falls back to a cached
// credential.
type cleanupStorageCredential struct {
	inputs *providerInputs
	file   string
}

func (s cleanupStorageCredential) Retrieve(ctx context.Context) (aws.Credentials, error) {
	var zero aws.Credentials
	b, err := s.inputs.read(ctx, s.file, 32<<10)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(b))
	if err != nil || !identity.Text(c.AccessKeyID, 256) || !identity.Text(c.SecretAccessKey, 8192) || len(c.SessionToken) > 8192 {
		return zero, mounts.ErrUnavailable
	}
	return aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Source: "hub-worker-cleanup"}, nil
}

// contextDeletionKeyID names a context-deletion signing key version.
func contextDeletionKeyID(version int) string { return "v" + strconv.Itoa(version) }
