package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"reflect"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/audit"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This fixed child runs only under the original A-HWORK scheduling owner.
// Its three physical pools remain separate. SQL locks/leases and independent
// positive object verification, rather than Lease ownership, authorize cleanup.
type CaptureCleanupWorkerDeployment struct {
	root                         context.Context
	cancel                       context.CancelFunc
	mu                           sync.Mutex
	closed, running              bool
	lastSweepPending             bool
	owners                       sync.WaitGroup
	once                         sync.Once
	closers                      []func()
	reader                       *kube.InstalledWorkerProjectionReader
	admission                    *fleetapp.WorkerRuntimeAdmission
	claim                        contracts.CaptureCleanupProjectionClaim
	journal, verifier, finalizer *postgres.OperationLifecycles
	healthy                      app.OperationCleanup
	overdue                      app.OperationOverdueCleanup
	history                      app.OperationHistoryCleanup
}

func NewCaptureCleanupWorkerDeployment(ctx context.Context, files *os.Root, worker contracts.HubWorkerDeployment, reader *kube.InstalledWorkerProjectionReader, expected contracts.CaptureCleanupProjectionClaim) (*CaptureCleanupWorkerDeployment, error) {
	return newCaptureCleanupWorkerDeployment(ctx, files, worker, reader, expected, nil)
}

func newCaptureCleanupWorkerDeployment(ctx context.Context, files *os.Root, worker contracts.HubWorkerDeployment, reader *kube.InstalledWorkerProjectionReader, expected contracts.CaptureCleanupProjectionClaim, selected *providerCleanupStartup) (*CaptureCleanupWorkerDeployment, error) {
	if ctx == nil || ctx.Err() != nil || files == nil || reader == nil || expected.Receipt == nil || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	// Legacy startup still performs its original independent read. The fresh
	// private caller already owns the exact native operation and performs its
	// genuine final pass after construction, before any cleanup Run call.
	got, until := expected, time.Time{}
	startupParent := ctx
	if selected == nil {
		observed, ready, bound, err := reader.ReadCleanup(ctx)
		if err != nil || !ready || !reflect.DeepEqual(observed, expected) || !time.Now().Before(bound) {
			return nil, mounts.ErrUnavailable
		}
		got, until = observed, bound
	} else {
		if selected.operation == nil || selected.admission == nil || worker.Activation == nil || worker.Activation.WorkerLayout != contracts.HubWorkerProviderInstalledLayout {
			return nil, mounts.ErrUnavailable
		}
		startupParent, until = selected.operation.Context(), selected.operation.FreshUntil()
		if startupParent.Err() != nil || !time.Now().Before(until) {
			return nil, mounts.ErrUnavailable
		}
	}
	read, endRead := context.WithDeadline(startupParent, until)
	c, m, err := readCaptureCleanupInputs(read, files, worker, got)
	endRead()
	if err != nil {
		return nil, err
	}
	root, cancel := context.WithCancel(ctx)
	d := &CaptureCleanupWorkerDeployment{root: root, cancel: cancel, reader: reader, lastSweepPending: true}
	if selected != nil {
		d.admission = selected.admission
	}
	encoded, err := json.Marshal(got)
	if err != nil || json.Unmarshal(encoded, &d.claim) != nil {
		cancel()
		return nil, mounts.ErrUnavailable
	}
	complete := false
	defer func() {
		if !complete {
			d.Close()
		}
	}()
	startup, end := context.WithDeadline(startupParent, identity.Earlier(time.Now().Add(30*time.Second), until))
	defer end()
	in := &providerInputs{files: files, postgresEndpoint: c.Postgres}
	d.closers = append(d.closers, in.closeHTTP)
	recovery, err := postgres.NewRecoveryTransactionGuard(c.RootID, c.InstallationID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	ledgers := make([]*postgres.OperationLifecycles, 0, 3)
	for _, purpose := range contracts.PublicRuntimeCaptureCleanupPurposes() {
		p, e := in.sqlConfig(startup, "sql-"+purpose+".json")
		if e != nil {
			return nil, mounts.ErrUnavailable
		}
		p.MaxConns, p.MinConns = 1, 0
		p.ConnConfig.RequireAuth = "scram-sha-256"
		p.ConnConfig.RuntimeParams["application_name"] = "asservat-capture-cleanup"
		pool, e := pgxpool.NewWithConfig(startup, p)
		if e != nil {
			return nil, mounts.ErrUnavailable
		}
		d.closers = append(d.closers, pool.Close)
		if postgres.VerifyCaptureCleanupCredential(startup, pool, m, purpose) != nil {
			return nil, mounts.ErrUnavailable
		}
		ledger, e := postgres.NewScopedCaptureOperationLifecycles(startup, pool, c.RootID, c.InstallationID, c.StoreID, recovery)
		if e != nil {
			return nil, mounts.ErrUnavailable
		}
		ledgers = append(ledgers, ledger)
	}
	d.journal, d.verifier, d.finalizer = ledgers[0], ledgers[1], ledgers[2]
	provider, err := ownerHTTP(c.KeyService.Endpoint, c.KeyService.Roots)
	if err != nil {
		return nil, err
	}
	d.closers = append(d.closers, provider.CloseIdleConnections)
	seal, err := kms.NewSealerWithTokenSource(c.KeyService.Endpoint, c.KeyService.AuditMount, c.KeyService.AuditKey, in.token("certificate-wrap.token"), provider)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.closers = append(d.closers, seal.Close)
	open, err := kms.NewOpenerWithTokenSource(c.KeyService.Endpoint, c.KeyService.AuditMount, c.KeyService.AuditKey, in.token("certificate-open.token"), provider)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.closers = append(d.closers, open.Close)
	verifyOpen, err := kms.NewOpenerWithTokenSource(c.KeyService.Endpoint, c.KeyService.AuditMount, c.KeyService.AuditKey, in.token("certificate-verify.token"), provider)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.closers = append(d.closers, verifyOpen.Close)
	public := map[string]ed25519.PublicKey{}
	for id, key := range c.Signing.PublicKeys {
		public[id] = ed25519.PublicKey(key)
	}
	sign, err := kms.NewSigningKeyWithTokenSource(c.KeyService.Endpoint, c.Signing.Mount, c.Signing.Name, c.Signing.Version, public[c.Signing.KeyID], in.token("certificate-sign.token"), provider)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.closers = append(d.closers, sign.Close)
	signer, err := jose.NewRemoteOperationRetirementSignatures(c.RootID, c.Signing.KeyID, public, sign.ForContext)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	verifier, err := jose.NewOperationRetirementSignatures(c.RootID, "", nil, public)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	stores := make([]*objectstore.Store, 0, 2)
	for _, independent := range []bool{false, true} {
		h, e := ownerHTTP(c.AuditStore.Endpoint, c.AuditStore.Roots)
		if e != nil {
			return nil, e
		}
		d.closers = append(d.closers, h.CloseIdleConnections)
		store, e := objectstore.NewVersionedAudit(c.AuditStore.Endpoint, c.AuditStore.Region, c.AuditStore.Bucket, captureCleanupStorage{in, independent}, h)
		if e != nil {
			return nil, mounts.ErrUnavailable
		}
		d.closers = append(d.closers, store.Close)
		stores = append(stores, store)
	}
	objects, err := objectstore.NewOperationAuditCleanupObjects(stores[0], c.StoreID, seal, open, signer, verifier)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	checks, err := objectstore.NewOperationAuditCleanupVerifier(stores[1], c.StoreID, verifyOpen, verifier)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.healthy = app.OperationCleanup{Journal: d.journal, Acknowledgements: d.verifier, Finalizer: d.finalizer, Objects: objects, Verifier: checks}
	d.overdue = app.OperationOverdueCleanup{Journal: d.journal, Acknowledgements: d.verifier, Finalizer: d.finalizer, Objects: objects, Verifier: checks}
	d.history = app.OperationHistoryCleanup{Journal: d.journal, Finalizer: d.finalizer}
	if selected == nil {
		check, endCheck, err := d.current(startup)
		if err != nil {
			return nil, err
		}
		err = check.Err()
		endCheck()
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
	} else if startup.Err() != nil || !time.Now().Before(until) {
		return nil, mounts.ErrUnavailable
	}
	complete = true
	return d, nil
}

func (d *CaptureCleanupWorkerDeployment) current(ctx context.Context) (context.Context, context.CancelFunc, error) {
	claim, ready, until, err := d.reader.ReadCleanup(ctx)
	if err != nil || !ready || !reflect.DeepEqual(claim, d.claim) || !time.Now().Before(until) {
		return nil, nil, mounts.ErrUnavailable
	}
	call, end := context.WithDeadline(ctx, until)
	return call, end, nil
}

func (d *CaptureCleanupWorkerDeployment) Run(ctx context.Context) error {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	d.mu.Lock()
	if d.closed || d.running || d.root.Err() != nil {
		d.mu.Unlock()
		return mounts.ErrUnavailable
	}
	d.running = true
	d.owners.Add(1)
	d.mu.Unlock()
	defer func() { d.owners.Done(); d.Close() }()
	live, cancel := context.WithCancel(ctx)
	joined := make(chan struct{})
	stop := context.AfterFunc(d.root, func() { cancel(); close(joined) })
	defer func() {
		cancel()
		if !stop() {
			<-joined
		}
	}()
	if d.admission != nil {
		return d.runProviderCleanup(live)
	}
	cursor := ""
	for {
		pending := false
		call, end, err := d.current(live)
		if err != nil {
			return err
		}
		ids, err := d.journal.DueCaptureOperations(call, cursor)
		end()
		if err != nil {
			return err
		}
		for _, id := range ids {
			call, end, err = d.current(live)
			if err != nil {
				return err
			}
			state, readErr := d.journal.ReadOperationLifecycle(call, id)
			if readErr == nil {
				b := state.Intent.Lifecycle
				var advanceErr error
				switch {
				case state.TerminalAcknowledged:
					advanceErr = d.finalizer.RetireOperationAudit(call, id)
				case b != nil && b.Policy.OverdueTerminal == value.OperationOverdueTerminal && !state.CertificateStarted && state.CertificateWriter == nil && state.CertificateReceipt == nil && !time.Now().Before(b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds)*time.Second)):
					advanceErr = d.overdue.Advance(call, id)
				default:
					advanceErr = d.healthy.Advance(call, id)
				}
				pending = pending || advanceErr != nil
			} else {
				pending = true
			}
			// Unavailable/unknown work remains charged. Advancing the bounded
			// scheduling cursor cannot acknowledge, delete or refund its row.
			end()
			cursor = id
		}
		if len(ids) < 16 {
			cursor = ""
		}
		call, end, err = d.current(live)
		if err != nil {
			return err
		}
		_, historyErr := d.history.Sweep(call)
		end()
		d.mu.Lock()
		d.lastSweepPending = pending || historyErr != nil
		d.mu.Unlock()
		timer := time.NewTimer(time.Second)
		select {
		case <-live.Done():
			timer.Stop()
			return live.Err()
		case <-timer.C:
		}
	}
}

// LastSweepPending reports only unresolved work in the last bounded page. It
// is not an installation-wide cleanliness or writer-quiescence assertion.
func (d *CaptureCleanupWorkerDeployment) LastSweepPending() bool {
	if d == nil {
		return true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.running || d.closed || d.lastSweepPending
}

func (d *CaptureCleanupWorkerDeployment) Close() {
	if d == nil {
		return
	}
	d.once.Do(func() {
		d.mu.Lock()
		d.closed = true
		if d.cancel != nil {
			d.cancel()
		}
		d.mu.Unlock()
		d.owners.Wait()
		for i := len(d.closers) - 1; i >= 0; i-- {
			d.closers[i]()
		}
	})
}
