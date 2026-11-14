package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/evidence"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// workerConfigurationObserver is the one call the child repeats.
type workerConfigurationObserver interface {
	Observe(context.Context) error
}

// workerConfigurationWorker is the ADR-204 decision 7 sub-child: the ADR-070
// observer of the worker profile ConfigMap in the worker namespace. It stages
// each accepted revision in SQL, writes its encrypted snapshot under the
// worker configuration audit Transit key and acknowledges it with the
// separate audit login.
type workerConfigurationWorker struct {
	observer workerConfigurationObserver
	// read is the fixed outcome of the last failed source read.
	read    string
	closers []func()
}

func (w *workerConfigurationWorker) Close() {
	for i := len(w.closers) - 1; i >= 0; i-- {
		w.closers[i]()
	}
	w.closers = nil
}

// openWorkerConfiguration reads the worker namespace and source UIDs by name
// (SQL keys on them) and composes the observer.
func (w *hubWorker) openWorkerConfiguration(ctx context.Context, v contracts.HubWorkerWorkerConfiguration, pools map[string]*pgxpool.Pool) (_ *workerConfigurationWorker, err error) {
	out := &workerConfigurationWorker{}
	defer func() {
		if err != nil {
			out.Close()
		}
	}()
	config := w.inputs.kubernetes(contracts.HubWorkerKubernetesTokenFile)
	nsUID, err := kube.ReadNamespaceUID(ctx, config, v.Namespace)
	if err != nil {
		return nil, &fixedStepError{"namespace", err}
	}
	observer, err := kube.NewPermissionClient(config, w.ids.ClusterID, cfg.NamespaceRef{Name: v.Namespace, UID: nsUID}, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	sourceUID, err := observer.ConfigMapUID(ctx, v.Source)
	if err != nil {
		return nil, &fixedStepError{"source/uid", err}
	}
	protection, err := kube.NewPlainWorkerConfigurationProtection(observer, v.Source)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	source, err := kube.NewWorkerConfigurationSource(observer, protection, v.Source, sourceUID, w.ids.InstallationID, w.ids.IssuerEpoch)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	ledger, err := postgres.NewWorkerConfigurations(ctx, pools["worker-config-observe"], w.ids.InstallationID, w.ids.ClusterID, nsUID, sourceUID)
	if err != nil {
		return nil, &fixedStepError{"sql/observe", err}
	}
	acknowledgements, err := postgres.NewWorkerConfigurations(ctx, pools["worker-config-audit"], w.ids.InstallationID, w.ids.ClusterID, nsUID, sourceUID)
	if err != nil {
		return nil, &fixedStepError{"sql/audit", err}
	}
	t := w.config.Provider.WorkerConfigurationAudit
	seal, open, err := w.providers.AuditKeys(t.Mount, t.Key)
	if err != nil {
		return nil, &fixedStepError{"transit", err}
	}
	out.closers = append(out.closers, seal.Close, open.Close)
	objects := &installedWorkerConfigurationAudit{installation: w.ids.InstallationID, authority: w.authority, audit: w.audit, seal: seal, open: open}
	out.observer = &evidence.WorkerConfigurationObserver{Reader: stagedWorkerConfigurationSource{source, &out.read}, Ledger: ledger, Audit: objects, Acknowledgements: acknowledgements, Now: time.Now}
	return out, nil
}

// run observes the source once a second until the Lease ends, so an accepted
// revision stays within its five-second freshness. A failed read fences the
// SQL head inside the observer.
func (w *workerConfigurationWorker) run(ctx context.Context) {
	last := "ok"
	for ctx.Err() == nil {
		w.read = ""
		outcome := regionalOutcome(w.observer.Observe(ctx))
		if outcome != "ok" && w.read == "ledger-or-audit" {
			outcome = w.read + ": " + outcome
		} else if outcome != "ok" && w.read != "" {
			outcome = w.read
		}
		if outcome != last && ctx.Err() == nil {
			last = outcome
			fmt.Fprintln(os.Stderr, "hub-worker worker configuration: "+outcome)
		}
		if !sleepContext(ctx, time.Second) {
			return
		}
	}
}

// stagedWorkerConfigurationSource records the fixed class of a failed read
// for the diagnostic above; it changes no behavior.
type stagedWorkerConfigurationSource struct {
	*kube.WorkerConfigurationSource
	read *string
}

func (s stagedWorkerConfigurationSource) ReadWorkerConfiguration(ctx context.Context) (authorization.DownloadWorkerObservation, error) {
	out, err := s.WorkerConfigurationSource.ReadWorkerConfiguration(ctx)
	if err != nil {
		*s.read = regionalOutcome(&fixedStepError{"source", err})
	} else if !out.Valid(time.Now()) {
		*s.read = "source/invalid-observation"
	} else {
		// A later failure is the SQL ledger, audit or acknowledgement.
		*s.read = "ledger-or-audit"
	}
	return out, err
}

// installedWorkerConfigurationAudit writes one revision's encrypted snapshot
// under one authority audit admission and provider operation, sealed with the
// worker configuration audit Transit key. A busy admission slot fails this
// attempt; the next observation retries.
type installedWorkerConfigurationAudit struct {
	installation string
	authority    *authorityAuditTurn
	audit        *installedConfigurationAudit
	seal         *kms.Sealer
	open         *kms.Opener
}

func (s *installedWorkerConfigurationAudit) WriteWorkerConfiguration(ctx context.Context, c authorization.DownloadWorkerConfiguration) (audit.Receipt, error) {
	if s == nil || s.authority == nil || s.audit == nil || s.audit.providers == nil || s.seal == nil || s.open == nil || ctx == nil || ctx.Err() != nil || !c.Valid() || c.Profile.InstallationID != s.installation {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return admittedAuthorityAudit(ctx, s.authority, s.audit, func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		writer := &objectstore.WorkerConfigurationAuditObjects{Store: store, Seal: s.seal, Open: s.open}
		return writer.WriteWorkerConfiguration(call, c)
	})
}

// authorityAuditTurn serializes this process's authority audit writers (the
// authority/retention publisher, worker configuration and context deletion)
// in front of the admission's single authority audit slot. The admission
// rejects a second ticket for a held slot at once; without the turn a writer
// that is rarely needed loses to the publisher, which holds the slot most of
// each second. The turn only orders process work and grants nothing.
type authorityAuditTurn struct {
	admission *fleetapp.WorkerRuntimeAdmission
	turn      chan struct{}
}

func newAuthorityAuditTurn(admission *fleetapp.WorkerRuntimeAdmission) *authorityAuditTurn {
	return &authorityAuditTurn{admission: admission, turn: make(chan struct{}, 1)}
}

// wait takes the turn, then one authority audit admission lease. release
// returns both.
func (g *authorityAuditTurn) wait(ctx context.Context) (_ *fleetapp.WorkerRuntimeAdmissionLease, release func(), _ error) {
	if g == nil || g.admission == nil || ctx == nil {
		return nil, nil, mounts.ErrUnavailable
	}
	select {
	case g.turn <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, mounts.ErrUnavailable
	}
	lease, err := g.admission.WaitAuthorityAudit(ctx)
	if err != nil {
		<-g.turn
		return nil, nil, err
	}
	return lease, func() { lease.Release(); <-g.turn }, nil
}

// admittedAuthorityAudit takes one authority audit turn and admission lease,
// waits for the fleet observation and writes under it.
func admittedAuthorityAudit(ctx context.Context, authority *authorityAuditTurn, a *installedConfigurationAudit, write func(context.Context, *objectstore.Store) (audit.Receipt, error)) (audit.Receipt, error) {
	lease, release, err := authority.wait(ctx)
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.admission", mounts.ErrUnavailable}
	}
	defer release()
	if err = lease.AwaitFleetObservation(); err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.fleet", mounts.ErrUnavailable}
	}
	return a.writeAuthorityAudit(lease.Context(), write)
}

// contextDeletionSweep is how often the deletion child lists due attempts
// (ADR-205 decision 1). The fixed cadence does not extend a capture's
// original deletion deadline.
const contextDeletionSweep = 30 * time.Second

// contextDeletionWorker deletes expired context evidence with ADR-111's
// cleaner, one due attempt at a time. A failed or unknown step stays pending:
// the attempt is listed again and Clean resumes from its checkpoint. The
// cleaner is prepared once the signing keys are read and the evidence store
// ID is known; deadline observation runs before that.
type contextDeletionWorker struct {
	root      string
	facets    []*postgres.ContextDeletions
	deadlines captureapp.ContextDeadlineObserver
	recovery  *postgres.RecoveryReader
	// prepare builds the cleaner; it is retried each sweep until it succeeds.
	prepare func(context.Context) (*privacyapp.ContextCleaner, []func(), error)
	cleaner *privacyapp.ContextCleaner
	closers []func()
}

func (d *contextDeletionWorker) Close() {
	for i := len(d.closers) - 1; i >= 0; i-- {
		d.closers[i]()
	}
	d.closers = nil
}

func (w *hubWorker) openContextDeletion(ctx context.Context, v contracts.HubWorkerContextDeletion, pools map[string]*pgxpool.Pool, signing *permissionDeletionSigning) (*contextDeletionWorker, error) {
	if signing == nil {
		return nil, mounts.ErrUnavailable
	}
	root, installation := w.ids.PermissionRootID, w.ids.InstallationID
	roots, err := readPEMRoots(ctx, w.files, contracts.HubWorkerAuditStoreRootsFile)
	if err != nil {
		return nil, &fixedStepError{"evidence-roots", err}
	}
	d := &contextDeletionWorker{root: root}
	for _, purpose := range contracts.PublicRuntimeContextDeletionPurposes() {
		f, e := postgres.NewContextDeletions(ctx, pools[purpose], root, installation)
		if e != nil {
			return nil, &fixedStepError{"sql/" + purpose, mounts.ErrUnavailable}
		}
		d.facets = append(d.facets, f)
	}
	if d.recovery, err = postgres.NewRecoveryReader(ctx, pools["context-cleanup"], installation); err != nil {
		return nil, &fixedStepError{"recovery", mounts.ErrUnavailable}
	}
	// ADR-223: the cleaner's login also marks elapsed capture deadlines.
	if d.deadlines, err = postgres.NewContextDeadlineObserver(ctx, pools["context-cleanup"], root); err != nil {
		return nil, &fixedStepError{"sql/context-deadlines", mounts.ErrUnavailable}
	}
	store := contracts.OwnerAuditStore{Endpoint: v.EvidenceStore.Endpoint, Roots: roots, Region: v.EvidenceStore.Region, Bucket: v.EvidenceStore.Bucket}
	d.prepare = func(ctx context.Context) (*privacyapp.ContextCleaner, []func(), error) {
		// The capacity child publishes the evidence store ID of its stored
		// qualification.
		storeID, ok := w.EvidenceStoreID()
		if !ok {
			return nil, nil, &fixedStepError{"evidence-store-id", mounts.ErrUnavailable}
		}
		pin, err := signing.get(ctx)
		if err != nil {
			return nil, nil, err
		}
		return prepareContextCleaner(contracts.ContextDeletionDeployment{EvidenceStore: store, Signing: pin}, storeID, root, d, w.inputs, w.providers, w.authority, w.audit)
	}
	return d, nil
}

// prepareContextCleaner builds the cleaner for one evidence store and
// signing key. On failure it releases everything it opened.
func prepareContextCleaner(v contracts.ContextDeletionDeployment, storeID, root string, d *contextDeletionWorker, inputs *providerInputs, providers *kms.InstalledConfigurationProviderEffects, authority *authorityAuditTurn, writer *installedConfigurationAudit) (_ *privacyapp.ContextCleaner, closers []func(), err error) {
	defer func() {
		if err != nil {
			for i := len(closers) - 1; i >= 0; i-- {
				closers[i]()
			}
			closers = nil
		}
	}()
	if !kube.ContextDeletionSectionValid(&v, time.Now()) || !authorization.UUID(storeID) || len(d.facets) != 3 {
		return nil, nil, &fixedStepError{"section", mounts.ErrUnavailable}
	}
	h, err := ownerHTTP(v.EvidenceStore.Endpoint, v.EvidenceStore.Roots)
	if err != nil {
		return nil, nil, &fixedStepError{"evidence-http", err}
	}
	closers = append(closers, h.CloseIdleConnections)
	evidenceStore, err := objectstore.New(v.EvidenceStore.Endpoint, v.EvidenceStore.Region, v.EvidenceStore.Bucket, evidenceDeleteStorage{inputs}, h)
	if err != nil {
		return nil, closers, &fixedStepError{"evidence-store", mounts.ErrUnavailable}
	}
	closers = append(closers, evidenceStore.Close)
	purger, err := evidenceStore.ForCustody(storeID)
	if err != nil {
		return nil, closers, &fixedStepError{"evidence-store", mounts.ErrUnavailable}
	}
	s := v.Signing
	public := make(map[string]ed25519.PublicKey, len(s.PublicKeys))
	for id, key := range s.PublicKeys {
		public[id] = ed25519.PublicKey(bytes.Clone(key))
	}
	key, err := providers.ContextDeletionSigningKey(s.Mount, s.Key, s.Version, public[s.KeyID])
	if err != nil {
		return nil, closers, &fixedStepError{"signing", mounts.ErrUnavailable}
	}
	closers = append(closers, key.Close)
	signatures, err := jose.NewRemoteContextDeletionSignatures(root, s.KeyID, public, key.ForContext)
	if err != nil {
		return nil, closers, &fixedStepError{"signing", mounts.ErrUnavailable}
	}
	objects := &installedContextDeletionAudit{authority: authority, audit: writer, signatures: signatures}
	return &privacyapp.ContextCleaner{Ledger: d.facets[0], Audit: d.facets[1], Finalize: d.facets[2], Purger: purger, Objects: objects, Recovery: d.recovery, Now: time.Now}, closers, nil
}

// run sweeps until the Lease ends, logging each outcome when it changes from
// the previous sweep's.
func (d *contextDeletionWorker) run(ctx context.Context) {
	last := map[artifact.Location]string{}
	lastDeadline := ""
	var cursor postgres.ContextDeletionCursor
	for ctx.Err() == nil {
		if outcome := observeContextDeadlines(ctx, d.deadlines.ObserveOverdueContextCaptures); outcome != lastDeadline && ctx.Err() == nil {
			shown := outcome
			if shown == "" {
				shown = "ok"
			}
			fmt.Fprintln(os.Stderr, "hub-worker context deadlines: "+shown)
			lastDeadline = outcome
		}
		outcomes := map[artifact.Location]string{}
		if d.cleaner == nil {
			cleaner, closers, err := d.prepare(ctx)
			if err != nil {
				outcomes[artifact.Location{}] = "prepare " + regionalOutcome(err)
			} else {
				d.cleaner = cleaner
				d.closers = append(d.closers, closers...)
			}
		}
		if d.cleaner != nil {
			cursor, outcomes = sweepContextDeletionPage(ctx, cursor, d.facets[0].DueContextDeletionPage, d.cleaner.Clean)
		}
		for loc, outcome := range outcomes {
			if last[loc] != outcome && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "hub-worker context deletion: "+outcome)
			}
		}
		last = outcomes
		if !sleepContext(ctx, contextDeletionSweep) {
			return
		}
	}
}

// Sweep exactly one bounded page. Listing advances the scheduling cursor even
// when every cleanup fails, so those rows cannot starve later due work. SQL's
// fixed pass cutoff makes the cursor wrap and retry failures despite arrivals.
// A failed/expired list keeps the original cursor; no cleanup effect follows it.
func sweepContextDeletionPage(ctx context.Context, cursor postgres.ContextDeletionCursor, list func(context.Context, postgres.ContextDeletionCursor) (postgres.ContextDeletionPage, error), clean func(context.Context, artifact.Location) error) (postgres.ContextDeletionCursor, map[artifact.Location]string) {
	outcomes := map[artifact.Location]string{}
	if ctx.Err() != nil {
		return cursor, outcomes
	}
	read, end := context.WithTimeout(ctx, 5*time.Second)
	page, err := list(read, cursor)
	if err == nil {
		err = read.Err()
	}
	end()
	if err != nil {
		outcomes[artifact.Location{}] = "list " + regionalOutcome(err)
		return cursor, outcomes
	}
	for _, loc := range page.Locations {
		if ctx.Err() != nil {
			break
		}
		outcomes[loc] = regionalOutcome(clean(ctx, loc))
	}
	return page.Next, outcomes
}

// contextDeadlinePages bounds one sweep's deadline observation: sixteen
// captures per SQL page, so at most 128 captures per 30-second sweep.
const contextDeadlinePages = 8

// observeContextDeadlines marks unpublished captures whose original deadline
// elapsed (ADR-223), page by page while pages are full. It returns an empty
// outcome on success and a fixed outcome on the first failed page.
func observeContextDeadlines(ctx context.Context, observe func(context.Context, int) (int64, error)) string {
	for range contextDeadlinePages {
		if ctx.Err() != nil {
			return ""
		}
		page, end := context.WithTimeout(ctx, 5*time.Second)
		n, err := observe(page, 16)
		end()
		if err != nil {
			return "deadline observation " + regionalOutcome(err)
		}
		if n < 16 {
			return ""
		}
	}
	return ""
}

// evidenceDeleteStorage reads the evidence list-and-delete credential
// (`<name>-s3-hub-worker-evidence-delete`) for each request, so a rotated
// Secret applies without a restart.
type evidenceDeleteStorage struct{ inputs *providerInputs }

func (s evidenceDeleteStorage) Retrieve(ctx context.Context) (aws.Credentials, error) {
	var zero aws.Credentials
	b, err := s.inputs.read(ctx, contracts.HubWorkerEvidenceDeleteStorageFile, 32<<10)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(b))
	if err != nil || !identity.Text(c.AccessKeyID, 256) || !identity.Text(c.SecretAccessKey, 8192) || c.SessionToken != "" {
		return zero, mounts.ErrUnavailable
	}
	return aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, Source: "evidence-delete"}, nil
}

// installedContextDeletionAudit writes the signed, encrypted deletion record
// under the authority audit admission and audit-only storage principal
// (ADR-205 decision 5). A retry reuses an object already written for the
// same checkpoint.
type installedContextDeletionAudit struct {
	authority  *authorityAuditTurn
	audit      *installedConfigurationAudit
	signatures *jose.RemoteContextDeletionSignatures
}

func (s *installedContextDeletionAudit) WriteContextDeletion(ctx context.Context, r privacy.ContextDeletionCheckpoint) (audit.Receipt, error) {
	if s == nil || s.authority == nil || s.audit == nil || s.audit.providers == nil || s.signatures == nil || ctx == nil || ctx.Err() != nil || !r.Valid() {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return admittedAuthorityAudit(ctx, s.authority, s.audit, func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		writer := &objectstore.ContextDeletionObjects{Store: store, Seal: s.audit.providers.Sealer(), Open: s.audit.providers.Opener(), Signer: s.signatures, Verifier: s.signatures}
		return writer.WriteContextDeletion(call, r)
	})
}

var _ privacyapp.ContextDeletionWriter = (*installedContextDeletionAudit)(nil)
