package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// contextDeletionSweep is how often the deletion child lists due attempts
// (ADR-205 decision 1). The fixed cadence does not extend a capture's
// original deletion deadline or guarantee that a sweep succeeds.
const contextDeletionSweep = 30 * time.Second

// contextDeletionWorker deletes expired context evidence with ADR-111's
// cleaner, one due attempt at a time. A failed or unknown step stays pending:
// the attempt is listed again and Clean resumes from its checkpoint. Its
// store and signing pins arrive with the capacity projection; until then
// every sweep is skipped.
type contextDeletionWorker struct {
	installation, root string
	facets             []*postgres.ContextDeletions
	recovery           *postgres.RecoveryReader
	base               *os.Root
	writer             *installedConfigurationAudit
	admission          *fleetapp.WorkerRuntimeAdmission
	section            func() (contracts.ContextDeletionDeployment, string, bool)
	cleaner            *privacyapp.ContextCleaner
	closers            []func()
}

func (w *contextDeletionWorker) Close() {
	for i := len(w.closers) - 1; i >= 0; i-- {
		w.closers[i]()
	}
	w.closers = nil
}

func openContextDeletion(ctx context.Context, c contracts.PermissionDeployment, pools map[string]*pgxpool.Pool, base *os.Root, writer *installedConfigurationAudit, admission *fleetapp.WorkerRuntimeAdmission, section func() (contracts.ContextDeletionDeployment, string, bool)) (*contextDeletionWorker, error) {
	if !c.ContextDeletion {
		return nil, nil
	}
	if base == nil || writer == nil || writer.providers == nil || admission == nil || section == nil || ctx == nil || ctx.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	w := &contextDeletionWorker{installation: c.InstallationID, root: c.RootID, base: base, writer: writer, admission: admission, section: section}
	for _, purpose := range contracts.PublicRuntimeContextDeletionPurposes() {
		f, e := postgres.NewContextDeletions(ctx, pools[purpose], c.RootID, c.InstallationID)
		if e != nil {
			return nil, &fixedStepError{"sql/" + purpose, mounts.ErrUnavailable}
		}
		w.facets = append(w.facets, f)
	}
	recovery, err := postgres.NewRecoveryReader(ctx, pools["context-cleanup"], c.InstallationID)
	if err != nil {
		return nil, &fixedStepError{"recovery", mounts.ErrUnavailable}
	}
	w.recovery = recovery
	return w, nil
}

// prepare builds the cleaner from the capacity projection's section once.
func (w *contextDeletionWorker) prepare(v contracts.ContextDeletionDeployment, storeID string) error {
	var closers []func()
	complete := false
	defer func() {
		if !complete {
			for i := len(closers) - 1; i >= 0; i-- {
				closers[i]()
			}
		}
	}()
	if !kube.ContextDeletionSectionValid(&v, time.Now()) {
		return &fixedStepError{"section", mounts.ErrUnavailable}
	}
	h, err := ownerHTTP(v.EvidenceStore.Endpoint, v.EvidenceStore.Roots)
	if err != nil {
		return &fixedStepError{"evidence-http", err}
	}
	closers = append(closers, h.CloseIdleConnections)
	evidenceStore, err := objectstore.New(v.EvidenceStore.Endpoint, v.EvidenceStore.Region, v.EvidenceStore.Bucket, evidenceDeleteStorage{&providerInputs{files: w.base, dir: contracts.EvidenceDeleteDirectory}}, h)
	if err != nil {
		return &fixedStepError{"evidence-store", mounts.ErrUnavailable}
	}
	closers = append(closers, evidenceStore.Close)
	purger, err := evidenceStore.ForCustody(storeID)
	if err != nil {
		return &fixedStepError{"evidence-store", mounts.ErrUnavailable}
	}
	s := v.Signing
	public := make(map[string]ed25519.PublicKey, len(s.PublicKeys))
	for id, key := range s.PublicKeys {
		public[id] = ed25519.PublicKey(bytes.Clone(key))
	}
	key, err := w.writer.providers.ContextDeletionSigningKey(s.Mount, s.Key, s.Version, public[s.KeyID])
	if err != nil {
		return &fixedStepError{"signing", mounts.ErrUnavailable}
	}
	closers = append(closers, key.Close)
	signatures, err := jose.NewRemoteContextDeletionSignatures(w.root, s.KeyID, public, key.ForContext)
	if err != nil {
		return &fixedStepError{"signing", mounts.ErrUnavailable}
	}
	objects := &installedContextDeletionAudit{admission: w.admission, audit: w.writer, signatures: signatures}
	w.cleaner = &privacyapp.ContextCleaner{Ledger: w.facets[0], Audit: w.facets[1], Finalize: w.facets[2], Purger: purger, Objects: objects, Recovery: w.recovery, Now: time.Now}
	w.closers = append(w.closers, closers...)
	complete = true
	return nil
}

// run sweeps until the Lease ends, logging each outcome when it changes from
// the previous sweep's.
func (w *contextDeletionWorker) run(ctx context.Context) {
	last := map[artifact.Location]string{}
	var cursor postgres.ContextDeletionCursor
	for ctx.Err() == nil {
		outcomes := map[artifact.Location]string{}
		if w.cleaner == nil {
			if v, storeID, ok := w.section(); !ok {
				outcomes[artifact.Location{}] = "waiting for the capacity projection"
			} else if err := w.prepare(v, storeID); err != nil {
				outcomes[artifact.Location{}] = "prepare " + regionalOutcome(err)
			}
		}
		if w.cleaner != nil {
			cursor, outcomes = sweepContextDeletionPage(ctx, cursor, w.facets[0].DueContextDeletionPage, w.cleaner.Clean)
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

// evidenceDeleteStorage reads the operator's evidence delete credential for
// each request through the stable mount root (ADR-205 decision 4).
type evidenceDeleteStorage struct{ inputs *providerInputs }

func (s evidenceDeleteStorage) Retrieve(ctx context.Context) (aws.Credentials, error) {
	var zero aws.Credentials
	b, err := s.inputs.read(ctx, contracts.EvidenceDeleteCredentialFile, 32<<10)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(b))
	if err != nil || !identity.Text(c.AccessKeyID, 256) || !identity.Text(c.SecretAccessKey, 8192) || c.SessionToken != "" {
		return zero, mounts.ErrUnavailable
	}
	return aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, Source: "protected-evidence-delete"}, nil
}

// installedContextDeletionAudit writes the signed, encrypted deletion record
// under the hub-worker's authority audit admission and audit-only storage
// principal, sealed with its audit Transit key, as the worker configuration
// audit does (ADR-205 decision 5). The record object is created once; a
// retry reuses an object already written for the same checkpoint.
type installedContextDeletionAudit struct {
	admission  *fleetapp.WorkerRuntimeAdmission
	audit      *installedConfigurationAudit
	signatures *jose.RemoteContextDeletionSignatures
}

func (s *installedContextDeletionAudit) WriteContextDeletion(ctx context.Context, r privacy.ContextDeletionCheckpoint) (audit.Receipt, error) {
	if s == nil || s.admission == nil || s.audit == nil || s.audit.providers == nil || s.signatures == nil || ctx == nil || ctx.Err() != nil || !r.Valid() {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	lease, err := s.admission.WaitAuthorityAudit(ctx)
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.admission", mounts.ErrUnavailable}
	}
	defer lease.Release()
	if err = lease.AwaitFleetObservation(); err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.fleet", mounts.ErrUnavailable}
	}
	operation, err := s.audit.providers.BeginAuthorityAudit(lease.Context())
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.begin", mounts.ErrUnavailable}
	}
	defer operation.Close()
	call := operation.Context()
	material, err := operation.Credentials()
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.credentials", mounts.ErrUnavailable}
	}
	store, err := s.audit.storage(material)
	if err != nil {
		return audit.Receipt{}, &fixedStepError{"audit.storage", err}
	}
	defer store.Close()
	writer := &objectstore.ContextDeletionObjects{Store: store, Seal: s.audit.providers.Sealer(), Open: s.audit.providers.Opener(), Signer: s.signatures, Verifier: s.signatures}
	receipt, err := writer.WriteContextDeletion(call, r)
	if err != nil || call.Err() != nil {
		return audit.Receipt{}, &fixedStepError{"audit.write", mounts.ErrUnavailable}
	}
	if err = operation.Finish(); err != nil || call.Err() != nil {
		return audit.Receipt{}, &fixedStepError{"audit.finish", mounts.ErrUnavailable}
	}
	return receipt, nil
}

var _ privacyapp.ContextDeletionWriter = (*installedContextDeletionAudit)(nil)
