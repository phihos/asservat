package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
)

// errHubWorkerCapacityConfig stops the capacity child (and so the process):
// the capacity section cannot produce a valid qualification.
var errHubWorkerCapacityConfig = errors.New("invalid hub-worker capacity section")

// capacityRetry is the pause between capacity attempts; a transient failure
// never returns from the child.
const capacityRetry = 5 * time.Second

// capacityInitializedAt is the setup time of a stored qualification: the
// builder starts the capture lane's ValidUntil there (the reserve phase later
// sets the planned date in SQL; the stored qualification keeps the original).
// A restart rebuilds with it, so SQL finds the identical qualification.
func capacityInitializedAt(q app.CapacityQualification) time.Time {
	return q.RootBacking.Capture.Policy.ValidUntil
}

// capacityAccountVersion is the capture account MAC version, derived from
// the generated role setup ID as the installer did.
func capacityAccountVersion(ids contracts.InstallationIDs) string {
	return ids.RoleSetupID + "-account/v1"
}

// validateHubWorkerCapacity checks the section's names and that its values
// and qualification are valid.
func validateHubWorkerCapacity(c *contracts.HubWorkerCapacity, ids contracts.InstallationIDs, namespace string) error {
	if c == nil || len(validation.IsDNS1123Subdomain(c.ProcessingSource)) != 0 || c.Revision < 1 {
		return errHubWorkerCapacityConfig
	}
	if _, err := capacityRuntimeProcessingPaths(capacityPaths(c)); err != nil {
		return errHubWorkerCapacityConfig
	}
	if _, err := capacityValues(c.CapacityValues); err != nil {
		return err
	}
	// The processing source UID is a placeholder here; only the settings decide.
	if _, err := buildHubWorkerQualification(c, ids, namespace, ids.ClusterID, time.Now()); err != nil {
		return errHubWorkerCapacityConfig
	}
	return nil
}

// capacityValues converts the Helm values to bytes: the system reserve is
// 1/16 of the evidence storage and the default hard limit 10 %, raised
// to the effective share.
func capacityValues(c contracts.CapacityValues) (app.CapacityValues, error) {
	total, err := resource.ParseQuantity(c.EvidenceStorage)
	if err != nil || total.Value() <= 0 {
		return app.CapacityValues{}, errHubWorkerCapacityConfig
	}
	out := app.CapacityValues{EvidenceBytes: total.Value(), ReserveBytes: total.Value() / 16, MaxConcurrentExpensive: max(1, c.Workload.MaxConcurrentExpensive), OnFull: c.Workload.OnFull}
	if out.OnFull == "" {
		out.OnFull = "RejectNewExpensive"
	}
	bytes := func(v string) (int64, error) {
		if v == "" {
			return 0, nil
		}
		if p, ok := strings.CutSuffix(v, "%"); ok {
			f, err := strconv.ParseFloat(p, 64)
			if err != nil || f <= 0 || f > 100 {
				return 0, errHubWorkerCapacityConfig
			}
			return int64(float64(out.EvidenceBytes) * f / 100), nil
		}
		q, err := resource.ParseQuantity(v)
		if err != nil || q.Value() <= 0 {
			return 0, errHubWorkerCapacityConfig
		}
		return q.Value(), nil
	}
	if out.ShareBytes, err = bytes(c.Workload.Share); err != nil {
		return out, err
	}
	if out.LimitBytes, err = bytes(c.Workload.Limit); err != nil {
		return out, err
	}
	if out.LimitBytes == 0 {
		// Default 10%, never below the effective share: the configured share,
		// or at most usable/8 when it is derived (specs/capacity.md).
		share := out.ShareBytes
		if share == 0 {
			share = (out.EvidenceBytes - out.ReserveBytes) / 8
		}
		out.LimitBytes = max(out.EvidenceBytes/10, share)
	}
	if out.NamespaceLimitBytes, err = bytes(c.NamespaceLimit); err != nil {
		return out, err
	}
	if !out.SettingsValid() {
		return out, fmt.Errorf("%w: workload share above its limit or the usable evidence storage", errHubWorkerCapacityConfig)
	}
	return out, nil
}

func capacityPaths(c *contracts.HubWorkerCapacity) []contracts.DownloadEnvironmentPath {
	if c.Paths == nil {
		return []contracts.DownloadEnvironmentPath{}
	}
	return c.Paths
}

// capacitySettings are the internal capacity bookkeeping settings: audit
// lanes, history footprints and the backup profile (ADR-335 D2: internal
// estimates, not values). 125000 capture accounts x 8 records is the
// processing-state bound (MaxCaptures <= 1e6); the envelope is not a limit.
func capacitySettings() contracts.InstallerCapacitySettings {
	f := func(row, wal int64) contracts.InstallerCapacityFootprint {
		return contracts.InstallerCapacityFootprint{RowBytes: row, TransitionWALBytes: wal}
	}
	lane := func(accounts, records int64) contracts.InstallerCapacityLane {
		return contracts.InstallerCapacityLane{Accounts: accounts, Records: records, RetainedSeconds: 10000}
	}
	return contracts.InstallerCapacitySettings{Accounts: 125000, Records: 8, AdmissionSeconds: 86400,
		Lanes:               contracts.InstallerCapacityLanes{CaptureRetainedSeconds: 10000, Normal: lane(1000000, 128), Resolution: lane(1000000, 8), Processing: lane(2, 16)},
		StopRetainedSeconds: 10000, Backup: contracts.CapacityBackup(),
		Footprints: contracts.InstallerCapacityFootprints{Capture: f(128<<10, 256<<10), Operation: f(128<<10, 256<<10), Processing: f(128<<10, 256<<10),
			Native: f(64<<10, 128<<10), Stop: f(128<<10, 256<<10), ProcessingState: f(16<<10, 64<<10)},
		PurgeLeases: 4, Processing: contracts.InstallerCapacityProcessing{MaxRules: 2, MaxRootTransitions: 512},
		Metadata: contracts.InstallerCapacityMetadata{FixedRowBytes: 1 << 20, AccountRowBytes: 256 << 10, RecordRowBytes: 128 << 10, RecordWALBytes: 8 << 20,
			RecordKeyAttempts: 16, TransitionWALBytes: 1 << 20, ConfigurationTransitions: 3 + 3*125000},
		Envelope: contracts.InstallerCapacityEnvelope{SystemObjects: contracts.InstallerCapacityAmount{Bytes: 1 << 62, Objects: 1 << 62},
			SQLBytes: 1 << 62, BackupBytes: 1 << 62, WALBytes: 1 << 62, KeyAttempts: 1 << 62},
		Backends: []contracts.InstallerCapacityBackend{{StorageProfile: "evidence", Usable: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1000000000}}}}
}

// buildHubWorkerQualification is the capacity qualification with
// Helm-native inputs: S values from ids, the processing source UID read by
// name, deterministic source digests and identities derived from
// RoleSetupID and the first initialization time, so a retry builds the same
// qualification.
func buildHubWorkerQualification(c *contracts.HubWorkerCapacity, ids contracts.InstallationIDs, namespace, processingUID string, initialized time.Time) (app.CapacityQualification, error) {
	return buildCapacityQualification(capacitySettings(), capacityDerived{SharedQueries: c.SharedQueries, Root: ids.PermissionRootID, Installation: ids.InstallationID,
		AccountVersion: capacityAccountVersion(ids), SystemPoolUID: uuid.NewSHA1(uuid.MustParse(ids.InstallationID), []byte("capacity/pool")).String(), ProcessingSourceUID: processingUID,
		ProcessingProtection: contracts.ConfigMapSourceDigest(ids.ClusterID, namespace, c.ProcessingSource),
		NamespaceGuards:      []app.CapacityNamespaceQualification{{ClusterID: ids.ClusterID, Digest: contracts.NamespaceSourceDigest(ids.ClusterID, namespace), Keys: contracts.CapacityNamespaceKeys()}},
		Now:                  initialized}, capacityIDs(ids.RoleSetupID))
}

// runCapacity applies the capacity values once per start (a helm upgrade
// restarts the hub-worker) and keeps the child alive; workloads enroll on
// demand in the hub-api. A failure before the setup rows exist retries.
func (w *hubWorker) runCapacity(ctx context.Context) error {
	if w == nil || ctx == nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	if err := validateHubWorkerCapacity(w.config.Capacity, w.ids, w.namespace.Name); err != nil {
		return &fixedStepError{"config", err}
	}
	last := ""
	for ctx.Err() == nil {
		err := w.applyCapacity(ctx)
		if err == nil {
			fmt.Fprintln(os.Stderr, "capacity applied")
			<-ctx.Done()
			break
		}
		if errors.Is(err, errHubWorkerCapacityConfig) {
			return err
		}
		if s := regionalOutcome(err); s != last {
			last = s
			fmt.Fprintln(os.Stderr, "capacity not applied, retrying: "+s)
		}
		t := time.NewTimer(capacityRetry)
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
	}
	return ctx.Err()
}

func (w *hubWorker) applyCapacity(ctx context.Context) (err error) {
	c := w.config.Capacity
	at := "sql"
	defer func() {
		if err != nil && !errors.Is(err, errHubWorkerCapacityConfig) {
			err = &fixedStepError{at, err}
		}
	}()
	call, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	role, known := postgres.PublicRuntimeRoleName(w.ids.InstallationID, "capacity")
	if !known {
		return errHubWorkerCapacityConfig
	}
	pool, err := w.pool(call, contracts.HubWorkerCapacitySQLFile, role, "asservat-capacity")
	if err != nil {
		return err
	}
	defer pool.Close()
	at = "processing-source"
	observer, err := w.kubeClient()
	if err != nil {
		return err
	}
	processingUID, err := observer.ConfigMapUID(call, c.ProcessingSource)
	if err != nil {
		return err
	}
	// The first application's time stays in the stored qualification; a
	// restart rebuilds the identical one.
	at = "qualification"
	initialized := time.Now()
	switch stored, err := postgres.ReadCapacityQualification(call, pool, w.ids.PermissionRootID); {
	case err == nil:
		initialized = stored.RootBacking.Capture.Policy.ValidUntil
	case !errors.Is(err, postgres.ErrCapacityQualificationAbsent):
		return err
	}
	q, err := buildHubWorkerQualification(c, w.ids, w.namespace.Name, processingUID, initialized)
	if err != nil {
		return errHubWorkerCapacityConfig
	}
	values, err := capacityValues(c.CapacityValues)
	if err != nil {
		return err
	}
	at = "apply"
	if q, err = postgres.ApplyCapacity(call, pool, w.ids.ClusterID, w.namespace.UID, q, values); err != nil {
		return err
	}
	// Context deletion purges the one evidence store this qualification names.
	at = "evidence-store-id"
	if len(q.Backends) != 1 {
		return errHubWorkerCapacityConfig
	}
	return w.publishEvidenceStoreID(q.Backends[0].EvidenceStoreID)
}
