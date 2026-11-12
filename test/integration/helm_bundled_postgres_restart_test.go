package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5/pgxpool"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// These snapshots contain public identity/incarnation facts only, never Secret
// payloads. They deliberately separate original activation from the live process.
type bundledPostgresSQLSnapshot struct {
	Database                                          string
	DatabaseOID                                       uint32
	SystemIdentifier                                  string
	Timeline                                          int32
	PostmasterAt                                      time.Time
	ActivatedPostmasterAt                             time.Time
	ActivatedDatabaseOID                              uint32
	ActivatedSystemIdentifier                         string
	ActivatedTimeline                                 int32
	RecoveryBlocked, Suspended, InRecovery            bool
	CurrentTrust, RestartRecorded, PermissionsCurrent bool
}
type bundledPostgresKubernetesSnapshot struct {
	Namespace, StatefulSetName, PodName, Image                       string
	StatefulSetUID, PodUID, StateSecretUID, DataPVCUID, BackupPVCUID types.UID
	StatefulSetGeneration                                            int64
	DataVolumeName, BackupVolumeName                                 string
	StatefulSetSpec                                                  apps.StatefulSetSpec
}
type bundledPostgresRestartSnapshot struct {
	SQL        bundledPostgresSQLSnapshot
	Kubernetes bundledPostgresKubernetesSnapshot
}
type bundledPostgresRestartResult struct {
	Before, After bundledPostgresRestartSnapshot
	Elapsed       time.Duration
}

// restartHelmBundledPostgres performs exactly one normal-grace, UID-preconditioned
// Pod deletion. All SQL is read-only: reactivation belongs to the running fleet
// observer. The original verified-TLS administrator pool is reset, not rebuilt.
func restartHelmBundledPostgres(t *testing.T, parent context.Context, admin *pgxpool.Pool, api kubernetes.Interface, plan contracts.SmallPostgresPlan, image, installation string) bundledPostgresRestartResult {
	t.Helper()
	if !plan.Valid() || image == "" || installation == "" || admin == nil || api == nil {
		t.Fatal("bundled PostgreSQL restart: invalid original inputs")
	}
	ctx, stop := context.WithTimeout(parent, 3*time.Minute)
	defer stop()
	started := time.Now()
	var result bundledPostgresRestartResult
	var err error
	result.Before.Kubernetes, err = readBundledPostgresKubernetes(ctx, api, plan, image)
	if err != nil {
		t.Fatalf("bundled PostgreSQL restart: original Kubernetes pins: %v", err)
	}
	result.Before.SQL, err = readBundledPostgresSQL(ctx, admin, installation)
	if err != nil {
		t.Fatalf("bundled PostgreSQL restart: original SQL read unavailable (%T)", err)
	}
	if !result.Before.SQL.current() {
		t.Fatal("bundled PostgreSQL restart: original SQL incarnation/trust/permissions unavailable")
	}
	if err = deleteBundledPostgresPod(ctx, api, result.Before.Kubernetes); err != nil {
		t.Fatalf("bundled PostgreSQL restart: exact Pod deletion unavailable (%T)", err)
	}
	// Reset closes old pooled sockets while preserving the complete original TLS,
	// endpoint, database and login configuration. No SQL activation is performed.
	admin.Reset()
	for {
		after, readErr := readBundledPostgresKubernetes(ctx, api, plan, image)
		if readErr == nil {
			if err = unchangedBundledPostgresKubernetes(result.Before.Kubernetes, after); err != nil {
				t.Fatal(err)
			}
			if after.PodUID != result.Before.Kubernetes.PodUID {
				result.After.Kubernetes = after
				break
			}
		} else if !errors.Is(readErr, errBundledPostgresPodPending) {
			t.Fatalf("bundled PostgreSQL restart: Kubernetes readback: %v", readErr)
		}
		if installedJourneyPause(ctx, installedPoll) != nil {
			t.Fatal("bundled PostgreSQL restart: replacement Pod readiness deadline")
		}
	}
	var lastSQL bundledPostgresSQLSnapshot
	for {
		after, readErr := readBundledPostgresSQL(ctx, admin, installation)
		if readErr == nil {
			lastSQL = after
			if err = unchangedBundledPostgresSQL(result.Before.SQL, after); err != nil {
				t.Fatal(err)
			}
			if after.PostmasterAt.After(result.Before.SQL.PostmasterAt) && after.current() && after.RestartRecorded {
				result.After.SQL = after
				break
			}
		}
		if installedJourneyPause(ctx, installedPoll) != nil {
			t.Fatalf("bundled PostgreSQL restart: product readiness deadline: new_postmaster=%t current_trust=%t restart_recorded=%t permissions_current=%t stored_recovery_blocked=%t suspended=%t in_recovery=%t read_error=%T", lastSQL.PostmasterAt.After(result.Before.SQL.PostmasterAt), lastSQL.CurrentTrust, lastSQL.RestartRecorded, lastSQL.PermissionsCurrent, lastSQL.RecoveryBlocked, lastSQL.Suspended, lastSQL.InRecovery, readErr)
		}
	}
	// Recheck retained pins after the observer completed, not only while SQL was
	// coming back. A later replacement cannot satisfy the original Pod proof.
	last, err := readBundledPostgresKubernetes(ctx, api, plan, image)
	if err != nil || unchangedBundledPostgresKubernetes(result.Before.Kubernetes, last) != nil || last.PodUID != result.After.Kubernetes.PodUID {
		t.Fatal("bundled PostgreSQL restart: retained pins changed during reactivation")
	}
	result.Elapsed = time.Since(started)
	t.Logf("bundled PostgreSQL restart: normal-grace replacement, retained StatefulSet/PVC/Secret UIDs and activation; new process with original database/system/timeline, product restart lineage and current trust/permissions (%s)", result.Elapsed.Round(time.Millisecond))
	return result
}

func readBundledPostgresSQL(ctx context.Context, admin *pgxpool.Pool, installation string) (bundledPostgresSQLSnapshot, error) {
	var s bundledPostgresSQLSnapshot
	read, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	err := admin.QueryRow(read, `SELECT current_database(),
 (SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
 (pg_control_system()).system_identifier::text,
 CASE WHEN pg_is_in_recovery() THEN 0 ELSE ('x'||substr(pg_walfile_name(pg_current_wal_lsn()),1,8))::bit(32)::integer END,
 pg_postmaster_start_time(),t.activated_postmaster_at,t.activated_database_oid::bigint,
 t.activated_system_identifier,t.activated_timeline,t.recovery_blocked,t.suspended,pg_is_in_recovery(),
 EXISTS(SELECT 1 FROM fleet_current_trust c WHERE c.installation_id=t.installation_id AND NOT c.recovery_blocked AND NOT c.suspended AND c.fresh_until>clock_timestamp()),
 EXISTS(SELECT 1 FROM database_restart WHERE started_at=pg_postmaster_start_time()),
 (SELECT COALESCE(bool_and(COALESCE(NOT suspended AND observed_at>pg_postmaster_start_time() AND fresh_until>clock_timestamp(),false)),false) FROM permission_stream)
 FROM fleet_trust t WHERE t.installation_id=$1`, installation).Scan(
		&s.Database, &s.DatabaseOID, &s.SystemIdentifier, &s.Timeline, &s.PostmasterAt, &s.ActivatedPostmasterAt, &s.ActivatedDatabaseOID, &s.ActivatedSystemIdentifier, &s.ActivatedTimeline, &s.RecoveryBlocked, &s.Suspended, &s.InRecovery, &s.CurrentTrust, &s.RestartRecorded, &s.PermissionsCurrent)
	return s, err
}
func (s bundledPostgresSQLSnapshot) current() bool {
	return s.Database != "" && s.DatabaseOID != 0 && s.SystemIdentifier != "" && s.Timeline > 0 && !s.PostmasterAt.IsZero() && !s.ActivatedPostmasterAt.IsZero() && !s.ActivatedPostmasterAt.After(s.PostmasterAt) && s.DatabaseOID == s.ActivatedDatabaseOID && s.SystemIdentifier == s.ActivatedSystemIdentifier && s.Timeline == s.ActivatedTimeline && !s.RecoveryBlocked && !s.Suspended && !s.InRecovery && s.CurrentTrust && s.PermissionsCurrent
}
func unchangedBundledPostgresSQL(before, after bundledPostgresSQLSnapshot) error {
	if before.Database != after.Database || before.DatabaseOID != after.DatabaseOID || before.SystemIdentifier != after.SystemIdentifier || before.Timeline != after.Timeline || !before.ActivatedPostmasterAt.Equal(after.ActivatedPostmasterAt) || before.ActivatedDatabaseOID != after.ActivatedDatabaseOID || before.ActivatedSystemIdentifier != after.ActivatedSystemIdentifier || before.ActivatedTimeline != after.ActivatedTimeline || after.PostmasterAt.Before(before.PostmasterAt) || after.InRecovery {
		return errors.New("bundled PostgreSQL restart: database/cluster/timeline/original activation changed")
	}
	return nil
}

var errBundledPostgresPodPending = errors.New("bundled PostgreSQL Pod not Ready")

func readBundledPostgresKubernetes(ctx context.Context, api kubernetes.Interface, plan contracts.SmallPostgresPlan, image string) (bundledPostgresKubernetesSnapshot, error) {
	var s bundledPostgresKubernetesSnapshot
	s.Namespace, s.StatefulSetName, s.PodName, s.Image = plan.Namespace, plan.ServiceName(), plan.ServiceName()+"-0", image
	sts, err := api.AppsV1().StatefulSets(plan.Namespace).Get(ctx, s.StatefulSetName, meta.GetOptions{})
	if err != nil {
		return s, fmt.Errorf("StatefulSet read: %w", err)
	}
	if sts.Name != s.StatefulSetName || sts.Namespace != s.Namespace || sts.UID == "" || sts.Generation <= 0 || sts.DeletionTimestamp != nil || sts.Spec.Replicas == nil || *sts.Spec.Replicas != 1 || sts.Spec.ServiceName != s.StatefulSetName || !bundledPostgresPodSpec(sts.Spec.Template.Spec, plan, image) {
		return s, errors.New("bundled PostgreSQL StatefulSet identity/spec changed")
	}
	s.StatefulSetUID, s.StatefulSetGeneration, s.StatefulSetSpec = sts.UID, sts.Generation, *sts.Spec.DeepCopy()
	raw, err := api.CoreV1().RESTClient().Get().AbsPath("/api/v1/namespaces/"+plan.Namespace+"/secrets/"+plan.StateSecretName()).SetHeader("Accept", "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1").MaxRetries(0).DoRaw(ctx)
	if err != nil {
		return s, errors.New("bundled PostgreSQL state metadata unavailable")
	}
	var secret meta.PartialObjectMetadata
	if len(raw) > 32<<10 || json.Unmarshal(raw, &secret) != nil || secret.Kind != "PartialObjectMetadata" || secret.APIVersion != "meta.k8s.io/v1" || secret.Name != plan.StateSecretName() || secret.Namespace != plan.Namespace || secret.UID == "" || secret.ResourceVersion == "" || secret.DeletionTimestamp != nil || len(secret.OwnerReferences) != 0 || len(secret.Finalizers) != 0 || secret.Labels["asservat.io/private-role"] != "small-postgres" {
		return s, errors.New("bundled PostgreSQL state metadata changed")
	}
	s.StateSecretUID = secret.UID
	for _, name := range []string{plan.DataPVCName(), plan.BackupPVCName()} {
		pvc, err := api.CoreV1().PersistentVolumeClaims(plan.Namespace).Get(ctx, name, meta.GetOptions{})
		if err != nil {
			return s, fmt.Errorf("retained PVC read: %w", err)
		}
		if pvc.Name != name || pvc.Namespace != plan.Namespace || pvc.UID == "" || pvc.DeletionTimestamp != nil || pvc.Status.Phase != core.ClaimBound || pvc.Spec.VolumeName == "" {
			return s, errors.New("bundled PostgreSQL retained PVC changed")
		}
		if name == plan.DataPVCName() {
			s.DataPVCUID, s.DataVolumeName = pvc.UID, pvc.Spec.VolumeName
		} else {
			s.BackupPVCUID, s.BackupVolumeName = pvc.UID, pvc.Spec.VolumeName
		}
	}
	pod, err := api.CoreV1().Pods(plan.Namespace).Get(ctx, s.PodName, meta.GetOptions{})
	if apierrors.IsNotFound(err) {
		return s, errBundledPostgresPodPending
	}
	if err != nil {
		return s, err
	}
	owner := meta.GetControllerOf(pod)
	if pod.Name != s.PodName || pod.Namespace != s.Namespace || pod.UID == "" || owner == nil || owner.APIVersion != "apps/v1" || owner.Kind != "StatefulSet" || owner.Name != s.StatefulSetName || owner.UID != s.StatefulSetUID || !bundledPostgresPodSpec(pod.Spec, plan, image) {
		return s, errors.New("bundled PostgreSQL Pod owner/image/volumes changed")
	}
	s.PodUID = pod.UID
	if pod.DeletionTimestamp != nil || pod.Status.Phase != core.PodRunning || len(pod.Status.ContainerStatuses) != 2 {
		return s, errBundledPostgresPodPending
	}
	ready := map[string]bool{}
	for _, status := range pod.Status.ContainerStatuses {
		if status.State.Running != nil && status.Ready {
			ready[status.Name] = true
		}
	}
	if !ready["postgres"] || !ready["backup"] {
		return s, errBundledPostgresPodPending
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == core.PodReady && condition.Status == core.ConditionTrue {
			return s, nil
		}
	}
	return s, errBundledPostgresPodPending
}
func bundledPostgresPodSpec(spec core.PodSpec, plan contracts.SmallPostgresPlan, image string) bool {
	if len(spec.Containers) != 2 {
		return false
	}
	containers := map[string]bool{}
	for _, container := range spec.Containers {
		if container.Image != image || containers[container.Name] || (container.Name != "postgres" && container.Name != "backup") {
			return false
		}
		containers[container.Name] = true
	}
	data, backup, serverSecret, backupSecret := false, false, false, false
	for _, volume := range spec.Volumes {
		switch volume.Name {
		case "data":
			data = volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == plan.DataPVCName()
		case "backup":
			backup = volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == plan.BackupPVCName()
		case "server-material":
			serverSecret = volume.Secret != nil && volume.Secret.SecretName == plan.StateSecretName()
		case "backup-material":
			backupSecret = volume.Secret != nil && volume.Secret.SecretName == plan.StateSecretName()
		}
	}
	return data && backup && serverSecret && backupSecret
}
func unchangedBundledPostgresKubernetes(before, after bundledPostgresKubernetesSnapshot) error {
	if before.Namespace != after.Namespace || before.StatefulSetName != after.StatefulSetName || before.PodName != after.PodName || before.Image != after.Image || before.StatefulSetUID != after.StatefulSetUID || before.StatefulSetGeneration != after.StatefulSetGeneration || !reflect.DeepEqual(before.StatefulSetSpec, after.StatefulSetSpec) || before.StateSecretUID != after.StateSecretUID || before.DataPVCUID != after.DataPVCUID || before.BackupPVCUID != after.BackupPVCUID || before.DataVolumeName != after.DataVolumeName || before.BackupVolumeName != after.BackupVolumeName {
		return errors.New("bundled PostgreSQL restart: retained StatefulSet/PVC/Secret identity changed")
	}
	return nil
}
func deleteBundledPostgresPod(ctx context.Context, api kubernetes.Interface, before bundledPostgresKubernetesSnapshot) error {
	if before.Namespace == "" || before.PodName == "" || before.PodUID == "" {
		return errors.New("missing original PostgreSQL Pod identity")
	}
	body, err := json.Marshal(meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &before.PodUID}})
	if err != nil {
		return err
	}
	// No mutation retry, no force, no grace override, no controller deletion.
	return api.CoreV1().RESTClient().Delete().AbsPath("/api/v1/namespaces/" + before.Namespace + "/pods/" + before.PodName).Body(body).MaxRetries(0).Do(ctx).Error()
}

// The earlier cold-pull proof cordons Node A (helm_bootstrap_test.go), while
// the bundled PostgreSQL local PV is pinned there (helm_bootstrap_postgres_test.go).
// Restore scheduling only after that proof, before deleting the original PG Pod.
func uncordonHelmBundledPostgresNode(ctx context.Context, api kubernetes.Interface, nodeName, nodeUID string) error {
	if api == nil || nodeName == "" || nodeUID == "" {
		return errors.New("missing original PostgreSQL storage node")
	}
	node, err := api.CoreV1().Nodes().Get(ctx, nodeName, meta.GetOptions{})
	if err != nil {
		return err
	}
	if node.Name != nodeName || string(node.UID) != nodeUID || node.ResourceVersion == "" || node.DeletionTimestamp != nil {
		return errors.New("original PostgreSQL storage node changed")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if !node.Spec.Unschedulable {
		return nil
	}
	desired := node.DeepCopy()
	desired.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Node"}
	desired.Spec.Unschedulable = false
	body, err := json.Marshal(desired)
	if err != nil {
		return err
	}
	// Preserve UID/resourceVersion and every other field; an uncertain update is
	// not replayed, and no replacement node or alternate storage is selected.
	var updated core.Node
	err = api.CoreV1().RESTClient().Put().AbsPath("/api/v1/nodes/" + nodeName).Body(body).MaxRetries(0).Do(ctx).Into(&updated)
	if err != nil {
		return err
	}
	if updated.Name != nodeName || string(updated.UID) != nodeUID || updated.Spec.Unschedulable {
		return errors.New("original PostgreSQL storage node update unacknowledged")
	}
	return ctx.Err()
}
