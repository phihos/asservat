package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type acceptedHeavyInput struct {
	Filename                 string            `json:"filename"`
	Side                     string            `json:"side"`
	Functions                int               `json:"functions"`
	Locations                int               `json:"locations"`
	Samples                  int               `json:"samples"`
	FrameVisits              int               `json:"frame_visits"`
	SampleLocationReferences int               `json:"sample_location_references"`
	InlineLines              int               `json:"inline_lines"`
	ValuesPerSample          int               `json:"values_per_sample"`
	SampleTypes              int               `json:"sample_types"`
	NumericLabels            int               `json:"numeric_label_records_with_units"`
	StringTableEntries       int               `json:"string_table_entries"`
	SharedUnits              int               `json:"shared_object_units"`
	ProtobufBytes            int64             `json:"protobuf_bytes"`
	NativeBytes              int64             `json:"native_bytes"`
	ProtobufSHA256           string            `json:"protobuf_sha256"`
	NativeSHA256             string            `json:"native_sha256"`
	Files                    map[string]string `json:"encrypted_fixture_sha256"`
}

type acceptedHeavyManifest struct {
	Format                string               `json:"format"`
	GeneratorBinarySHA256 string               `json:"generator_binary_sha256"`
	GoVersion             string               `json:"go_version"`
	ProfileType           string               `json:"profile_type"`
	SampleType            string               `json:"sample_type"`
	Unit                  string               `json:"unit"`
	DurationNanos         int64                `json:"duration_ns"`
	Inputs                []acceptedHeavyInput `json:"inputs"`
}
type installedProfileContainmentFixture struct {
	ResourceProbeSHA256 string
	OutputDirectory     string // Private harness work directory, collected explicitly at terminal.
	Manifest            acceptedHeavyManifest
}

func installedAcceptedHeavyComparison() bool {
	if os.Getenv("ASSERVAT_PROFILE_VARIANT") != "accepted-heavy" {
		return false
	}
	if installedJourneyFocus() != "profile-comparison" {
		panic("accepted-heavy variant requires profile-comparison focus")
	}
	return true
}
func acceptedHeavySourceMatches(f *installedProfileContainmentFixture, ordinal int, native []byte) error {
	if f == nil || ordinal < 0 || ordinal > 1 || len(f.Manifest.Inputs) != 2 || f.Manifest.Format != "accepted-heavy-pprof-fixture/v1" || f.Manifest.ProfileType != "cpu" || f.Manifest.SampleType != "cpu" || f.Manifest.Unit != "nanoseconds" || f.Manifest.DurationNanos != int64(10*time.Second) {
		return errors.New("accepted-heavy source provenance missing")
	}
	i := f.Manifest.Inputs[ordinal]
	wantSide := []string{"baseline", "incident"}[ordinal]
	h := sha256.Sum256(native)
	if i.Side != wantSide || i.Filename != "profile-heavy-"+wantSide+".pb.gz" || i.NativeBytes != int64(len(native)) || i.NativeSHA256 != hex.EncodeToString(h[:]) || i.NativeBytes <= 8<<20 || i.NativeBytes > 16<<20 || i.ProtobufBytes > 16<<20 || i.ProtobufBytes < (16<<20)-128 || i.Functions != 100000 || i.Locations != 100000 || i.Samples != 100000 || i.FrameVisits != 1048576 || i.SampleLocationReferences != 1048576 || i.InlineLines != 100000 || i.ValuesPerSample != 16 || i.SampleTypes != 16 || i.NumericLabels != 32768 || i.StringTableEntries != 100021 || i.SharedUnits != 662144 || len(i.Files) != 0 {
		return errors.New("downloaded source does not match exact accepted-heavy native/shape")
	}
	return nil
}

type workerCgroupLimit struct {
	Value     int64 `json:"value"`
	Unlimited bool  `json:"unlimited"`
}
type workerCgroupObservation struct {
	Format        string            `json:"format"`
	ObservedAt    time.Time         `json:"observed_at"`
	BinarySHA256  string            `json:"binary_sha256"`
	MemoryMax     workerCgroupLimit `json:"memory_max"`
	MemoryCurrent int64             `json:"memory_current"`
	MemoryPeak    int64             `json:"memory_peak"`
	SwapMax       workerCgroupLimit `json:"swap_max"`
	SwapCurrent   int64             `json:"swap_current"`
	MemoryEvents  map[string]int64  `json:"memory_events"`
	CPUQuota      workerCgroupLimit `json:"cpu_quota"`
	CPUPeriod     int64             `json:"cpu_period"`
	CPUStat       map[string]int64  `json:"cpu_stat"`
}

func (o workerCgroupObservation) valid(probeSHA string) bool {
	if len(probeSHA) != 64 || o.Format != "asservat-worker-cgroup-observation/v1" || o.BinarySHA256 != probeSHA || o.ObservedAt.IsZero() || o.MemoryMax.Unlimited || o.MemoryMax.Value != query.ProfileComparisonWorkerBytes || o.MemoryCurrent < 0 || o.MemoryPeak <= 0 || o.MemoryPeak < o.MemoryCurrent || o.MemoryPeak > o.MemoryMax.Value || o.CPUQuota.Unlimited || o.CPUQuota.Value <= 0 || o.CPUQuota.Value > 1<<50 || o.CPUQuota.Value*2 != o.CPUPeriod || o.SwapCurrent < 0 || o.SwapMax.Value < 0 {
		return false
	}
	for _, key := range []string{"oom", "oom_kill"} {
		n, ok := o.MemoryEvents[key]
		if !ok || n != 0 {
			return false
		}
	}
	for _, key := range []string{"usage_usec", "user_usec", "system_usec", "nr_periods", "nr_throttled", "throttled_usec"} {
		n, ok := o.CPUStat[key]
		if !ok || n < 0 {
			return false
		}
	}
	return o.CPUStat["usage_usec"] > 0
}

type installedComparisonResourceObserver func(index int, handle, operation string, sources [2]installedProfileComparisonSource, complete bool)

func installedComparisonResources(t *testing.T, ctx context.Context, admin *pgxpool.Pool, api kubernetes.Interface, kubeconfig, root string, f *installedProfileContainmentFixture) installedComparisonResourceObserver {
	t.Helper()
	if f == nil || len(f.ResourceProbeSHA256) != 64 || !filepath.IsAbs(f.OutputDirectory) {
		t.Fatal("accepted-heavy resource probe provenance or private output directory missing")
	}
	if info, err := os.Stat(f.OutputDirectory); err != nil || !info.IsDir() {
		t.Fatal("accepted-heavy private output directory unavailable", err)
	}
	return func(index int, handle, operation string, sources [2]installedProfileComparisonSource, complete bool) {
		t.Helper()
		record := map[string]any{"format": "installed-accepted-heavy-worker/v1", "index": index, "handle": handle, "operation": operation, "complete": complete, "resourceQualified": false, "observerIncludedInWholeWorkerCost": true, "counterBaseline": "whole container cumulative through the live probe snapshot, not analyzer-only; subsequent output and idle lifetime are not this counter baseline", "scope": "one accepted-heavy shape; not all parser maxima/64MiB/native runtime overhead"}
		var failure error
		defer func() {
			if failure != nil {
				record["error"] = failure.Error()
			}
			if err := writeComparisonResourceRecord(f.OutputDirectory, index, complete, record); err != nil {
				t.Error(err)
			}
			if complete && failure != nil {
				t.Fatal("accepted-heavy worker resource qualification", failure)
			}
		}()
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		var rawQuery, rawIntent, rawJob, rawBinding []byte
		var nativeClosed, closed, active, uncertain bool
		var units, keys int
		var rootSpent int64
		var roleMasks, readDeadlines json.RawMessage
		read := func() error {
			readCall, stopRead := context.WithTimeout(call, 2*time.Second)
			defer stopRead()
			return admin.QueryRow(readCall, `SELECT q.query,w.intent_json,w.job_json,w.binding_json,coalesce(b.native_closed,false),coalesce(b.closed,false),q.active_batch IS NOT NULL,q.uncertain,
 context_query_units(q.query->'Scope'),(SELECT count(*) FROM context_query_key_binding k WHERE k.query_id=q.id AND k.used_roles=7),
 (SELECT allocated FROM context_query_backing WHERE root_id=q.root_id),
 coalesce((SELECT jsonb_agg(jsonb_build_object('ordinal',source_ordinal,'used_roles',used_roles) ORDER BY source_ordinal) FROM context_query_key_binding WHERE query_id=q.id),'[]'::jsonb),
 jsonb_build_object('batchStartedAt',b.batch->'StartedAt','batchUntil',b.batch->'Until',
 'requestStartedAt',b.batch->'Request'->'Call'->'StartedAt','requestUntil',b.batch->'Request'->'Call'->'Until',
 'operationStartedAt',b.native_operation->'StartedAt','operationUntil',b.native_operation->'Until',
 'authorityCheckedAt',b.native_authority->'CheckedAt','authorityValidUntil',b.native_authority->'ValidUntil',
 'accessUntil',b.native_authority->'AccessUntil')
 FROM context_query q JOIN download_worker w ON w.root_id=q.root_id AND w.id=q.worker_id AND w.query_id=q.id
 LEFT JOIN context_query_batch b ON b.query_id=q.id AND b.generation=q.generation
 WHERE q.root_id=$1 AND q.operation_id=$2`, root, operation).Scan(&rawQuery, &rawIntent, &rawJob, &rawBinding, &nativeClosed, &closed, &active, &uncertain, &units, &keys, &rootSpent, &roleMasks, &readDeadlines)
		}
		if operation == "" {
			failure = errors.New("no acknowledged original query locator; resource failure remains unknown")
			return
		}
		if failure = read(); failure != nil {
			return
		}
		var q query.ContextQuery
		var intent query.ContextProjectionWorkerIntent
		var worker value.AcquisitionWorker
		if json.Unmarshal(rawQuery, &q) != nil || !q.Valid() || json.Unmarshal(rawIntent, &intent) != nil || !intent.Valid() || !intent.Query.Equal(q) || json.Unmarshal(rawJob, &worker.Job) != nil || json.Unmarshal(rawBinding, &worker.Binding) != nil {
			failure = errors.New("resource observer original query/worker binding unavailable")
			return
		}
		worker.Intent = intent.Worker
		baseline, ok := q.Scope.BaselineScope()
		if !ok || !worker.Valid() || handle != "" && q.ID != handle || q.Scope.ArtifactID != sources[1].ArtifactID || baseline.ArtifactID != sources[0].ArtifactID || hex.EncodeToString(q.Scope.Version[:]) != sources[1].Version || hex.EncodeToString(baseline.Version[:]) != sources[0].Version {
			failure = errors.New("resource observer substituted source/query identity")
			return
		}
		record["queryID"], record["workerID"], record["workerUntil"], record["queryUnits"], record["rootUnits"], record["fullyConsumedChildren"] = q.ID, q.WorkerID, q.WorkerUntil, units, rootSpent, keys
		record["observedAt"], record["queryCreatedAt"], record["queryDeadline"] = time.Now().UTC(), q.CreatedAt, q.Deadline
		record["planHardUntil"], record["baselinePlanHardUntil"], record["readDeadlines"] = q.Plan.HardUntil, q.BaselinePlan.HardUntil, readDeadlines
		record["nativeClosed"], record["closed"], record["active"], record["uncertain"] = nativeClosed, closed, active, uncertain
		record["keyRoles"], record["sourcePodUIDs"] = roleMasks, [2]string{baseline.PodUID, q.Scope.PodUID}
		if complete {
			// SQL lookup has its own short timeout. The complete observation
			// retains the original caller/worker interval across close polling,
			// Pod reads and exec; no earlier SQL child can shorten it.
			workerCall, stop := context.WithDeadline(ctx, q.WorkerUntil)
			defer stop()
			call = workerCall
			for !nativeClosed || !closed || active {
				if failure = installedJourneyPause(call, 100*time.Millisecond); failure != nil {
					return
				}
				if failure = read(); failure != nil {
					return
				}
			}
			if units != 20 || keys != 2 || rootSpent != int64(index+1)*20 || uncertain {
				failure = errors.New("resource observer lacks exact paid/joined comparison")
				return
			}
			record["nativeClosed"], record["closed"], record["active"], record["uncertain"], record["keyRoles"], record["readDeadlines"] = nativeClosed, closed, active, uncertain, roleMasks, readDeadlines
			record["observedAt"] = time.Now().UTC()
		}
		readPod := func() (*core.Pod, error) {
			podCall, stopPod := context.WithTimeout(call, 2*time.Second)
			defer stopPod()
			return api.CoreV1().Pods(worker.Binding.Namespace).Get(podCall, worker.Binding.Pod, meta.GetOptions{})
		}
		pod, err := readPod()
		if err != nil {
			failure = err
			return
		}
		record["podUID"], record["node"], record["phase"], record["containerStatuses"] = string(pod.UID), pod.Spec.NodeName, pod.Status.Phase, pod.Status.ContainerStatuses
		if !complete {
			return
		}
		if !comparisonResourcePodMatches(worker, pod) || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].State.Running == nil {
			failure = errors.New("original resource worker unavailable/terminated before finite probe")
			return
		}
		if !time.Now().Before(q.WorkerUntil) {
			failure = errors.New("original worker cutoff passed before finite probe")
			return
		}
		execCall, stopExec := context.WithTimeout(call, 2*time.Second)
		defer stopExec()
		command := exec.CommandContext(execCall, "kubectl", "--kubeconfig", kubeconfig, "-n", worker.Binding.Namespace, "exec", worker.Binding.Pod, "-c", "acquisition", "--", "/worker-resource-probe")
		command.WaitDelay = 250 * time.Millisecond
		probeStarted := time.Now()
		out, err := command.Output()
		record["probeElapsedSeconds"] = time.Since(probeStarted).Seconds()
		if err != nil {
			failure = err
			return
		}
		if len(out) > 64<<10 {
			failure = errors.New("resource probe output exceeded bound")
			return
		}
		var observed workerCgroupObservation
		decoder := json.NewDecoder(bytes.NewReader(out))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&observed) != nil || !observed.valid(f.ResourceProbeSHA256) || call.Err() != nil {
			record["observation"] = observed
			failure = errors.New("actual cgroup bounds/finite probe mismatch")
			return
		}
		current, err := readPod()
		if err != nil || call.Err() != nil || !time.Now().Before(q.WorkerUntil) || !comparisonResourcePodMatches(worker, current) || current.Status.ContainerStatuses[0].ContainerID != pod.Status.ContainerStatuses[0].ContainerID {
			failure = errors.New("resource worker changed during finite exec")
			return
		}
		record["observation"] = observed
		record["resourceQualified"] = true
		t.Logf("accepted-heavy whole worker: query=%s podUID=%s memoryPeak=%d/384MiB cpuUsageUS=%d quota=%d/%d throttledPeriods=%d (observer included, no analyzer-only baseline)", q.ID, pod.UID, observed.MemoryPeak, observed.CPUStat["usage_usec"], observed.CPUQuota.Value, observed.CPUPeriod, observed.CPUStat["nr_throttled"])
	}
}

// The only observer artifacts are fixed names in the private harness directory.
// The Python owner copies them to results after the test has terminated.
func writeComparisonResourceRecord(directory string, index int, complete bool, record map[string]any) error {
	kind := "complete"
	if !complete {
		kind = "failure"
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(directory, fmt.Sprintf("profile-worker-containment-%d-%s.json", index, kind))
	return os.WriteFile(path, append(raw, '\n'), 0600)
}

func comparisonResourcePodMatches(worker value.AcquisitionWorker, pod *core.Pod) bool {
	if pod == nil || string(pod.UID) != worker.Binding.PodUID || pod.Name != worker.Binding.Pod || pod.Namespace != worker.Binding.Namespace || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != "acquisition" || pod.Spec.Containers[0].Resources.Limits.Memory().Value() != query.ProfileComparisonWorkerBytes || pod.Spec.Containers[0].Resources.Limits.Cpu().MilliValue() != 500 || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].Name != "acquisition" || pod.Status.ContainerStatuses[0].ContainerID == "" || pod.Status.ContainerStatuses[0].ImageID == "" || pod.Spec.Containers[0].Image != worker.Intent.Profile.Image {
		return false
	}
	owner := meta.GetControllerOf(pod)
	return owner != nil && string(owner.UID) == worker.Binding.JobUID && owner.Name == worker.Binding.Job && owner.Kind == "Job" && owner.APIVersion == "batch/v1"
}
