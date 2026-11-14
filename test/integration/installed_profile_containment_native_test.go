package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
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
