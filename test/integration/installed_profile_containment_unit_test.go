package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestInstalledProfileComparisonContainmentPreparedLocalFiles(t *testing.T) {
	dir := os.Getenv("ASSERVAT_PROFILE_CONTAINMENT_PREPARED")
	if dir == "" {
		t.Skip("explicit local harness producer/consumer composition")
	}
	b, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil || len(b) > 64<<10 {
		t.Fatal("bounded local harness report", err)
	}
	var report struct {
		Fixture installedProfileContainmentFixture `json:"profileContainment"`
	}
	if err := json.Unmarshal(b, &report); err != nil {
		t.Fatal("Python harness to Go fixture metadata", err)
	}
	for index, input := range report.Fixture.Manifest.Inputs {
		native, err := os.ReadFile(filepath.Join(dir, "image", input.Filename))
		if err != nil {
			t.Fatal(err)
		}
		if err := acceptedHeavySourceMatches(&report.Fixture, index, native); err != nil {
			t.Fatal("actual prepared native/metadata round trip", err)
		}
		clear(native)
	}
	probe, err := os.ReadFile(filepath.Join(dir, "image", "worker-resource-probe"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(probe)
	if hex.EncodeToString(sum[:]) != report.Fixture.ResourceProbeSHA256 {
		t.Fatal("actual finite probe build hash mismatch")
	}
	t.Log("actual separate producer -> Python manifest/hash/mode admission -> Go source ordinal/native hash and probe binary metadata matched; no installed worker claim")
}

func TestInstalledProfileComparisonAcceptedHeavySelectorAndFunding(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "profile-comparison")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "accepted-heavy")
	if !installedAcceptedHeavyComparison() || installedHeapProfileVariant() || nativeCapacityProfile().Records != 40 || !installedRecordingFocus() || installedClusterCount() != 2 {
		t.Fatal("heavy variant changed comparison placement/funding")
	}
	system, burst := installedCapacityObjectPartitions()
	bytes, objects := installedRegionalContextReserve()
	if system != 20000 || burst != 30000 || bytes != 79429632 || objects != 32 {
		t.Fatal("accepted-heavy input introduced new funding", system, burst, bytes, objects)
	}
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "cpu")
	if installedAcceptedHeavyComparison() {
		t.Fatal("ordinary comparison silently selected synthetic heavy input")
	}
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "accepted-heavy")
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-profile")
	defer func() {
		if recover() == nil {
			t.Error("heavy input must refuse another focus")
		}
	}()
	installedAcceptedHeavyComparison()
}

func TestInstalledProfileComparisonResourceProbeContract(t *testing.T) {
	sha := strings.Repeat("a", 64)
	base := workerCgroupObservation{Format: "asservat-worker-cgroup-observation/v1", ObservedAt: time.Now().UTC(), BinarySHA256: sha, MemoryMax: workerCgroupLimit{Value: 384 << 20}, MemoryCurrent: 200 << 20, MemoryPeak: 260 << 20, CPUQuota: workerCgroupLimit{Value: 50000}, CPUPeriod: 100000, MemoryEvents: map[string]int64{"oom": 0, "oom_kill": 0}, CPUStat: map[string]int64{"usage_usec": 1500000, "user_usec": 1400000, "system_usec": 100000, "nr_periods": 40, "nr_throttled": 10, "throttled_usec": 1200000}}
	if !base.valid(sha) {
		t.Fatal("complete fixed worker observation refused")
	}
	for name, change := range map[string]func(*workerCgroupObservation){
		"wrong-helper":        func(o *workerCgroupObservation) { o.BinarySHA256 = strings.Repeat("b", 64) },
		"unbounded-memory":    func(o *workerCgroupObservation) { o.MemoryMax.Unlimited = true },
		"wrong-memory":        func(o *workerCgroupObservation) { o.MemoryMax.Value = 512 << 20 },
		"peak-over-limit":     func(o *workerCgroupObservation) { o.MemoryPeak = 385 << 20 },
		"missing-peak":        func(o *workerCgroupObservation) { o.MemoryPeak = 0 },
		"unbounded-cpu":       func(o *workerCgroupObservation) { o.CPUQuota.Unlimited = true },
		"wrong-cpu":           func(o *workerCgroupObservation) { o.CPUQuota.Value = 100000 },
		"oom":                 func(o *workerCgroupObservation) { o.MemoryEvents["oom"] = 1 },
		"oom-kill":            func(o *workerCgroupObservation) { o.MemoryEvents["oom_kill"] = 1 },
		"missing-cpu-counter": func(o *workerCgroupObservation) { delete(o.CPUStat, "nr_throttled") },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			changed.MemoryEvents = maps.Clone(base.MemoryEvents)
			changed.CPUStat = maps.Clone(base.CPUStat)
			change(&changed)
			if changed.valid(sha) {
				t.Fatal("invalid observer evidence accepted")
			}
		})
	}
	base.CPUStat["nr_throttled"], base.CPUStat["throttled_usec"] = 0, 0
	if !base.valid(sha) {
		t.Fatal("a real quota without observed throttling must remain explicit, not invent throttling")
	}
}

func TestInstalledProfileComparisonResourceProbePinsOriginalPod(t *testing.T) {
	worker := value.AcquisitionWorker{Binding: value.AcquisitionWorkerBinding{Namespace: "private-workers", Pod: "original-pod", PodUID: "original-uid", Job: "original-job", JobUID: "job-uid"}, Intent: value.AcquisitionWorkerIntent{Profile: value.DownloadWorkerProfile{Image: "fixture@sha256:original"}}}
	controller := true
	pod := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: worker.Binding.Pod, Namespace: worker.Binding.Namespace, UID: types.UID(worker.Binding.PodUID), OwnerReferences: []meta.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: worker.Binding.Job, UID: types.UID(worker.Binding.JobUID), Controller: &controller}}}, Spec: core.PodSpec{Containers: []core.Container{{Name: "acquisition", Image: "fixture@sha256:original", Resources: core.ResourceRequirements{Limits: core.ResourceList{core.ResourceMemory: resource.MustParse("384Mi"), core.ResourceCPU: resource.MustParse("500m")}}}}}, Status: core.PodStatus{ContainerStatuses: []core.ContainerStatus{{Name: "acquisition", ContainerID: "original-container", ImageID: "sha256:original"}}}}
	if !comparisonResourcePodMatches(worker, pod) {
		t.Fatal("exact pinned resource worker refused")
	}
	for name, change := range map[string]func(*core.Pod){"replacement-pod": func(p *core.Pod) { p.UID = "replacement" }, "replacement-job": func(p *core.Pod) { p.OwnerReferences[0].UID = "replacement" }, "wrong-container": func(p *core.Pod) { p.Spec.Containers[0].Name = "other" }, "raised-memory": func(p *core.Pod) {
		p.Spec.Containers[0].Resources.Limits[core.ResourceMemory] = resource.MustParse("512Mi")
	}} {
		t.Run(name, func(t *testing.T) {
			changed := pod.DeepCopy()
			change(changed)
			if comparisonResourcePodMatches(worker, changed) {
				t.Fatal("resource worker identity/limits changed")
			}
		})
	}
}

func TestInstalledProfileComparisonAcceptedHeavyNativeHashPins(t *testing.T) {
	// The real generator component separately proves native/semantic shape;
	// this pure check isolates immutable downloaded-byte/ordinal matching.
	native := make([]byte, (8<<20)+1)
	hash := sha256.Sum256(native)
	f := &installedProfileContainmentFixture{Manifest: acceptedHeavyManifest{Format: "accepted-heavy-pprof-fixture/v1", ProfileType: "cpu", SampleType: "cpu", Unit: "nanoseconds", DurationNanos: int64(10 * time.Second), Inputs: make([]acceptedHeavyInput, 2)}}
	for index, side := range []string{"baseline", "incident"} {
		f.Manifest.Inputs[index] = acceptedHeavyInput{Filename: "profile-heavy-" + side + ".pb.gz", Side: side, Functions: 100000, Locations: 100000, Samples: 100000, FrameVisits: 1048576, SampleLocationReferences: 1048576, InlineLines: 100000, ValuesPerSample: 16, SampleTypes: 16, NumericLabels: 32768, StringTableEntries: 100021, SharedUnits: 662144, ProtobufBytes: (16 << 20) - 56, NativeBytes: int64(len(native)), NativeSHA256: hex.EncodeToString(hash[:])}
		if err := acceptedHeavySourceMatches(f, index, native); err != nil {
			t.Fatal(err)
		}
	}
	f.Manifest.Inputs[0], f.Manifest.Inputs[1] = f.Manifest.Inputs[1], f.Manifest.Inputs[0]
	if acceptedHeavySourceMatches(f, 0, native) == nil {
		t.Fatal("source ordinal swap accepted")
	}
	f.Manifest.Inputs[0], f.Manifest.Inputs[1] = f.Manifest.Inputs[1], f.Manifest.Inputs[0]
	native[0] = 1
	if acceptedHeavySourceMatches(f, 0, native) == nil {
		t.Fatal("changed native bytes accepted")
	}
}
