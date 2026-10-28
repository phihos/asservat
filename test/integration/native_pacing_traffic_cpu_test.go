package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Test-only reads of the exact target cgroup in its owned Kind node. These
// cover the target cgroup, including its background work; they do not
// attribute recorder CPU. Wall intervals also include node-side command overhead.
type nativeTrafficCPU struct {
	StartedAt, FinishedAt time.Time
	ContainerID           string
	Quota, Period         uint64
	Counters              map[string]uint64
}

type nativeCPUOutput struct {
	bytes.Buffer
	limit int
}

func (b *nativeCPUOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("CPU command output exceeds bound")
	}
	return b.Buffer.Write(p)
}
func nativeCPUCommand(ctx context.Context, limit int, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, "docker", args...)
	b := &nativeCPUOutput{limit: limit}
	c.Stdout = b
	if err := c.Run(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func nativeTrafficTargetCPU(ctx context.Context, api kubernetes.Interface, expected *core.Pod) (out nativeTrafficCPU, err error) {
	out.StartedAt = time.Now().UTC()
	defer func() { out.FinishedAt = time.Now().UTC() }()
	pod, err := api.CoreV1().Pods(expected.Namespace).Get(ctx, expected.Name, meta.GetOptions{})
	if err != nil {
		return out, err
	}
	if pod.UID != expected.UID || pod.Spec.NodeName != expected.Spec.NodeName || pod.DeletionTimestamp != nil || len(pod.Status.ContainerStatuses) != 1 || len(expected.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].ContainerID != expected.Status.ContainerStatuses[0].ContainerID {
		return out, errors.New("CPU target changed")
	}
	out.ContainerID = pod.Status.ContainerStatuses[0].ContainerID
	id := strings.TrimPrefix(out.ContainerID, "containerd://")
	rawID, e := hex.DecodeString(id)
	if e != nil || len(rawID) != 32 || id == out.ContainerID {
		return out, errors.New("CPU target container unavailable")
	}
	inspected, err := nativeCPUCommand(ctx, 128<<10, "exec", pod.Spec.NodeName, "crictl", "inspect", id)
	if err != nil {
		return out, err
	}
	var state struct {
		Info struct {
			Pid int64 `json:"pid"`
		} `json:"info"`
		Status struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"status"`
	}
	if json.Unmarshal(inspected, &state) != nil || state.Info.Pid < 1 || state.Info.Pid > 1<<31-1 || state.Status.ID != id || state.Status.State != "CONTAINER_RUNNING" {
		return out, errors.New("CPU target process unavailable")
	}
	root := "/proc/" + strconv.FormatInt(state.Info.Pid, 10) + "/root/sys/fs/cgroup/"
	observed, err := nativeCPUCommand(ctx, 8192, "exec", pod.Spec.NodeName, "cat", root+"cpu.max", root+"cpu.stat")
	if err != nil {
		return out, err
	}
	return parseNativeTrafficCPU(observed, out)
}
func parseNativeTrafficCPU(raw []byte, out nativeTrafficCPU) (nativeTrafficCPU, error) {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 {
		return out, errors.New("missing CPU measurement")
	}
	quota := strings.Fields(lines[0])
	if len(quota) != 2 {
		return out, errors.New("missing CPU quota")
	}
	var err error
	out.Quota, err = strconv.ParseUint(quota[0], 10, 64)
	if err != nil {
		return out, err
	}
	out.Period, err = strconv.ParseUint(quota[1], 10, 64)
	if err != nil {
		return out, err
	}
	if out.Quota == 0 || out.Period == 0 || out.Period > 1e9 || out.Quota > 1e9 || out.Quota*10 != out.Period {
		return out, errors.New("CPU quota is not installed 100m")
	}
	out.Counters = map[string]uint64{}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) != 2 {
			return out, errors.New("invalid CPU counter")
		}
		switch f[0] {
		case "usage_usec", "user_usec", "system_usec", "nr_periods", "nr_throttled", "throttled_usec":
		default:
			continue
		}
		if _, exists := out.Counters[f[0]]; exists {
			return out, errors.New("duplicate CPU counter")
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			return out, err
		}
		out.Counters[f[0]] = n
	}
	if len(out.Counters) != 6 {
		return out, errors.New("incomplete CPU counters")
	}
	return out, nil
}
func nativeTrafficCPUDelta(a, b nativeTrafficCPU) (map[string]uint64, error) {
	if a.ContainerID == "" || a.ContainerID != b.ContainerID || a.Quota != b.Quota || a.Period != b.Period || len(a.Counters) != 6 || len(b.Counters) != 6 {
		return nil, errors.New("CPU measurement identity changed")
	}
	out := map[string]uint64{}
	for k, v := range a.Counters {
		n, ok := b.Counters[k]
		if !ok || n < v {
			return nil, errors.New("CPU counters moved backward")
		}
		out[k] = n - v
	}
	return out, nil
}

func TestNativeTrafficCPUQuotaAndCountersNeverInventAZero(t *testing.T) {
	raw := []byte("10000 100000\nusage_usec 100\nuser_usec 60\nsystem_usec 40\nnr_periods 9\nnr_throttled 3\nthrottled_usec 700\nburst_usec 0\n")
	first, err := parseNativeTrafficCPU(raw, nativeTrafficCPU{ContainerID: "exact-owned"})
	if err != nil || first.Quota != 10000 || first.Counters["throttled_usec"] != 700 {
		t.Fatal(first, err)
	}
	second, err := parseNativeTrafficCPU(bytes.ReplaceAll(raw, []byte("700"), []byte("900")), nativeTrafficCPU{ContainerID: "exact-owned"})
	delta, err := nativeTrafficCPUDelta(first, second)
	if err != nil || delta["throttled_usec"] != 200 || delta["usage_usec"] != 0 {
		t.Fatal(delta, err)
	}
	for _, broken := range [][]byte{nil, bytes.Replace(raw, []byte("10000"), []byte("max"), 1), bytes.Replace(raw, []byte("10000"), []byte("100000"), 1), bytes.Replace(raw, []byte("user_usec 60\n"), nil, 1), append(append([]byte(nil), raw...), []byte("usage_usec 100\n")...)} {
		if _, err := parseNativeTrafficCPU(broken, nativeTrafficCPU{}); err == nil {
			t.Fatal("unavailable/changed quota or missing data accepted")
		}
	}
	if _, err := nativeTrafficCPUDelta(second, first); err == nil {
		t.Fatal("backward counters accepted")
	}
	second.ContainerID = "replacement"
	if _, err := nativeTrafficCPUDelta(first, second); err == nil {
		t.Fatal("replacement cgroup accepted")
	}
}
