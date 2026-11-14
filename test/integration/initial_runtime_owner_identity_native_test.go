package integration

import (
	"context"
	"io"
	"strings"
	"time"

	"asservat.local/asservat/internal/bootstrap"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Failure diagnostics only. These reads cannot grant authority, adopt another
// Pod, retry an effect or change the original failing verdict. Both log streams
// share the original caller's at-most-five-second bound and 8 KiB each. Only
// exact closed startup records survive; arbitrary stdout/stderr is discarded.
func originalOwnerStartupLogDiagnostics(ctx context.Context, api kubernetes.Interface, original *core.Pod) []string {
	if ctx == nil || ctx.Err() != nil || api == nil || original == nil || original.UID == "" {
		return nil
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pods := api.CoreV1().Pods(original.Namespace)
	before, err := pods.Get(call, original.Name, meta.GetOptions{})
	if err != nil || before.UID != original.UID {
		return nil
	}
	var out []string
	for _, previous := range []bool{false, true} {
		limit, tail := int64(8192), int64(32)
		stream, e := pods.GetLogs(original.Name, &core.PodLogOptions{Container: "hub", Previous: previous, LimitBytes: &limit, TailLines: &tail, Follow: false}).Stream(call)
		if e != nil {
			continue
		}
		raw, e := io.ReadAll(io.LimitReader(stream, 8193))
		closeErr := stream.Close()
		if e == nil && closeErr == nil && len(raw) <= 8192 {
			for _, line := range strings.Split(string(raw), "\n") {
				if safe, ok := bootstrap.OwnerStartupDiagnosticLine(line); ok {
					scope := "current"
					if previous {
						scope = "previous"
					}
					out = append(out, scope+": "+safe)
					// One closed startup failure per process invocation is sufficient.
					break
				}
			}
		}
		clear(raw)
	}
	after, err := pods.Get(call, original.Name, meta.GetOptions{})
	if err != nil || after.UID != original.UID || call.Err() != nil {
		return nil
	}
	return out
}
