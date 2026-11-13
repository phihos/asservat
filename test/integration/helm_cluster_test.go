package integration

import (
	"context"
	"io"
	"strings"
	"testing"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// helmClusterLogs prints the installer hook's own stop lines: a fixed step
// and a closed cause, never inputs.
func helmClusterLogs(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace string) {
	t.Helper()
	pods, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: "job-name=asservat-cluster-installer"})
	if err != nil {
		return
	}
	for _, p := range pods.Items {
		for _, s := range p.Status.ContainerStatuses {
			if s.State.Waiting != nil {
				t.Logf("installer pod %s waiting: %s", p.Name, s.State.Waiting.Reason)
			}
		}
		stream, err := api.CoreV1().Pods(namespace).GetLogs(p.Name, &core.PodLogOptions{LimitBytes: ptr.To(int64(4 << 10))}).Stream(ctx)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(stream, 4<<10))
		stream.Close()
		t.Logf("installer pod %s: %s", p.Name, strings.TrimSpace(string(b)))
	}
}
