package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/domain/authorization"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Resolve the physical API once, before any installation plan or effect. The
// descriptor remains factual: logical region 1 never overwrites cluster 1.
func installerContextRegionalIndex(helmContext bool, focus, topology string, clusters int) (int, error) {
	if topology != "" && topology != "separate-api" && topology != "same-api" {
		return 0, errors.New("unknown Helm context topology")
	}
	if topology != "" && !helmContext || helmContext && focus != "journey" {
		return 0, errors.New("explicit topology requires the actual Helm context journey")
	}
	index := 1
	if topology == "same-api" {
		index = 0
	}
	if clusters <= index {
		return 0, errors.New("selected physical API is absent from the original fixture")
	}
	return index, nil
}

func TestInstallerContextTopologySelectsOriginalAPI(t *testing.T) {
	for _, tc := range []struct {
		name, topology, focus string
		helm                  bool
		clusters, want        int
		refused               bool
	}{
		{name: "legacy", clusters: 2, want: 1},
		{name: "default Helm", helm: true, focus: "journey", clusters: 2, want: 1},
		{name: "explicit separate", helm: true, focus: "journey", topology: "separate-api", clusters: 2, want: 1},
		{name: "same with unused cluster", helm: true, focus: "journey", topology: "same-api", clusters: 2},
		{name: "one physical cluster", helm: true, focus: "journey", topology: "same-api", clusters: 1},
		{name: "missing separate API", helm: true, focus: "journey", clusters: 1, refused: true},
		{name: "unknown", helm: true, focus: "journey", topology: "combined", clusters: 2, refused: true},
		{name: "ordinary runtime", topology: "same-api", clusters: 2, refused: true},
		{name: "explicit separate without Helm", topology: "separate-api", clusters: 2, refused: true},
		{name: "other focus", helm: true, focus: "browser", topology: "same-api", clusters: 2, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := installerContextRegionalIndex(tc.helm, tc.focus, tc.topology, tc.clusters)
			if (err != nil) != tc.refused || err == nil && got != tc.want {
				t.Fatal("topology selection", got, err)
			}
		})
	}
}

// The independent original hub observer must see the same concrete identities
// used by the regional journey; API selection cannot pass by mixing clusters.
func assertSameAPIRegionalTarget(t *testing.T, ctx context.Context, hub kubernetes.Interface, installed kube.RegionalInstallation, w regionalWorkload, podName string, target authorization.Target) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connector, err := hub.CoreV1().Namespaces().Get(ctx, installed.Namespace.Name, meta.GetOptions{})
	if err != nil || string(connector.UID) != installed.Namespace.UID {
		t.Fatal("same-api original hub does not hold the installed connector namespace", err)
	}
	namespace, err := hub.CoreV1().Namespaces().Get(ctx, w.ns.Name, meta.GetOptions{})
	if err != nil || string(namespace.UID) != target.NamespaceUID {
		t.Fatal("same-api original target namespace differs on hub API", err)
	}
	workload, err := hub.AppsV1().Deployments(w.ns.Name).Get(ctx, w.app.Name, meta.GetOptions{})
	if err != nil || string(workload.UID) != target.WorkloadUID {
		t.Fatal("same-api original target workload differs on hub API", err)
	}
	pod, err := hub.CoreV1().Pods(w.ns.Name).Get(ctx, podName, meta.GetOptions{})
	if err != nil || string(pod.UID) != target.PodUID {
		t.Fatal("same-api original selected Pod differs on hub API", err)
	}
	t.Log("same-api original hub independently observed the exact connector, namespace, workload and selected Pod UIDs")
}

func assertUnusedRegionalAPI(t *testing.T, ctx context.Context, f fixture, connectorNamespace, workloadNamespace string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if len(f.Clusters) == 1 {
		t.Log("same-api trial has one physical API and no unused cluster")
		return
	}
	config, err := clientcmd.BuildConfigFromFlags("", f.Clusters[1].Config)
	if err != nil {
		t.Fatal("unused physical API configuration", err)
	}
	api, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal("unused physical API observer", err)
	}
	for _, name := range []string{connectorNamespace, workloadNamespace} {
		if _, err := api.CoreV1().Namespaces().Get(ctx, name, meta.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatal("same-api trial touched the unused physical workload API", name, err)
		}
	}
	t.Log("same-api unused physical API contains neither the actual connector nor workload namespace")
}
