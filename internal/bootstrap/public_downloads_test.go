package bootstrap

import (
	"os"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

const workerNamespaceID = "33333333-3333-4333-8333-333333333333"

// ADR-204 decision 2: with one pinned worker API in its own namespace, the
// guarded worker profile source is read there, with that API's client and a
// separate probe token; otherwise the hub namespace clients read it as before.
func TestWorkerSourceClientsFollowTheWorkerNamespace(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	hub := cfg.NamespaceRef{Name: "hub", UID: runtimeID}
	newClient := func(ns cfg.NamespaceRef) *kube.PermissionClient {
		in := &providerInputs{files: root, kubernetesEndpoint: contracts.OwnerProviderEndpoint{Endpoint: "https://api.synthetic.invalid"}}
		c, err := kube.NewPermissionClient(in.kubernetes("kube-observer.token"), runtimeID, ns, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	observer, probe := newClient(hub), newClient(hub)
	api := func(name, uid string) contracts.OwnerNativeWorkerAPI {
		return contracts.OwnerNativeWorkerAPI{ClusterID: runtimeID, Namespace: contracts.WorkerObjectReference{Name: name, UID: uid}, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://api.synthetic.invalid"}}
	}
	workers := api("asservat-downloads", workerNamespaceID)
	if got := nativeKubernetesProbeTokenName(workers); got != "native-kube-probe-"+runtimeID+"-"+workerNamespaceID+".token" || got == nativeKubernetesTokenName(workers) {
		t.Fatal("probe token name", got)
	}
	workerClient := newClient(cfg.NamespaceRef{Name: workers.Namespace.Name, UID: workers.Namespace.UID})
	for _, mode := range []string{"unconfigured", "no-native", "worker-namespace", "hub-namespace", "two-apis", "missing-client"} {
		t.Run(mode, func(t *testing.T) {
			n := &contracts.OwnerNativeDeployment{WorkerAPIs: []contracts.OwnerNativeWorkerAPI{}}
			clients := map[ownerNativeAPIKey]*kube.PermissionClient{{runtimeID, workerNamespaceID}: workerClient}
			switch mode {
			case "no-native":
				n = nil
			case "worker-namespace":
				n.WorkerAPIs = append(n.WorkerAPIs, workers)
			case "hub-namespace":
				n.WorkerAPIs = append(n.WorkerAPIs, api("hub", runtimeID))
			case "two-apis":
				n.WorkerAPIs = append(n.WorkerAPIs, workers, api("asservat-downloads-2", "44444444-4444-4444-8444-444444444444"))
			case "missing-client":
				n.WorkerAPIs = append(n.WorkerAPIs, workers)
				clients = map[ownerNativeAPIKey]*kube.PermissionClient{}
			}
			d := &OwnerDeployment{inputs: &ownerInputs{providerInputs: &providerInputs{files: root}, config: contracts.OwnerDeployment{Native: n}}, shared: publicShared{workers: clients}}
			var closers []func()
			o, p, control, err := d.workerSourceClients(observer, probe, hub, &closers)
			for _, c := range closers {
				c()
			}
			switch mode {
			case "unconfigured", "no-native", "hub-namespace":
				if err != nil || o != observer || p != probe || control != hub || len(closers) != 0 {
					t.Fatal("hub namespace source clients changed", err)
				}
			case "worker-namespace":
				if err != nil || o != workerClient || p == nil || p == observer || p == probe || p == workerClient || control != (cfg.NamespaceRef{Name: "asservat-downloads", UID: workerNamespaceID}) || len(closers) != 1 {
					t.Fatal("worker namespace source not read with its own pinned clients", err)
				}
			default:
				if err == nil || o != nil || p != nil {
					t.Fatal("ambiguous or unpinned worker namespace accepted", mode)
				}
			}
		})
	}
}
