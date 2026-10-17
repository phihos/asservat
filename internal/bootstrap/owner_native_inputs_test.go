package bootstrap

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func nativeInputFixture(t *testing.T) (*ownerInputs, string, contracts.OwnerDeployment) {
	in, dir, c := ownerInputFixture(t)
	c.Native = &contracts.OwnerNativeDeployment{
		ConnectorRoots: c.Kubernetes.Roots, Connections: 2, Concurrency: 1,
		WorkerAPIs:          []contracts.OwnerNativeWorkerAPI{{ClusterID: runtimeID, Namespace: contracts.WorkerObjectReference{Name: "workers", UID: runtimeID}, Kubernetes: c.Kubernetes}},
		RetentionTopologies: []contracts.OwnerNativeTopology{{TargetClusterID: runtimeID, Name: "topology", UID: runtimeID, SHA256: strings.Repeat("1", 64)}},
	}
	return in, dir, c
}
func TestOwnerNativeInputsAreClosedPinnedAndOptional(t *testing.T) {
	for _, mode := range []string{"valid", "absent", "duplicate-api", "missing-api", "empty-api", "empty-topologies", "foreign-namespace", "http-api", "api-credentials", "nil-roots", "duplicate-topology", "zero-topology-digest", "alias-digest", "excess-concurrency", "workload-cluster-api", "unknown-field"} {
		t.Run(mode, func(t *testing.T) {
			in, dir, c := nativeInputFixture(t)
			switch mode {
			case "absent":
				c.Native = nil
			case "duplicate-api":
				c.Native.WorkerAPIs = append(c.Native.WorkerAPIs, c.Native.WorkerAPIs[0])
			case "missing-api":
				c.Native.WorkerAPIs = nil
			case "empty-api":
				// ADR-194 D2: only the provider-installed layout may start empty.
				c.Native.WorkerAPIs = []contracts.OwnerNativeWorkerAPI{}
			case "empty-topologies":
				c.Native.RetentionTopologies = []contracts.OwnerNativeTopology{}
			case "foreign-namespace":
				c.Native.WorkerAPIs[0].Namespace.Name = "../workers"
			case "http-api":
				c.Native.WorkerAPIs[0].Kubernetes.Endpoint = "http://api.invalid"
			case "api-credentials":
				c.Native.WorkerAPIs[0].Kubernetes.Endpoint = "https://user:secret@api.invalid"
			case "nil-roots":
				c.Native.ConnectorRoots = nil
			case "duplicate-topology":
				c.Native.RetentionTopologies = append(c.Native.RetentionTopologies, c.Native.RetentionTopologies[0])
			case "zero-topology-digest":
				c.Native.RetentionTopologies[0].SHA256 = strings.Repeat("0", 64)
			case "alias-digest":
				c.Native.RetentionTopologies[0].SHA256 = strings.Repeat("A", 64)
			case "excess-concurrency":
				c.Native.Concurrency = 3
			case "workload-cluster-api": // ADR-179: only the hub's own cluster API
				c.Native.WorkerAPIs[0].ClusterID = "10000000-0000-4000-8000-0000000000aa"
			}
			if mode == "unknown-field" {
				raw, _ := json.Marshal(c)
				var v map[string]any
				if json.Unmarshal(raw, &v) != nil {
					t.Fatal("fixture JSON")
				}
				v["native"].(map[string]any)["credentialPath"] = "ambient"
				writeOwnerJSON(t, dir, "deployment.json", v)
			} else {
				writeOwnerJSON(t, dir, "deployment.json", c)
			}
			got, e := readOwnerInputs(context.Background(), in.files)
			if mode == "valid" || mode == "absent" {
				if e != nil || got == nil {
					t.Fatal("supported protected projection", e)
				}
				if mode == "valid" && nativeKubernetesTokenName(got.config.Native.WorkerAPIs[0]) != "native-kube-"+runtimeID+"-"+runtimeID+".token" {
					t.Fatal("token path is not fixed from pinned identities")
				}
			} else if e == nil {
				t.Fatal("unsafe native projection accepted", mode)
			}
		})
	}
}
func TestOwnerNativeRuntimeRequiresBothProtectedPortAndInputs(t *testing.T) {
	for _, mode := range []string{"port-only", "inputs-only"} {
		t.Run(mode, func(t *testing.T) {
			_, c, l := newRuntimeFixture(t)
			defer l.Close()
			if mode == "port-only" {
				c.Pool.NativePort = 9444
			} else {
				c.Native = &OwnerNativeRuntimeConfig{}
			}
			r, e := NewOwnerRuntime(context.Background(), c)
			if r != nil {
				r.Close()
			}
			if e == nil {
				t.Fatal("partial native runtime configuration accepted", mode)
			}
		})
	}
}
