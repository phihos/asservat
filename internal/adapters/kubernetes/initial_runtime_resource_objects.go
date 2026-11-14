package kubernetes

import (
	"strings"
)

var initialRuntimeResourceItems = [...]string{
	"owner-account", "worker-account", "owner-role", "owner-binding", "owner-cluster-role", "owner-cluster-binding",
	"worker-role", "worker-binding", "worker-cluster-role", "worker-cluster-binding", "owner-deployment", "worker-deployment",
	"owner-service", "worker-lease", "owner-source", "owner-source-policy", "owner-source-binding", "owner-workload-policy", "owner-workload-binding",
}

type initialRuntimeResourceNames struct {
	Owner, Worker, OwnerInputs, WorkerInputs, OwnerProviders, WorkerProviders string
	OwnerSource, OwnerSourceGuard, WorkloadGuard, Lease                       string
}

func runtimeResourceNames(installation string) initialRuntimeResourceNames {
	prefix := "asservat-" + strings.ReplaceAll(installation, "-", "")
	return initialRuntimeResourceNames{prefix + "-owner", prefix + "-worker", prefix + "-owner-inputs", prefix + "-worker-inputs", prefix + "-owner-providers", prefix + "-worker-providers", prefix + "-owner-source", prefix + "-owner-source-guard", prefix + "-workload-guard", prefix + "-leader"}
}
