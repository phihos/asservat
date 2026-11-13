package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
)

// Commands taking arguments; all others take none.
var withArguments = []string{"installer-cluster", "installer-cluster-join", "download-worker", "setup"}

// One-shot commands report a cancellation as a failure.
var oneShot = []string{"secrets", "installer-cluster", "installer-cluster-join", "setup"}

var commands = []string{"secrets", "setup", "installer-cluster", "installer-cluster-join", "download-worker", "hub-api", "hub-worker", "hub-federation", "connector", "key-service", "publisher", "node"}

func main() { os.Exit(run()) }
func run() int {
	if len(os.Args) < 2 || !slices.Contains(commands, os.Args[1]) || !slices.Contains(withArguments, os.Args[1]) && len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: asservat secrets | setup [--wait-schema --config file --credential file] | installer-cluster --offer file --bootstrap file [--evidence-credential file] [--kubeconfig file] [--context name] [--namespace name] [--in-cluster] | installer-cluster-join --namespace name --join file [--standby n] [--captures n] [--kubeconfig file] [--context name] | download-worker [protected startup arguments] | hub-api | hub-worker | hub-federation | connector | key-service | publisher | node")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var err error
	switch os.Args[1] {
	case "secrets":
		err = bootstrap.RunSecrets(ctx)
	case "setup":
		err = bootstrap.RunSetup(ctx, os.Args[2:], os.Stdout)
	case "installer-cluster":
		err = bootstrap.RunInstallerCluster(ctx, os.Args[2:], os.Stdout)
	case "installer-cluster-join":
		err = bootstrap.RunInstallerClusterJoin(ctx, os.Args[2:], os.Stdout)
	case "hub-api":
		err = bootstrap.RunHubAPI(ctx, os.Getenv(contracts.OwnerPodUIDEnvironment))
	case "connector":
		err = bootstrap.RunRegional(ctx, os.Getenv(contracts.RegionalPodUIDEnvironment))
	case "hub-federation":
		err = bootstrap.RunFederation(ctx)
	case "key-service":
		err = bootstrap.RunKeyService(ctx)
	case "publisher":
		err = bootstrap.RunPublisher(ctx)
	case "node":
		err = bootstrap.RunNode(ctx, os.Getenv(contracts.NodePodUIDEnvironment))
	case "hub-worker":
		err = bootstrap.RunHubWorker(ctx, os.Getenv(contracts.OwnerPodUIDEnvironment))
	default:
		err = bootstrap.RunDownloadWorker(ctx, os.Args[2:], os.Getenv(contracts.WorkerPodUIDEnvironment), os.Stdout)
	}
	if ctx.Err() != nil && !slices.Contains(oneShot, os.Args[1]) {
		return 0
	}
	if err == nil {
		return 0
	}
	switch os.Args[1] {
	case "secrets":
		fmt.Fprintln(os.Stderr, bootstrap.SecretsDiagnostic(err))
	case "setup", "installer-cluster":
		// A fixed step name and error class only, no provider response bodies.
		fmt.Fprintln(os.Stderr, err)
	case "hub-api":
		fmt.Fprintln(os.Stderr, bootstrap.OwnerStartupDiagnostic(err))
	case "download-worker":
		fmt.Fprintln(os.Stderr, bootstrap.DownloadWorkerDiagnostic(err))
	case "node":
		fmt.Fprintln(os.Stderr, bootstrap.NodeDiagnostic(err))
	case "hub-worker", "publisher":
		fmt.Fprintln(os.Stderr, bootstrap.HubWorkerDiagnostic(err))
	default:
		fmt.Fprintln(os.Stderr, "service stopped: protected configuration, credentials or original deadline unavailable")
	}
	return 1
}
