package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
)

func main() { os.Exit(run()) }
func run() int {
	if len(os.Args) < 2 || (os.Args[1] != "configuration-role-install" && os.Args[1] != "installer-provider-recipe" && os.Args[1] != "installer-resume" && os.Args[1] != "installer-provider-apply" && os.Args[1] != "installer-cluster" && os.Args[1] != "installer-cluster-join" && os.Args[1] != "installer-continue" && os.Args[1] != "download-worker" && os.Args[1] != "hub-api" && os.Args[1] != "hub-worker" && os.Args[1] != "hub-federation" && os.Args[1] != "connector" && os.Args[1] != "key-service" && os.Args[1] != "publisher" && os.Args[1] != "initial-install" && os.Args[1] != "initial-prepare" && os.Args[1] != "initial-schema" && os.Args[1] != "initial-bootstrap" && os.Args[1] != "initial-bootstrap-schema" && os.Args[1] != "initial-bootstrap-retire" && os.Args[1] != "initial-bootstrap-prepare") || (os.Args[1] == "configuration-role-install" || os.Args[1] == "installer-continue" || os.Args[1] == "hub-api" || os.Args[1] == "hub-worker" || os.Args[1] == "hub-federation" || os.Args[1] == "connector" || os.Args[1] == "key-service" || os.Args[1] == "publisher" || os.Args[1] == "initial-install" || os.Args[1] == "initial-prepare" || os.Args[1] == "initial-schema" || os.Args[1] == "initial-bootstrap" || os.Args[1] == "initial-bootstrap-schema" || os.Args[1] == "initial-bootstrap-retire" || os.Args[1] == "initial-bootstrap-prepare") && len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: asservat installer-provider-recipe [public provider name flags] | installer-resume [--kubeconfig file] [--context name] [--namespace name] [--name install] | installer-provider-apply --installation id --audit-credential file [--federation-audit-credential file] [--oidc-client-secret file --public-tls-certificate file --public-tls-key file] [--kubeconfig file] [--context name] [--namespace name] | installer-cluster --offer file --bootstrap file [--evidence-credential file] [--kubeconfig file] [--context name] [--namespace name] [--in-cluster] | installer-cluster-join --namespace name --join file [--standby n] [--captures n] [--kubeconfig file] [--context name] | installer-continue | download-worker [protected startup arguments] | configuration-role-install | hub-api | hub-worker | hub-federation | connector | key-service | publisher | initial-install | initial-prepare | initial-schema | initial-bootstrap | initial-bootstrap-schema | initial-bootstrap-retire | initial-bootstrap-prepare")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var err error
	if os.Args[1] == "configuration-role-install" {
		err = bootstrap.RunConfigurationRoleInstaller(ctx)
	} else if os.Args[1] == "installer-provider-recipe" {
		err = bootstrap.RunInstallerProviderRecipe(ctx, os.Args[2:], os.Stdout)
	} else if os.Args[1] == "installer-resume" {
		err = bootstrap.RunInstallerResume(ctx, os.Args[2:], os.Stdout)
	} else if os.Args[1] == "installer-provider-apply" {
		err = bootstrap.RunInstallerProviderApply(ctx, os.Args[2:], os.Stdout)
	} else if os.Args[1] == "installer-cluster" {
		err = bootstrap.RunInstallerCluster(ctx, os.Args[2:], os.Stdout)
	} else if os.Args[1] == "installer-cluster-join" {
		err = bootstrap.RunInstallerClusterJoin(ctx, os.Args[2:], os.Stdout)
	} else if os.Args[1] == "installer-continue" {
		err = bootstrap.RunInstallerContinue(ctx)
	} else if os.Args[1] == "hub-api" {
		err = bootstrap.RunHubAPI(ctx, os.Getenv(contracts.OwnerPodUIDEnvironment))
	} else if os.Args[1] == "initial-bootstrap" {
		err = bootstrap.RunInitialBootstrap(ctx)
	} else if os.Args[1] == "initial-bootstrap-schema" {
		err = bootstrap.RunInitialBootstrapSchema(ctx)
	} else if os.Args[1] == "initial-bootstrap-prepare" {
		err = bootstrap.RunInitialBootstrapPreparer(ctx)
	} else if os.Args[1] == "initial-bootstrap-retire" {
		err = bootstrap.RunInitialBootstrapRetire(ctx)
	} else if os.Args[1] == "initial-schema" {
		err = bootstrap.RunInitialSchema(ctx)
	} else if os.Args[1] == "initial-prepare" {
		err = bootstrap.RunInitialPreparer(ctx)
	} else if os.Args[1] == "initial-install" {
		err = bootstrap.RunInitialInstaller(ctx)
	} else if os.Args[1] == "connector" {
		err = bootstrap.RunRegional(ctx, os.Getenv(contracts.RegionalPodUIDEnvironment))
	} else if os.Args[1] == "hub-federation" {
		err = bootstrap.RunFederation(ctx)
	} else if os.Args[1] == "key-service" {
		err = bootstrap.RunKeyService(ctx)
	} else if os.Args[1] == "publisher" {
		err = bootstrap.RunPublisher(ctx)
	} else if os.Args[1] == "hub-worker" {
		err = bootstrap.RunHubWorker(ctx, os.Getenv(contracts.OwnerPodUIDEnvironment))
	} else {
		err = bootstrap.RunDownloadWorker(ctx, os.Args[2:], os.Getenv(contracts.WorkerPodUIDEnvironment), os.Stdout)
	}
	if ctx.Err() != nil && os.Args[1] != "configuration-role-install" && os.Args[1] != "installer-continue" && os.Args[1] != "installer-provider-recipe" && os.Args[1] != "installer-resume" && os.Args[1] != "installer-provider-apply" && os.Args[1] != "installer-cluster" && os.Args[1] != "installer-cluster-join" && os.Args[1] != "initial-install" && os.Args[1] != "initial-prepare" && os.Args[1] != "initial-schema" && os.Args[1] != "initial-bootstrap" && os.Args[1] != "initial-bootstrap-schema" && os.Args[1] != "initial-bootstrap-retire" && os.Args[1] != "initial-bootstrap-prepare" {
		return 0
	}
	if err != nil {
		if os.Args[1] == "hub-api" {
			fmt.Fprintln(os.Stderr, bootstrap.OwnerStartupDiagnostic(err))
			return 1
		}
		if os.Args[1] == "hub-worker" {
			fmt.Fprintln(os.Stderr, bootstrap.HubWorkerDiagnostic(err))
			return 1
		}
		if os.Args[1] == "configuration-role-install" {
			fmt.Fprintln(os.Stderr, bootstrap.ConfigurationRoleInstallerRemedy(err))
			return 1
		}
		if os.Args[1] == "installer-provider-recipe" {
			fmt.Fprintln(os.Stderr, "provider recipe unavailable: use five distinct bounded policy/role names and the original audit mount/key; no credentials are accepted")
			return 1
		}
		if os.Args[1] == "installer-continue" {
			// A fixed step name and error class only (ADR-183).
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if os.Args[1] == "installer-cluster" {
			// A fixed installer step and a closed cause (ADR-193).
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if os.Args[1] == "installer-provider-apply" {
			fmt.Fprintln(os.Stderr, "provider recipe not applied: check BAO_ADDR/BAO_TOKEN, the scoped audit credential file and that the continuation published an outbox; existing objects are never overwritten")
			return 1
		}
		if os.Args[1] == "installer-resume" {
			fmt.Fprintln(os.Stderr, "installer runner was not removed: verify the selected Kubernetes context and original release input; live, unknown or changed runners must remain retained")
			return 1
		}
		if os.Args[1] == "initial-prepare" || os.Args[1] == "initial-bootstrap" || os.Args[1] == "initial-bootstrap-schema" || os.Args[1] == "initial-bootstrap-retire" || os.Args[1] == "initial-bootstrap-prepare" {
			fmt.Fprintln(os.Stderr, bootstrap.InitialPreparationRemedy(err))
			return 1
		}
		fmt.Fprintln(os.Stderr, "service stopped: protected configuration, credentials or original deadline unavailable")
		return 1
	}
	return 0
}
