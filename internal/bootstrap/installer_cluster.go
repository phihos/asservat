package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"k8s.io/client-go/rest"
)

// RunInstallerCluster is the ADR-193 regional installer. It uses the
// operator's kubeconfig for the regional cluster (no in-cluster fallback),
// the hub's public regional offer and the bootstrap record the operator read
// from the channel with their own access. It prints the installed objects.
func RunInstallerCluster(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || ctx.Err() != nil || out == nil {
		return mounts.ErrUnavailable
	}
	flags := flag.NewFlagSet("installer-cluster", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	kubeconfig := flags.String("kubeconfig", "", "regional Kubernetes configuration file")
	selected := flags.String("context", "", "Kubernetes context override")
	namespace := flags.String("namespace", "asservat-connector", "connector namespace")
	offerFile := flags.String("offer", "", "the hub's regional-offer.json")
	bootstrapFile := flags.String("bootstrap", "", "the bootstrap record read from the channel")
	inCluster := flags.Bool("in-cluster", false, "Helm hook only: use the Pod's installer account as the guards' administrator")
	evidenceFile := flags.String("evidence-credential", "", "the operator's write-only regional evidence credential (required when the offer names the regional executor)")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *offerFile == "" || *bootstrapFile == "" {
		return mounts.ErrUnavailable
	}
	rawOffer, err := os.ReadFile(*offerFile)
	if err != nil {
		return mounts.ErrUnavailable
	}
	var offer contracts.RegionalOffer
	d := json.NewDecoder(bytes.NewReader(rawOffer))
	d.DisallowUnknownFields()
	if len(rawOffer) > 1<<20 || d.Decode(&offer) != nil || d.More() {
		return mounts.ErrUnavailable
	}
	record, err := os.ReadFile(*bootstrapFile)
	defer clear(record)
	if err != nil {
		return mounts.ErrUnavailable
	}
	envelope, err := kms.DecodeBootstrapRecord(record)
	if err != nil {
		return err
	}
	var config *rest.Config
	if *inCluster {
		// The chart's hook: no kubeconfig selection, the Pod's own account.
		if *kubeconfig != "" || *selected != "" {
			return mounts.ErrUnavailable
		}
		if config, err = rest.InClusterConfig(); err != nil {
			return mounts.ErrUnavailable
		}
	} else if config, _, _, err = localKubernetes(*kubeconfig, *selected, ""); err != nil {
		return err
	}
	var evidence []byte
	if *evidenceFile != "" {
		if evidence, err = os.ReadFile(*evidenceFile); err != nil || len(evidence) > 32<<10 {
			return mounts.ErrUnavailable
		}
		defer clear(evidence)
	}
	// The output includes the public join record of an installed executor
	// (ADR-196 decision 2); it holds no credential.
	installed, err := kube.InstallRegionalConnector(ctx, config, kube.RegionalInstallPlan{Offer: offer, Bootstrap: envelope, Namespace: *namespace, AccountAdministrator: *inCluster, Evidence: evidence})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(installed)
}
