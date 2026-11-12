package bootstrap

import (
	"context"
	"fmt"
	"io"
	"strings"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	bao "github.com/openbao/openbao/api/v2"
	"k8s.io/client-go/rest"
)

// External provider administration remains operator-owned. The selected store
// has already retained the original scoped inputs; none is exported or replaced.
func applyMixedExternalProvider(ctx context.Context, config *rest.Config, current, namespace, installation string, outbox contracts.InstallerRecipeOutbox, out io.Writer) error {
	if outbox.ProviderMode != contracts.InstallerProviderBundledObjectStore {
		return mounts.ErrUnavailable
	}
	digest := installerRecipeDigest(outbox.Recipe)
	original, err := kube.ReadMixedInstallerInbox(ctx, config, namespace, installation, digest, outbox.ProviderMode)
	if err != nil {
		return err
	}
	defer clearMixedInstallerData(original.Data)
	if mixedInstallerDataMatchesRecipe(outbox.Phase, outbox.Recipe, original.Data) != nil {
		return mounts.ErrUnavailable
	}
	if _, err = fmt.Fprintf(out, "Kubernetes context %q, namespace %q, installation %q: applying phase %d %s with retained bundled storage inputs.\n", current, namespace, installation, outbox.Phase, outbox.Purpose); err != nil {
		return err
	}
	client, err := bao.NewClient(bao.DefaultConfig())
	if err != nil {
		return mounts.ErrUnavailable
	}
	name := "asservat-" + strings.ReplaceAll(installation, "-", "") + "-" + outbox.Purpose + "-inspection"
	token, err := providerconfig.ApplySetupArtifact(ctx, client, name, outbox.Recipe, out)
	if err != nil {
		return err
	}
	defer clear(token)
	completed, err := kube.CompleteMixedInstallerInbox(ctx, config, namespace, installation, digest, outbox.ProviderMode, original, token)
	if err != nil {
		return err
	}
	defer clearMixedInstallerData(completed.Data)
	_, err = fmt.Fprintln(out, "Original inbox inspection completed; the continuation verifies provider and storage before use.")
	return err
}
