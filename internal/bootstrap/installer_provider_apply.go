package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	bao "github.com/openbao/openbao/api/v2"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// localKubernetes follows kubectl's KUBECONFIG/current-context conventions and
// named overrides, with no in-cluster credential fallback.
func localKubernetes(kubeconfig, selected, namespace string) (*rest.Config, string, string, error) {
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	loading.ExplicitPath = kubeconfig
	raw, err := loading.Load()
	if err != nil {
		return nil, "", "", mounts.ErrUnavailable
	}
	current := raw.CurrentContext
	if selected != "" {
		current = selected
	}
	if current == "" || len(current) > 256 || raw.Contexts[current] == nil {
		return nil, "", "", mounts.ErrUnavailable
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: current}
	if namespace != "" {
		overrides.Context.Namespace = namespace
	}
	// Direct local-config construction deliberately avoids the deferred
	// loader's fallback to a Pod's ambient in-cluster credentials.
	client := clientcmd.NewNonInteractiveClientConfig(*raw, current, overrides, loading)
	configuration, err := client.ClientConfig()
	if err != nil {
		return nil, "", "", mounts.ErrUnavailable
	}
	resolved, _, err := client.Namespace()
	if err != nil {
		return nil, "", "", mounts.ErrUnavailable
	}
	return configuration, current, resolved, nil
}

// RunInstallerProviderApply is the ADR-183 operator command. It uses the
// operator's own OpenBao administration (BAO_ADDR, BAO_CACERT, BAO_TOKEN) and
// the operator's scoped audit storage credential; neither enters the cluster
// except the scoped credential and a ten-minute read-only inspection token.
func RunInstallerProviderApply(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || ctx.Err() != nil || out == nil {
		return mounts.ErrUnavailable
	}
	flags := flag.NewFlagSet("installer-provider-apply", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	kubeconfig := flags.String("kubeconfig", "", "Kubernetes configuration file")
	selected := flags.String("context", "", "Kubernetes context override")
	namespace := flags.String("namespace", "", "bootstrap namespace override")
	installation := flags.String("installation", "", "installation ID")
	credentialFile := flags.String("audit-credential", "", "scoped audit storage credential JSON file")
	federationFile := flags.String("federation-audit-credential", "", "the federation's scoped audit storage credential JSON file (phase 3 with a federation)")
	clientSecretFile := flags.String("oidc-client-secret", "", "the hub-api's OIDC client secret file (phase 3 of a promoted owner)")
	certificateFile := flags.String("public-tls-certificate", "", "the hub-api's public TLS certificate chain PEM file (phase 3 of a promoted owner)")
	keyFile := flags.String("public-tls-key", "", "the hub-api's public TLS private key PEM file (phase 3 of a promoted owner)")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *installation == "" || *credentialFile == "" {
		return mounts.ErrUnavailable
	}
	credential, err := os.ReadFile(*credentialFile)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer clear(credential)
	if c, e := contracts.DecodeOwnerStorageCredential(bytes.NewReader(credential)); e != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return mounts.ErrUnavailable
	}
	var federation []byte
	if *federationFile != "" {
		if federation, err = os.ReadFile(*federationFile); err != nil {
			return mounts.ErrUnavailable
		}
		defer clear(federation)
		if c, e := contracts.DecodeOwnerStorageCredential(bytes.NewReader(federation)); e != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
			return mounts.ErrUnavailable
		}
	}
	// ADR-194: a promoted owner's public material, all three or none.
	var public map[string][]byte
	if *clientSecretFile != "" || *certificateFile != "" || *keyFile != "" {
		public = map[string][]byte{}
		for key, file := range map[string]string{contracts.OwnerPublicClientSecretFile: *clientSecretFile, contracts.OwnerPublicTLSCertificate: *certificateFile, contracts.OwnerPublicTLSKey: *keyFile} {
			b, e := os.ReadFile(file)
			if e != nil || len(b) == 0 || len(b) > 64<<10 {
				return mounts.ErrUnavailable
			}
			defer clear(b)
			public[key] = b
		}
		if _, e := tls.X509KeyPair(public[contracts.OwnerPublicTLSCertificate], public[contracts.OwnerPublicTLSKey]); e != nil {
			return mounts.ErrUnavailable
		}
	}
	configuration, current, resolved, err := localKubernetes(*kubeconfig, *selected, *namespace)
	if err != nil {
		return err
	}
	ctx, end := context.WithTimeout(ctx, time.Minute)
	defer end()
	outbox, err := kube.ReadInstallerOutbox(ctx, configuration, resolved, *installation)
	if err != nil {
		return err
	}
	// An artifact with a federation section needs its separate credential,
	// checked before any provider write.
	var plan struct {
		Federation json.RawMessage `json:"federation"`
		Public     bool            `json:"public"`
	}
	if json.Unmarshal(outbox.Recipe, &plan) == nil && len(plan.Federation) != 0 && string(plan.Federation) != "null" && federation == nil {
		_, _ = fmt.Fprintln(out, "This recipe provisions the federation: pass --federation-audit-credential with its separately scoped audit credential.")
		return mounts.ErrUnavailable
	}
	if plan.Public != (public != nil) {
		_, _ = fmt.Fprintln(out, "Pass --oidc-client-secret, --public-tls-certificate and --public-tls-key exactly when this recipe promotes the hub-api.")
		return mounts.ErrUnavailable
	}
	if _, err = fmt.Fprintf(out, "Kubernetes context %q, namespace %q, installation %q: applying phase %d %s recipe.\n", current, resolved, *installation, outbox.Phase, outbox.Purpose); err != nil {
		return mounts.ErrUnavailable
	}
	client, err := bao.NewClient(bao.DefaultConfig())
	if err != nil {
		return mounts.ErrUnavailable
	}
	name := "asservat-" + strings.ReplaceAll(*installation, "-", "") + "-" + outbox.Purpose + "-inspection"
	token, err := providerconfig.ApplySetupArtifact(ctx, client, name, outbox.Recipe, out)
	if err != nil {
		return err
	}
	defer clear(token)
	if err = kube.WriteInstallerInbox(ctx, configuration, resolved, *installation, outbox.Phase, token, credential, federation, public); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "Inbox written; the continuation verifies the provider before any use.")
	return err
}
