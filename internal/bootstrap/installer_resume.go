package bootstrap

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
)

// RunInstallerResume is a local administrator command, not a private in-Pod
// loader. It follows kubectl's KUBECONFIG/current-context conventions and named
// overrides, with no in-cluster credential fallback. It neither invokes Helm
// nor treats orchestration cleanup as database/provider recovery.
func RunInstallerResume(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || ctx.Err() != nil || out == nil {
		return mounts.ErrUnavailable
	}
	flags := flag.NewFlagSet("installer-resume", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	kubeconfig := flags.String("kubeconfig", "", "Kubernetes configuration file")
	selected := flags.String("context", "", "Kubernetes context override")
	namespace := flags.String("namespace", "", "bootstrap namespace override")
	name := flags.String("name", "asservat", "original stable installer name")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return mounts.ErrUnavailable
	}
	configuration, current, resolved, err := localKubernetes(*kubeconfig, *selected, *namespace)
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintf(out, "Kubernetes context %q, bootstrap namespace %q, installation %q.\n", current, resolved, *name); err != nil {
		return mounts.ErrUnavailable
	}
	ctx, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	result, err := kube.ResumeInitialBootstrapRunner(ctx, configuration, resolved, *name)
	if err != nil {
		return err
	}
	if result.Absent {
		_, err = fmt.Fprintln(out, "No runner is present. Retry the same Helm release and original values; the installer will verify retained progress before any effects.")
	} else {
		_, err = fmt.Fprintf(out, "Removed terminated runner UID %s. Retry the same Helm release and original values; this did not change installation progress or complete recovery.\n", result.RemovedUID)
	}
	if err != nil {
		return err
	}
	return ctx.Err()
}
