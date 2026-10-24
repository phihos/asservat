package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/utils/ptr"
)

// This fixture uses the public compiler and exact product runner. It supplies
// only synthetic operator choices, never a product installation/plan/journal ID.
func installedUnifiedPublicInput(t *testing.T, desired contracts.InitialBootstrap) (contracts.InitialBootstrapInput, contracts.InitialBootstrap) {
	t.Helper()
	input := helmBootstrapPublicInput(desired)
	input.RegistryAuthentication = "" // the existing owned fixture preloads its exact image
	input.ProbeAudience = desired.ProbeAudience
	var ca bytes.Buffer
	for _, root := range desired.Kubernetes.Roots {
		if err := pem.Encode(&ca, &pem.Block{Type: "CERTIFICATE", Bytes: root}); err != nil {
			t.Fatal(err)
		}
	}
	input.Kubernetes.RootsPEM = ca.String()
	compiled, err := providerconfig.CompileInitialBootstrapInput(input, nil, nil, time.Now())
	if err != nil {
		t.Fatal("actual public bootstrap compiler", err)
	}
	if len(compiled.Administrators) != 1 || compiled.Administrators[0].Name != "system:serviceaccount:"+input.BootstrapNamespace+":"+input.RunnerAccount {
		t.Fatal("public compiler changed the single original runner administrator")
	}
	return input, compiled
}

func installedUnifiedRunnerConfig(config *rest.Config, desired contracts.InitialBootstrap) *rest.Config {
	runner := rest.CopyConfig(config)
	runner.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + desired.BootstrapNamespace + ":" + desired.Name + "-bootstrap-runner", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + desired.BootstrapNamespace, "system:authenticated"}}
	return runner
}

// The join CLI uses the same accepted runner actor as guarded operator writes.
// Keep the owned hub credentials and endpoint in a private temporary file;
// neither the original kubeconfig nor the regional configuration is changed.
func installedUnifiedRunnerKubeconfig(t *testing.T, original string, desired contracts.InitialBootstrap) string {
	t.Helper()
	config, err := clientcmd.LoadFromFile(original)
	if err != nil || clientcmdapi.MinifyConfig(config) != nil || clientcmd.ResolveLocalPaths(config) != nil {
		t.Fatal("owned hub kubeconfig unavailable")
	}
	auth := config.AuthInfos[config.Contexts[config.CurrentContext].AuthInfo]
	if auth == nil {
		t.Fatal("owned hub kubeconfig identity missing")
	}
	actor := installedUnifiedRunnerConfig(&rest.Config{}, desired).Impersonate
	auth.Impersonate, auth.ImpersonateUID = actor.UserName, actor.UID
	auth.ImpersonateGroups, auth.ImpersonateUserExtra = actor.Groups, actor.Extra
	dir := t.TempDir()
	if err = os.Chmod(dir, 0o700); err != nil {
		t.Fatal("private hub kubeconfig directory unavailable", err)
	}
	file := filepath.Join(dir, "hub-runner.kubeconfig")
	if err = clientcmd.WriteToFile(*config, file); err != nil {
		t.Fatal("private hub kubeconfig unavailable", err)
	}
	return file
}

type installedUnifiedRunner struct {
	template     *core.Pod
	pod          *core.Pod
	continuation *installerContinuationFixture
	ownedNode    string
	verifyReplay func(*testing.T)
}

func newInstalledUnifiedRunner(t *testing.T, ctx context.Context, api kubernetes.Interface, input contracts.InitialBootstrapInput, setup *installerContinuationFixture, ownedNode string) *installedUnifiedRunner {
	t.Helper()
	public, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	continuationSum := sha256.Sum256(setup.document)
	continuationDigest := hex.EncodeToString(continuationSum[:])
	refs, err := json.Marshal(contracts.InitialBootstrapRunnerInput{Format: contracts.InitialBootstrapRunnerInputFormat, ProducerSecret: "operator-producer", SchemaSecret: "operator-ddl", RetirementSecret: "operator-retirement", ContinuationDigest: continuationDigest})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append(append(bytes.Clone(public), '\n'), refs...))
	digest := hex.EncodeToString(sum[:])
	pod, err := kube.BuildInitialBootstrapRunner(kube.InitialBootstrapRunnerPlan{Namespace: input.BootstrapNamespace, Name: input.Name, Image: input.Image, InputDigest: digest, ProducerSecret: "operator-producer", SchemaSecret: "operator-ddl", RetirementSecret: "operator-retirement", ProbeAudience: input.ProbeAudience, ContinuationDigest: continuationDigest})
	if err != nil {
		t.Fatal("exact product five-command profile", err)
	}
	for name, data := range map[string]map[string]string{
		input.Name + "-bootstrap-input." + digest[:32] + "." + digest[32:]: {"bootstrap.json": string(public), "runner.json": string(refs)},
		input.Name + "-continuation." + continuationDigest[:32]:            {contracts.InstallerContinuationFile: string(setup.document)},
	} {
		if _, err = api.CoreV1().ConfigMaps(input.BootstrapNamespace).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: name}, Immutable: ptr.To(true), Data: data}, meta.CreateOptions{}); err != nil {
			t.Fatal("original immutable public runner input", err)
		}
	}
	return &installedUnifiedRunner{template: pod, continuation: setup, ownedNode: ownedNode}
}

func (u *installedUnifiedRunner) start(t *testing.T, ctx context.Context, api kubernetes.Interface) *core.Pod {
	t.Helper()
	pod, err := api.CoreV1().Pods(u.template.Namespace).Create(ctx, u.template.DeepCopy(), meta.CreateOptions{})
	if err != nil {
		t.Fatal("actual unified Restricted runner admission", err)
	}
	if u.pod != nil && pod.UID == u.pod.UID {
		t.Fatal("unified resume reused the old Pod result")
	}
	u.pod = pod
	t.Cleanup(func() { installerContinuationLogs(t, api, pod) })
	return pod
}

func (u *installedUnifiedRunner) current(t *testing.T, ctx context.Context, api kubernetes.Interface) *core.Pod {
	t.Helper()
	pod, err := api.CoreV1().Pods(u.pod.Namespace).Get(ctx, u.pod.Name, meta.GetOptions{})
	if err != nil || pod.UID != u.pod.UID || pod.DeletionTimestamp != nil {
		t.Fatal("original unified runner lost/replaced/deleting", err)
	}
	return pod
}

// Do not wait for Pod success: the final command must still be alive at its
// first operator wait while the original activation/retirement is inspected.
func (u *installedUnifiedRunner) waitRetired(t *testing.T, ctx context.Context, api kubernetes.Interface, original *core.Pod) {
	t.Helper()
	wait, end := context.WithTimeout(ctx, 310*time.Second)
	defer end()
	for {
		pod := u.current(t, wait, api)
		if pod.UID != original.UID || pod.Status.Phase == core.PodFailed {
			t.Fatal("unified bootstrap failed before retirement")
		}
		if len(pod.Status.InitContainerStatuses) == 4 && pod.Status.InitContainerStatuses[3].State.Terminated != nil {
			u.checkPhases(t, pod, false)
			return
		}
		installedUnifiedPoll(t, wait)
	}
}

func (u *installedUnifiedRunner) checkPhases(t *testing.T, pod *core.Pod, complete bool) {
	t.Helper()
	if len(pod.Status.InitContainerStatuses) != 4 {
		t.Fatal("unified runner init dispositions incomplete")
	}
	names := []string{"produce", "schema", "prepare", "retire"}
	statuses := append([]core.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	if complete {
		if pod.Status.Phase != core.PodSucceeded || len(pod.Status.ContainerStatuses) != 1 {
			t.Fatal("unified runner final disposition incomplete")
		}
		names = append(names, "continue")
		statuses = append(statuses, pod.Status.ContainerStatuses...)
	}
	for i, status := range statuses {
		if status.Name != names[i] || status.State.Terminated == nil || status.State.Terminated.ExitCode != 0 || status.RestartCount != 0 || !strings.HasSuffix(status.ImageID, strings.Split(u.template.Spec.Containers[0].Image, "@")[1]) {
			t.Fatal("unified runner wrong image/restarted/failed phase", status.Name)
		}
	}
}

func installedUnifiedPoll(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
		t.Fatal("unified runner original fixture interval", ctx.Err())
	case <-time.After(100 * time.Millisecond):
	}
}

// The interruption happens only after a published phase-1 outbox and before
// any operator provider effect. The native run stops the exact owned process;
// no journal, credential, Pod status or phase receipt is edited by the fixture.
func (u *installedUnifiedRunner) interruptAndResume(t *testing.T, ctx context.Context, api kubernetes.Interface, config *rest.Config, kubeconfig string, desired contracts.InitialBootstrap, original contracts.InitialPreparer) *core.Pod {
	t.Helper()
	wait, end := context.WithTimeout(ctx, 3*time.Minute)
	defer end()
	installation := original.Plan.InstallationID
	outboxName := contracts.InstallerRecipeOutboxName(installation)
	var outbox *core.ConfigMap
	for {
		pod := u.current(t, wait, api)
		if pod.Status.Phase == core.PodFailed || pod.Status.Phase == core.PodSucceeded {
			t.Fatal("unified runner stopped before the first provider wait")
		}
		observed, err := kube.ReadInstallerOutbox(wait, config, desired.BootstrapNamespace, installation)
		if err == nil {
			if observed.Phase != 1 || observed.Purpose != "worker-provider" {
				t.Fatal("unexpected first provider phase")
			}
			outbox, err = api.CoreV1().ConfigMaps(desired.BootstrapNamespace).Get(wait, outboxName, meta.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			break
		}
		installedUnifiedPoll(t, wait)
	}
	if _, err := api.CoreV1().Secrets(desired.BootstrapNamespace).Get(wait, contracts.InstallerInboxName(installation), meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("first provider wait already has an inbox", err)
	}
	root, err := api.CoreV1().ConfigMaps(desired.BootstrapNamespace).Get(wait, original.Plan.RootName, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	journalName := "asservat-runtime-resources-" + strings.ReplaceAll(installation, "-", "")
	journal, err := api.CoreV1().Secrets(desired.TargetNamespace).Get(wait, journalName, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, data := range journal.Data {
			clear(data)
		}
	}()
	args := []string{"--kubeconfig", kubeconfig, "--namespace", desired.BootstrapNamespace, "--name", desired.Name}
	var output bytes.Buffer
	if err = bootstrap.RunInstallerResume(wait, args, &output); !errors.Is(err, kube.ErrInitialBootstrapRunnerActive) {
		t.Fatal("live unified resume was not refused", err)
	}
	before := u.current(t, wait, api)
	if before.Status.Phase != core.PodRunning || len(before.Status.ContainerStatuses) != 1 || before.Status.ContainerStatuses[0].Name != "continue" || before.Status.ContainerStatuses[0].State.Running == nil {
		t.Fatal("first provider wait lacks a live exact continuation process")
	}
	installedUnifiedStop(t, wait, before, u.ownedNode)
	for {
		stopped := u.current(t, wait, api)
		if stopped.Status.Phase == core.PodFailed {
			u.checkPhases(t, stopped, false)
			if len(stopped.Status.ContainerStatuses) != 1 || stopped.Status.ContainerStatuses[0].State.Terminated == nil || stopped.Status.ContainerStatuses[0].State.Terminated.ExitCode == 0 || stopped.Status.ContainerStatuses[0].RestartCount != 0 {
				t.Fatal("interrupted continuation lacks a positive nonzero terminal receipt")
			}
			break
		}
		installedUnifiedPoll(t, wait)
	}
	// Preserve the failed process logs before terminal-only deletion removes it.
	installerUnifiedLogs(t, wait, api, before)
	output.Reset()
	if err = bootstrap.RunInstallerResume(wait, args, &output); err != nil {
		t.Fatal("actual positive-terminal unified resume", err)
	}
	if !strings.Contains(output.String(), string(before.UID)) {
		t.Fatal("resume did not report the original removed UID")
	}
	if _, err = api.CoreV1().Pods(before.Namespace).Get(wait, before.Name, meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("resume absence not observed", err)
	}
	next := u.start(t, ctx, api)
	u.waitRetired(t, ctx, api, next)
	// An identical outbox UPDATE may keep its resource version. The new Pod
	// must report the existing fixed outbox-completion line before readback.
	for {
		replay, e := api.CoreV1().ConfigMaps(desired.BootstrapNamespace).Get(wait, outboxName, meta.GetOptions{})
		current := u.current(t, wait, api)
		if current.Status.Phase == core.PodFailed {
			t.Fatal("resumed unified continuation failed")
		}
		// This process-local progress comes from entering WorkerLaunch's inbox
		// wait. The retained old outbox alone is insufficient after a restart.
		if e == nil && replay.UID == outbox.UID && equalJSONForBootstrap(replay.Data, outbox.Data) && len(current.Status.ContainerStatuses) == 1 && current.Status.ContainerStatuses[0].State.Running != nil {
			logs, logErr := api.CoreV1().Pods(next.Namespace).GetLogs(next.Name, &core.PodLogOptions{Container: "continue", LimitBytes: ptr.To(int64(8192)), TailLines: ptr.To(int64(40))}).DoRaw(wait)
			if logErr == nil && bytes.Contains(logs, []byte("installer continuation: worker/outbox done in ")) {
				// Bind the log read to the same live UID, not merely its fixed name.
				u.current(t, wait, api)
				break
			}
		}
		installedUnifiedPoll(t, wait)
	}

	afterOutbox, e := api.CoreV1().ConfigMaps(desired.BootstrapNamespace).Get(wait, outboxName, meta.GetOptions{})
	afterRoot, re := api.CoreV1().ConfigMaps(desired.BootstrapNamespace).Get(wait, root.Name, meta.GetOptions{})
	afterJournal, je := api.CoreV1().Secrets(desired.TargetNamespace).Get(wait, journal.Name, meta.GetOptions{})
	if e != nil || re != nil || je != nil {
		t.Fatal("original progress readback after resume", e, re, je)
	}
	defer func() {
		for _, data := range afterJournal.Data {
			clear(data)
		}
	}()
	if afterOutbox.UID != outbox.UID || !equalJSONForBootstrap(afterOutbox.Data, outbox.Data) || afterRoot.UID != root.UID || !equalJSONForBootstrap(afterRoot.Data, root.Data) || afterJournal.UID != journal.UID || !equalJSONForBootstrap(afterJournal.Data, journal.Data) {
		t.Fatal("resume changed original outbox/root/journal identity or contents")
	}
	u.verifyReplay(t)
	t.Log("unified runner resumed", before.UID, "to", next.UID, "with original installation", installation, "root", root.UID, "journal", journal.UID, "before first provider apply")
	return next
}

// Same owned-node/container selection as installerCrashHubWorker, but the
// RestartPolicyNever runner must become Failed instead of being restarted.
func installedUnifiedStop(t *testing.T, ctx context.Context, pod *core.Pod, ownedNode string) {
	t.Helper()
	node := pod.Spec.NodeName
	cluster := strings.TrimSuffix(strings.TrimSuffix(node, "-control-plane"), "-worker")
	if node != ownedNode || !strings.HasPrefix(node, "asservat-") || cluster == node {
		t.Fatal("unified runner is not on an owned harness node")
	}
	label, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{ index .Config.Labels \"io.x-k8s.kind.cluster\" }}", node).Output()
	if err != nil || strings.TrimSpace(string(label)) != cluster {
		t.Fatal("runner node ownership differs", err)
	}
	ids, err := exec.CommandContext(ctx, "docker", "exec", node, "crictl", "ps", "-q", "--no-trunc", "--label", "io.kubernetes.pod.uid="+string(pod.UID), "--name", "continue").Output()
	id := strings.TrimSpace(string(ids))
	if err != nil || id == "" || strings.Contains(id, "\n") || pod.Status.ContainerStatuses[0].ContainerID != "containerd://"+id {
		t.Fatal("exact original continuation container missing", err)
	}
	if err = exec.CommandContext(ctx, "docker", "exec", node, "crictl", "stop", id).Run(); err != nil {
		t.Fatal("owned continuation interruption", err)
	}
}

func installerUnifiedLogs(t *testing.T, ctx context.Context, api kubernetes.Interface, pod *core.Pod) {
	t.Helper()
	for _, name := range []string{"produce", "schema", "prepare", "retire", "continue"} {
		raw, err := api.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &core.PodLogOptions{Container: name, LimitBytes: ptr.To(int64(8192)), Timestamps: true}).DoRaw(ctx)
		if err != nil {
			t.Log("unified runner log unavailable", name, err)
			continue
		}
		t.Log("unified runner", pod.UID, name, string(raw))
	}
}

func (u *installedUnifiedRunner) replay(t *testing.T, ctx context.Context, api kubernetes.Interface, kubeconfig string, desired contracts.InitialBootstrap) {
	t.Helper()
	completed := u.current(t, ctx, api)
	u.checkPhases(t, completed, true)
	var output bytes.Buffer
	if err := bootstrap.RunInstallerResume(ctx, []string{"--kubeconfig", kubeconfig, "--namespace", desired.BootstrapNamespace, "--name", desired.Name}, &output); err != nil {
		t.Fatal("completed unified runner resume", err)
	}
	if !strings.Contains(output.String(), string(completed.UID)) {
		t.Fatal("completed resume omitted original UID")
	}
	u.start(t, ctx, api)
	wait, end := context.WithTimeout(ctx, 3*time.Minute)
	defer end()
	for {
		pod := u.current(t, wait, api)
		if pod.Status.Phase == core.PodFailed {
			t.Fatal("completed five-command replay failed")
		}
		if pod.Status.Phase == core.PodSucceeded {
			u.checkPhases(t, pod, true)
			u.verifyReplay(t)
			return
		}
		installedUnifiedPoll(t, wait)
	}
}
