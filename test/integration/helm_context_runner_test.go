package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
)

// This is test orchestration for the real chart, not a second installer. Only
// public values are written locally. Helm creates the original runner and its
// input objects; the existing context journey drives the actual product waits.
type helmContextRunner struct {
	kubeconfig, chartArchive, valuesPath, namespace, name, image string
	active                                                       *helmContextInvocation
}
type helmContextInvocation struct {
	mu                     sync.Mutex
	original               types.UID
	latest, terminal       *core.Pod
	commandErr, watchErr   error
	commandDone, watchDone chan struct{}
	cancel                 context.CancelFunc
}

func newHelmContextRunner(t *testing.T, kubeconfig string, input contracts.InitialBootstrapInput, setup *installerContinuationFixture, chartArchive string) *helmContextRunner {
	t.Helper()
	if os.Getenv("ASSERVAT_HELM_CONTEXT_NATIVE") != "1" || kubeconfig == "" || chartArchive == "" || setup == nil || len(input.Administrators) == 0 || input.RegistryAuthentication != "" {
		t.Fatal("actual chart context needs explicit original administration, exact preloaded image and packaged chart")
	}
	values := helmBootstrapValues(input)
	bootstrap := values["bootstrap"].(map[string]any)
	bootstrap["registrySecret"] = "" // exact preloaded owned image; no registry claim
	var continuation map[string]any
	if json.Unmarshal(setup.document, &continuation) != nil {
		t.Fatal("actual continuation public input unavailable")
	}
	delete(continuation, "format")
	delete(continuation, "namespace")
	continuation["enabled"] = true
	// classQualified belongs to the product's canonical identity document. Helm
	// accepts the operator's id/kind choices and emits the fixed qualification.
	public, ok := continuation["public"].(map[string]any)
	if !ok {
		t.Fatal("chart context public continuation unavailable")
	}
	if clients, ok := public["clients"].([]any); ok {
		for _, item := range clients {
			if client, ok := item.(map[string]any); ok {
				delete(client, "classQualified")
			}
		}
	}
	bootstrap["continuation"] = continuation
	path := filepath.Join(t.TempDir(), "helm-context-values.json")
	helmBootstrapWriteValues(t, path, values)
	runner := &helmContextRunner{kubeconfig: kubeconfig, chartArchive: chartArchive, valuesPath: path, namespace: input.BootstrapNamespace, name: input.Name + "-bootstrap", image: input.Image}
	runner.checkRenderedInputs(t, input, setup.document)
	return runner
}

// Fail the producer/consumer boundary before creating any cluster resource.
// The actual chart must retain the full declared input, including capacity and
// original administrators, in its canonical product-decoded ConfigMaps.
func (r *helmContextRunner) checkRenderedInputs(t *testing.T, input contracts.InitialBootstrapInput, continuation []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "helm", "template", "asservat", r.chartArchive, "--namespace", r.namespace, "--values", r.valuesPath, "--skip-crds", "--kube-version", "1.37.0")
	raw, err := command.Output()
	if err != nil {
		t.Fatal("actual chart context public render refused", err)
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	bootstrapFound, continuationFound, podFound := false, false, false
	for {
		var object struct {
			Kind     string            `json:"kind"`
			Metadata meta.ObjectMeta   `json:"metadata"`
			Data     map[string]string `json:"data"`
		}
		if err = decoder.Decode(&object); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal("actual chart context render unreadable", err)
		}
		if object.Kind == "Pod" && object.Metadata.Name == r.name {
			podFound = true
		}
		if object.Kind != "ConfigMap" {
			continue
		}
		if value, ok := object.Data["bootstrap.json"]; ok {
			decoded, e := contracts.DecodeInitialBootstrapInput(strings.NewReader(value))
			a, _ := json.Marshal(decoded)
			b, _ := json.Marshal(input)
			if e != nil || !bytes.Equal(a, b) {
				t.Fatal("actual chart changed original bootstrap operator input", e)
			}
			if bootstrapFound {
				t.Fatal("actual chart emitted multiple bootstrap inputs")
			}
			bootstrapFound = true
		}
		if value, ok := object.Data[contracts.InstallerContinuationFile]; ok {
			decoded, e := contracts.DecodeInstallerContinuation(strings.NewReader(value))
			a, _ := json.Marshal(decoded)
			if e != nil || !bytes.Equal(a, continuation) {
				t.Fatal("actual chart changed original continuation operator input", e)
			}
			if continuationFound {
				t.Fatal("actual chart emitted multiple continuation inputs")
			}
			continuationFound = true
		}
	}
	if !bootstrapFound || !continuationFound || !podFound {
		t.Fatal("actual chart omitted original bootstrap, continuation or runner")
	}
}

func (r *helmContextRunner) start(t *testing.T, ctx context.Context, api kubernetes.Interface) *core.Pod {
	t.Helper()
	if r.active != nil {
		select {
		case <-r.active.commandDone:
		default:
			t.Fatal("prior actual Helm invocation remains active")
		}
		select {
		case <-r.active.watchDone:
		default:
			t.Fatal("prior actual Helm watch remains active")
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	list, err := api.CoreV1().Pods(r.namespace).List(runCtx, meta.ListOptions{FieldSelector: "metadata.name=" + r.name})
	if err != nil || len(list.Items) != 0 {
		cancel()
		t.Fatal("actual chart context requires no retained/live original hook", err)
	}
	watcher, err := api.CoreV1().Pods(r.namespace).Watch(runCtx, meta.ListOptions{FieldSelector: "metadata.name=" + r.name, ResourceVersion: list.ResourceVersion})
	if err != nil {
		cancel()
		t.Fatal("actual chart context original hook watch unavailable", err)
	}
	run := &helmContextInvocation{commandDone: make(chan struct{}), watchDone: make(chan struct{}), cancel: cancel}
	r.active = run
	go func() {
		defer close(run.watchDone)
		defer watcher.Stop()
		for event := range watcher.ResultChan() {
			pod, ok := event.Object.(*core.Pod)
			run.mu.Lock()
			if !ok || pod.Name != r.name || pod.Namespace != r.namespace || pod.UID == "" || run.original != "" && pod.UID != run.original {
				run.watchErr = errors.New("actual chart original hook watch identity changed")
				run.mu.Unlock()
				return
			}
			run.original = pod.UID
			run.latest = pod.DeepCopy()
			terminal := pod.Status.Phase == core.PodSucceeded || pod.Status.Phase == core.PodFailed
			if terminal {
				run.terminal = pod.DeepCopy()
			}
			run.mu.Unlock()
			if terminal {
				return
			}
		}
		run.mu.Lock()
		run.watchErr = errors.New("actual chart original hook watch ended without terminal")
		run.mu.Unlock()
	}()
	go func() {
		defer close(run.commandDone)
		command := exec.CommandContext(runCtx, "helm", "upgrade", "--install", "asservat", r.chartArchive, "--kubeconfig", r.kubeconfig, "--namespace", r.namespace, "--values", r.valuesPath, "--skip-crds", "--wait", "--timeout", "30m", "--history-max", "4")
		output := &helmBootstrapOutput{}
		command.Stdout = output
		command.Stderr = output
		err := command.Run()
		run.mu.Lock()
		defer run.mu.Unlock()
		if err != nil {
			run.commandErr = fmt.Errorf("actual Helm context invocation: %w: %s", err, output.Bytes())
		}
	}()
	t.Cleanup(func() { cancel(); <-run.commandDone; <-run.watchDone })
	for {
		run.mu.Lock()
		pod := run.latest
		watchErr, commandErr := run.watchErr, run.commandErr
		run.mu.Unlock()
		if watchErr != nil || commandErr != nil {
			t.Fatal("actual chart context failed before original runner observation", watchErr, commandErr)
		}
		if pod != nil {
			return pod.DeepCopy()
		}
		installedUnifiedPoll(t, runCtx)
	}
}

func (r *helmContextRunner) current(t *testing.T, ctx context.Context, api kubernetes.Interface, original types.UID) *core.Pod {
	t.Helper()
	for {
		pod, err := api.CoreV1().Pods(r.namespace).Get(ctx, r.name, meta.GetOptions{})
		if err == nil {
			terminal := pod.Status.Phase == core.PodSucceeded || pod.Status.Phase == core.PodFailed
			if pod.UID != original || pod.DeletionTimestamp != nil && !terminal {
				t.Fatal("actual chart original runner replaced or deleted while active")
			}
			// Helm may already be removing this same positively terminal hook.
			// complete still joins its watch/command and requires final absence.
			return pod
		}
		if !apierrors.IsNotFound(err) {
			t.Fatal("actual chart original runner observation failed", err)
		}
		run := r.active
		if run == nil {
			t.Fatal("actual chart has no original invocation")
		}
		run.mu.Lock()
		terminal := run.terminal
		watchErr, commandErr := run.watchErr, run.commandErr
		run.mu.Unlock()
		if terminal != nil {
			if terminal.UID != original {
				t.Fatal("actual chart retained another runner's terminal")
			}
			return terminal.DeepCopy()
		}
		if watchErr != nil || commandErr != nil {
			t.Fatal("actual chart removed runner without observed terminal", watchErr, commandErr)
		}
		installedUnifiedPoll(t, ctx)
	}
}

func (r *helmContextRunner) complete(t *testing.T, ctx context.Context, api kubernetes.Interface, original types.UID) *core.Pod {
	t.Helper()
	run := r.active
	if run == nil {
		t.Fatal("actual chart context lacks original invocation")
	}
	for _, done := range []chan struct{}{run.commandDone, run.watchDone} {
		select {
		case <-done:
		case <-ctx.Done():
			run.cancel()
			t.Fatal("actual Helm context did not join original terminal", ctx.Err())
		}
	}
	run.mu.Lock()
	terminal := run.terminal
	watchErr, commandErr := run.watchErr, run.commandErr
	run.mu.Unlock()
	if watchErr != nil || commandErr != nil {
		t.Fatal("actual Helm context terminal failure", watchErr, commandErr)
	}
	if err := helmContextTerminalValid(terminal, r.namespace, r.name, r.image, original); err != nil {
		t.Fatal(err)
	}
	// Helm success alone is not a cleanup receipt. Require absence of that exact
	// hook after retaining its independently watched positive terminal.
	if _, err := api.CoreV1().Pods(r.namespace).Get(ctx, r.name, meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("actual chart context hook-succeeded deletion unobserved", err)
	}
	run.cancel()
	t.Log("actual packaged chart: one original five-command bootstrap Pod, canonical operator inputs, five positive exact-image exits, joined Helm success and hook deletion")
	return terminal.DeepCopy()
}

func helmContextTerminalValid(pod *core.Pod, namespace, name, image string, original types.UID) error {
	if pod == nil || pod.Name != name || pod.Namespace != namespace || original == "" || pod.UID != original || pod.Status.Phase != core.PodSucceeded || len(pod.Spec.InitContainers) != 4 || len(pod.Spec.Containers) != 1 || len(pod.Status.InitContainerStatuses) != 4 || len(pod.Status.ContainerStatuses) != 1 {
		return errors.New("actual chart context missing exact five-command positive terminal")
	}
	_, digest, ok := strings.Cut(image, "@")
	if !ok || !strings.HasPrefix(digest, "sha256:") {
		return errors.New("actual chart context image is not pinned")
	}
	names := []string{"produce", "schema", "prepare", "retire", "continue"}
	containers := append(append([]core.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...)
	statuses := append(append([]core.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)
	for i, status := range statuses {
		if containers[i].Name != names[i] || containers[i].Image != image || status.Name != names[i] || status.RestartCount != 0 || status.State.Terminated == nil || status.State.Terminated.ExitCode != 0 || !strings.HasSuffix(status.ImageID, digest) {
			return fmt.Errorf("actual chart context invalid command terminal: %s", names[i])
		}
	}
	return nil
}

// Local actual-chart boundary check; the synthetic static choices supply no
// runtime authority and start no cluster or upstream service.
func TestHelmContextRunnerRendersCanonicalOperatorInputs(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("Helm unavailable")
	}
	t.Setenv("ASSERVAT_HELM_CONTEXT_NATIVE", "1")
	raw, err := os.ReadFile("../../internal/bootstrap/testdata/helm_context_public.json")
	if err != nil {
		t.Fatal(err)
	}
	var public contracts.InstallerPublicSettings
	if json.Unmarshal(raw, &public) != nil {
		t.Fatal("static public choices unavailable")
	}
	public.Origin, public.Issuer, public.ClientID = "https://asservat.example", "https://id.example/realms/org", "console"
	public.MaxLifetimeSeconds, public.MaxLogins, public.MaxSessions, public.MaxLogoutEvents, public.GroupMaxAgeSeconds = 3600, 8, 8, 8, 300
	public.Clients = []contracts.IdentityClient{{ID: "console", Kind: "human", ClassQualified: true}}
	public.EligibleSubjects = []contracts.IdentitySubject{}
	public.EligibleGroups = []string{"stable-group-id"}
	c := contracts.InstallerContinuation{Format: contracts.InstallerContinuationFormat, Namespace: "trusted-bootstrap", WorkerProvider: contracts.InstallerProviderSelection{AuthMount: "worker-k8s", AuthMountAccessor: "worker-accessor"}, OwnerProvider: contracts.InstallerProviderSelection{AuthMount: "owner-k8s", AuthMountAccessor: "owner-accessor"}, OwnerPKIMount: "owner-pki", OwnerIssuerRootsPEM: "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n", OwnerConnections: 4, OwnerConcurrency: 2, Public: &public}
	document, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	input := contracts.InitialBootstrapInput{Format: contracts.InitialBootstrapInputFormat, Name: "install", BootstrapNamespace: c.Namespace, TargetNamespace: "asservat-runtime", RunnerAccount: "install-bootstrap-runner", Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: "operator@example.org"}}, Image: "registry.example/asservat@sha256:" + strings.Repeat("a", 64), ProbeAudience: "https://kubernetes.default.svc.cluster.local",
		Kubernetes: contracts.InitialBootstrapEndpointInput{Endpoint: "https://kubernetes.default.svc", RootsPEM: "PUBLIC-CA"}, Postgres: contracts.InitialBootstrapPostgresInput{Host: "postgres.example", Port: 5432, Database: "asservat", MaxConnections: 2, RootsPEM: "PUBLIC-CA"}, AuditStore: contracts.InitialBootstrapAuditStoreInput{Endpoint: "https://store.example", Region: "region-a", Bucket: "audit", RootsPEM: "PUBLIC-CA"}, KeyService: contracts.InitialBootstrapKeyServiceInput{Endpoint: "https://bao.example", AuditMount: "asservat-audit", AuditKey: "audit", RootsPEM: "PUBLIC-CA"}, Fleet: contracts.InitialBootstrapFleet{Issuer: public.Issuer, Clients: []string{"console"}, Subjects: []contracts.IdentitySubject{}, Groups: []string{"stable-group-id"}, DeliveryProfiles: []string{"regional-installer"}, MaxActiveBootstraps: 1, MaxBootstrapHistory: 16, MaxClusters: 1}, Providers: contracts.InitialBootstrapProviders{IssuerPolicy: "asservat-install-issuer", WrapRole: "asservat-install-wrap", WrapPolicy: "asservat-install-encrypt", UnwrapRole: "asservat-install-unwrap", UnwrapPolicy: "asservat-install-decrypt"}}
	newHelmContextRunner(t, "unused-local-only", input, &installerContinuationFixture{document: document}, "../../charts/asservat")
}
