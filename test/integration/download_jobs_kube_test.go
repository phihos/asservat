package integration

import (
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"encoding/json"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	scheduling "k8s.io/api/scheduling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const syntheticAcquisitionHelper = `package main
import("os";"syscall";"net";"io";"time")
func main(){
 if len(os.Args)>1&&os.Args[1]=="fixture-proxy" {
  l,e:=net.Listen("tcp",":8443");if e!=nil{os.Exit(5)}
  slots:=make(chan struct{},4)
  for {c,e:=l.Accept();if e!=nil{os.Exit(6)};select{case slots<-struct{}{}:default:c.Close();continue}
   go func(){defer func(){<-slots}();defer c.Close();c.SetDeadline(time.Now().Add(30*time.Second));u,e:=net.DialTimeout("unix","/channel.sock",5*time.Second);if e!=nil{return};defer u.Close();u.SetDeadline(time.Now().Add(30*time.Second));done:=make(chan struct{},1);go func(){io.Copy(u,c);done<-struct{}{}}();io.Copy(c,u);u.Close();c.Close();<-done}()
  }
 }
 if len(os.Args)>1&&os.Args[1]=="fixture-token" {b,e:=os.ReadFile("/run/asservat/identity/token");if e!=nil{os.Exit(2)};os.Stdout.Write(b);return}
 if len(os.Args)>1&&os.Args[1]=="fixture-stop" {if syscall.Kill(1,syscall.SIGTERM)!=nil{os.Exit(3)};return}
 os.Exit(4)
}`

func ownedDownloadImage(t *testing.T, ctx context.Context, node, base string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	tag := "asservat.synthetic/worker:" + custodyID()
	command := func(name string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, name, args...)
		out, e := cmd.Output()
		if e != nil {
			t.Fatalf("owned worker fixture command %s failed: %v", name, e)
		}
		return strings.TrimSpace(string(out))
	}
	if e := os.WriteFile(filepath.Join(dir, "main.go"), []byte(syntheticAcquisitionHelper), 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(dir, "fixture"), filepath.Join(dir, "main.go"))
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("synthetic helper build: %v: %s", e, out)
	}
	cmd = exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", filepath.Join(dir, "asservat"), "./cmd/asservat")
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("product worker build: %v: %s", e, out)
	}
	if e := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM "+base+"\nCOPY asservat /asservat\nCOPY fixture /fixture\n"), 0600); e != nil {
		t.Fatal(e)
	}
	command("docker", "build", "--quiet", "--label", "asservat.test=download-worker-fixture", "-t", tag, dir)
	t.Cleanup(func() {
		cleanup, end := context.WithTimeout(context.Background(), 20*time.Second)
		defer end()
		if e := exec.CommandContext(cleanup, "docker", "image", "rm", tag).Run(); e != nil {
			t.Error("owned synthetic image cleanup", e)
		}
	})
	command("kind", "load", "docker-image", tag, "--name", strings.TrimSuffix(node, "-control-plane"))
	list := command("docker", "exec", node, "ctr", "--namespace", "k8s.io", "images", "list")
	digest := ""
	for _, line := range strings.Split(list, "\n") {
		f := strings.Fields(line)
		if len(f) > 2 && f[0] == tag {
			digest = f[2]
		}
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatal("owned image manifest digest missing")
	}
	ref := "asservat.synthetic/worker@" + digest
	command("docker", "exec", node, "ctr", "--namespace", "k8s.io", "images", "tag", tag, ref)
	return ref, tag
}

type fixtureWorkerIdentity struct {
	worker        value.DownloadWorker
	configuration evidence.WorkerConfigurationGuard
}

func (f fixtureWorkerIdentity) ReadDownloadWorkerIdentity(ctx context.Context, _ string, _ value.KeyPeer) (value.DownloadWorkerIdentity, error) {
	start := time.Now().UTC()
	until, e := f.configuration.CurrentWorkerConfiguration(ctx, f.worker.Intent.Profile)
	return value.DownloadWorkerIdentity{Worker: f.worker, ObservedAt: start, FreshUntil: identity.Earlier(until, identity.Earlier(start.Add(5*time.Second), f.worker.Intent.RunUntil))}, e
}

func TestDownloadJobsWithRealKubernetes(t *testing.T) {
	qualifyDownloadWorkerPod(t, false)
}

func TestDownloadNativeJobsWithRealKubernetes(t *testing.T) {
	qualifyDownloadWorkerPod(t, true)
}

func qualifyDownloadWorkerPod(t *testing.T, nativeMode bool) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run make context-integration for owned Kubernetes")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var f fixture
	if json.Unmarshal(b, &f) != nil || len(f.Clusters) == 0 {
		t.Fatal("fixtures missing")
	}
	clear(b)
	ctx, end := context.WithTimeout(context.Background(), 150*time.Second)
	defer end()
	config, e := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if e != nil {
		t.Fatal(e)
	}
	admin, e := kubernetes.NewForConfig(config)
	if e != nil {
		t.Fatal(e)
	}
	sample, e := admin.CoreV1().Pods(f.Clusters[0].Pod.Namespace).Get(ctx, f.Clusters[0].Pod.Name, meta.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	image, localImage := ownedDownloadImage(t, ctx, sample.Spec.NodeName, sample.Spec.Containers[0].Image)
	namespace := "download-job-dispatch"
	if nativeMode {
		namespace = "download-native-dispatch"
	}
	ns, e := admin.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: namespace, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	sa, e := admin.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "acquisition"}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	p := syntheticWorkerProfile(custodyID())
	proofClient, e := kube.NewPermissionClient(config, p.ClusterID, cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	recoveryEpoch := custodyID()
	bootstrap := preparePodWorkerBootstrap(t, ctx, f, proofClient, localImage, p, recoveryEpoch)
	wire := contracts.WorkerControl{Format: contracts.WorkerControlFormat, InstallationID: p.InstallationID, ClusterID: p.ClusterID, Endpoint: bootstrap.endpoint, ServerRoots: [][]byte{bootstrap.serverRoot}, IssuerRoots: [][]byte{bootstrap.issuerRoot}}
	var nativeIdle *nativePodIdleAdmission
	if nativeMode {
		nativeIdle = configureNativePodFixture(t, ctx, admin, ns.Name, localImage, bootstrap, proofClient, &p, &wire)
	}
	control, _ := json.Marshal(wire)
	yes := true
	cm, e := admin.CoreV1().ConfigMaps(ns.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "control"}, Immutable: &yes, Data: map[string]string{"worker.json": string(control)}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	preempt := core.PreemptNever
	priority, e := admin.SchedulingV1().PriorityClasses().Create(ctx, &scheduling.PriorityClass{ObjectMeta: meta.ObjectMeta{Name: "asservat-" + namespace}, Value: 0, PreemptionPolicy: &preempt}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	p.PriorityClass, p.PriorityClassUID = priority.Name, string(priority.UID)
	p.Namespace, p.NamespaceUID, p.ServiceAccount, p.ServiceAccountUID, p.Image, p.ControlConfig, p.ControlConfigUID = ns.Name, string(ns.UID), sa.Name, string(sa.UID), image, cm.Name, string(cm.UID)
	p.ControlDigest, e = kube.WorkerControlDigest(cm.Data)
	if e != nil {
		t.Fatal(e)
	}
	p, configuration := qualifiedWorkerConfiguration(t, ctx, f, admin, config, p)
	now := time.Now().UTC()
	u := custodyID()
	rev := identity.Revision{UID: "synthetic", Generation: 1, Digest: [32]byte{1}}
	actor := identity.Principal{Issuer: "https://synthetic.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}
	scope := artifact.DownloadScope{RootID: u, ArtifactID: custodyID(), CaptureID: custodyID(), ClusterID: custodyID(), NamespaceUID: "source-namespace", WorkloadUID: "source-workload", PodUID: "source-pod", Version: artifact.Digest{1}, Principal: actor}
	a := artifact.DownloadAuthority{Scope: scope, PermissionEpoch: custodyID(), PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: rev, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), AccessUntil: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}
	a.Environment = artifact.DownloadEnvironment{RootID: u, InstallationID: p.InstallationID, Region: "fixture", StoreID: custodyID(), RecoveryEpoch: recoveryEpoch, Location: artifact.Location{ClusterID: scope.ClusterID, ArtifactID: scope.ArtifactID, AttemptID: custodyID()}, Principal: actor, Revision: rev, RecoveryRevision: rev, ObservedAt: now, ValidUntil: a.ValidUntil}
	i := value.DownloadWorkerIntent{ID: custodyID(), SessionID: custodyID(), Generation: 1, Profile: p, Authority: a, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	if !i.Valid() {
		t.Fatal("synthetic dispatch authority invalid")
	}
	_, e = admin.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "dispatcher"}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	credential, e := admin.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, "dispatcher", &auth.TokenRequest{}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	limited := &rest.Config{Host: config.Host, BearerToken: credential.Status.Token, TLSClientConfig: rest.TLSClientConfig{CAData: config.CAData, CAFile: config.CAFile}}
	c, e := kube.NewPermissionClient(limited, p.ClusterID, cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	jobs, e := kube.NewDownloadWorkerJobs(c, p, configuration)
	if e != nil {
		t.Fatal(e)
	}
	launch := value.DownloadWorkerLaunch{Intent: i, CheckedAt: now, Until: now.Add(5 * time.Second), MayCreate: true}
	if _, e = jobs.CreateDownloadWorker(ctx, launch); e == nil {
		t.Fatal("unprivileged dispatcher created job")
	}
	subjects := []rbac.Subject{{Kind: "ServiceAccount", Name: "dispatcher", Namespace: ns.Name}}
	_, e = admin.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: namespace}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns.Name}, Verbs: []string{"get"}}, {APIGroups: []string{"scheduling.k8s.io"}, Resources: []string{"priorityclasses"}, ResourceNames: []string{priority.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	_, e = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: namespace}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: namespace}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	_, e = admin.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "dispatcher"}, Rules: []rbac.PolicyRule{{APIGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"create"}}, {APIGroups: []string{"batch"}, Resources: []string{"jobs"}, ResourceNames: []string{i.JobName()}, Verbs: []string{"get", "delete"}}, {APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}}, {APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{sa.Name}, Verbs: []string{"get"}}, {APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{cm.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	_, e = admin.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "dispatcher"}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "dispatcher"}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if nativeMode {
		role, err := admin.RbacV1().Roles(ns.Name).Get(ctx, "dispatcher", meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		role.Rules = append(role.Rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{p.StoreCredentialSecret}, Verbs: []string{"get"}})
		if _, err = admin.RbacV1().Roles(ns.Name).Update(ctx, role, meta.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	launch.CheckedAt = time.Now().UTC()
	launch.Until = launch.CheckedAt.Add(5 * time.Second)
	receipt, e := jobs.CreateDownloadWorker(ctx, launch)
	if e != nil {
		j, _ := admin.BatchV1().Jobs(ns.Name).Get(ctx, i.JobName(), meta.GetOptions{})
		if j != nil {
			v, _ := json.Marshal(j.Spec)
			t.Logf("synthetic Job spec: %s", v)
		}
		t.Fatal("actual job creation", e)
	}
	if r, e := jobs.FindDownloadWorkerJob(ctx, i); e != nil || r != receipt {
		t.Fatal("exact Job reconciliation", e)
	}
	var worker value.DownloadWorker
	limit := time.Now().Add(20 * time.Second)
	for time.Now().Before(limit) {
		worker, e = jobs.ObserveDownloadWorker(ctx, i, receipt)
		if e == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e != nil || !worker.Valid() {
		// This namespace contains only this test's synthetic worker. Event
		// messages here help distinguish API admission failures from scheduling.
		events, eventErr := admin.CoreV1().Events(ns.Name).List(ctx, meta.ListOptions{Limit: 20})
		if eventErr != nil {
			t.Log("synthetic event lookup", eventErr)
		} else {
			for _, event := range events.Items {
				t.Logf("synthetic worker event %s: %s", event.Reason, event.Message)
			}
		}
		pods, _ := admin.CoreV1().Pods(ns.Name).List(ctx, meta.ListOptions{})
		if pods != nil {
			for _, p := range pods.Items {
				v, _ := json.Marshal(p.Spec)
				t.Logf("synthetic Pod phase=%s spec=%s", p.Status.Phase, v)
			}
		}
		t.Fatal("actual worker observation", e)
	}
	bootstrap.bind(worker, configuration)
	limit = time.Now().Add(15 * time.Second)
	ready := false
	expectedLog := "worker credentials established; native transfer unavailable\n"
	if nativeMode {
		expectedLog = "worker credentials established\n"
	}
	for time.Now().Before(limit) {
		logs, logErr := admin.CoreV1().Pods(ns.Name).GetLogs(worker.Binding.Pod, &core.PodLogOptions{LimitBytes: ptr.To(int64(1024))}).DoRaw(ctx)
		if logErr == nil && string(logs) == expectedLog {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		logs, logErr := admin.CoreV1().Pods(ns.Name).GetLogs(worker.Binding.Pod, &core.PodLogOptions{LimitBytes: ptr.To(int64(1024))}).DoRaw(ctx)
		probe, probeErr := exec.CommandContext(ctx, "kubectl", "--kubeconfig", f.Clusters[0].Config, "--request-timeout=5s", "exec", "-n", ns.Name, worker.Binding.Pod, "--", "/fixture", "fixture-token").Output()
		t.Logf("fixture token readable=%v bytes=%d", probeErr == nil, len(probe))
		clear(probe)
		pod, podErr := admin.CoreV1().Pods(ns.Name).Get(ctx, worker.Binding.Pod, meta.GetOptions{})
		if podErr == nil {
			for _, status := range pod.Status.ContainerStatuses {
				t.Logf("credential process running=%v terminated=%v", status.State.Running != nil, status.State.Terminated)
			}
		}
		t.Fatalf("compiled Pod credential startup failed: stage=%d logError=%v podError=%v logs=%s", bootstrap.exchange.stage.Load(), logErr, podErr, logs)
	}
	if nativeMode {
		limit = time.Now().Add(10 * time.Second)
		for time.Now().Before(limit) && nativeIdle.accepted.Load() < 2 {
			time.Sleep(50 * time.Millisecond)
		}
		if nativeIdle.accepted.Load() < 2 {
			t.Fatalf("native worker did not perform two current authenticated idle exchanges: accepted=%d rejected=%d", nativeIdle.accepted.Load(), nativeIdle.rejected.Load())
		}
	}
	if _, e = jobs.ObserveDownloadWorkerTermination(ctx, worker); e == nil {
		t.Fatal("running worker released")
	}
	restricted, e := kubernetes.NewForConfig(limited)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = restricted.CoreV1().Secrets(ns.Name).List(ctx, meta.ListOptions{}); !apierrors.IsForbidden(e) {
		t.Fatal("dispatcher can read secrets")
	}
	if _, e = restricted.AuthenticationV1().TokenReviews().Create(ctx, &auth.TokenReview{}, meta.CreateOptions{}); !apierrors.IsForbidden(e) {
		t.Fatal("dispatcher can review tokens")
	}
	token, e := exec.CommandContext(ctx, "kubectl", "--kubeconfig", f.Clusters[0].Config, "--request-timeout=5s", "exec", "-n", ns.Name, worker.Binding.Pod, "--", "/fixture", "fixture-token").Output()
	if e != nil {
		t.Fatal("synthetic projected token read failed")
	}
	defer clear(token)
	tokens := &actualDownloadToken{}
	tokens.set(token)
	defer tokens.set(nil)
	source, e := kube.NewDispatchedDownloadPeerAttester(proofClient, fixtureWorkerIdentity{worker, configuration}, tokens)
	if e != nil {
		t.Fatal(e)
	}
	bootstrap.checkIssuer(ctx)
	bootstrap.exchange.mu.Lock()
	peer := bootstrap.exchange.issued.Peer
	bootstrap.exchange.mu.Unlock()
	proof, e := source.ReadDownloadPeerProof(ctx, i.SessionID, peer)
	if e != nil || proof.Binding != worker.Binding || proof.FreshUntil.After(i.RunUntil) {
		t.Fatal("dispatched projected-token proof", e)
	}
	// A changed source does not rewrite the exact running Pod. Observing it
	// is not credential/evidence authority; both actual proof paths still deny.
	priority.GlobalDefault = true
	priority, e = admin.SchedulingV1().PriorityClasses().Update(ctx, priority, meta.UpdateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if observed, err := jobs.ObserveDownloadWorker(ctx, i, receipt); err != nil || observed != worker {
		t.Fatal("exact existing worker observation", err)
	}
	if _, err := source.ReadDownloadPeerProof(ctx, i.SessionID, peer); err == nil {
		t.Fatal("changed priority source granted key proof")
	}
	enrollmentProofs, err := kube.NewWorkerEnrollmentAttester(proofClient, fixtureWorkerIdentity{worker, configuration}, tokens)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = enrollmentProofs.ReadWorkerEnrollmentProof(ctx, i.SessionID, i.ID, artifact.Digest{1}); err == nil {
		t.Fatal("changed priority source granted enrollment proof")
	}
	priority.GlobalDefault = false
	if _, e = admin.SchedulingV1().PriorityClasses().Update(ctx, priority, meta.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	if e = exec.CommandContext(ctx, "kubectl", "--kubeconfig", f.Clusters[0].Config, "--request-timeout=5s", "exec", "-n", ns.Name, worker.Binding.Pod, "--", "/fixture", "fixture-stop").Run(); e != nil {
		// A native idle exchange during the changed-source window is denied, and
		// the worker fails closed by exiting. Then there is nothing left to stop.
		stopped := false
		// Kubelet reports the exit shortly after exec already fails.
		for until := time.Now().Add(5 * time.Second); nativeMode && nativeIdle.rejected.Load() > 0 && !stopped && time.Now().Before(until); time.Sleep(100 * time.Millisecond) {
			if pod, err := admin.CoreV1().Pods(ns.Name).Get(ctx, worker.Binding.Pod, meta.GetOptions{}); err == nil {
				for _, status := range pod.Status.ContainerStatuses {
					stopped = stopped || status.State.Terminated != nil
				}
			}
		}
		if !stopped {
			t.Fatal("synthetic worker stop", e)
		}
		t.Log("native worker exited after its idle exchange was denied under the changed source")
	}
	var termination value.DownloadWorkerTermination
	limit = time.Now().Add(20 * time.Second)
	for time.Now().Before(limit) {
		termination, e = jobs.ObserveDownloadWorkerTermination(ctx, worker)
		if e == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e != nil {
		t.Fatal("real worker termination", e)
	}
	// The production coordinator persists this observation before deleting.
	// One attempt measures the adapter's bounded observation after its one
	// acknowledged UID-conditional delete; no outer delete retry masks failure.
	retirementCall, finishRetirement := context.WithTimeout(ctx, 5*time.Second)
	retirementUntil, _ := retirementCall.Deadline()
	retirementStarted := time.Now()
	retired, retireErr := jobs.RetireDownloadWorker(retirementCall, termination)
	remaining, expired := time.Until(retirementUntil), retirementCall.Err()
	finishRetirement()
	t.Logf("single foreground retirement elapsed=%s original-budget-left=%s", time.Since(retirementStarted), remaining)
	if retireErr != nil || expired != nil || !retired.Valid(time.Now()) || retired.Termination != termination {
		t.Fatal("real foreground cleanup", retireErr, expired)
	}
	if _, e = source.ReadDownloadPeerProof(ctx, i.SessionID, peer); e == nil {
		t.Fatal("deleted worker retained proof")
	}
	if nativeMode {
		t.Log("actual v2 product Pod: immutable credential projection, current TLS/Pod-token proof, two distinct native nonces and idle backoff, original lifetime and positive foreground retirement; synthetic dispatch/registry/audit and no evidence transfer")
		return
	}
	t.Log("restricted real Job creation, immutable image/config pins, projected token, exact Pod binding and confirmed termination/foreground cleanup passed; compiled credential-phase executable and OpenBao-issued process credential; dispatch authority/registry and issuance audit remain fixture inputs, no native transfer")
}
