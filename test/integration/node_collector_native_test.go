package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/domain/collector"
	cfg "asservat.local/asservat/internal/domain/configuration"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// collectorFixture is written by scripts/test-collector.py on a disposable
// runner: a kind cluster with the chart-rendered collector DaemonSet already
// applied. This test hosts the connector's real node listener (the
// NodeChannelServer that RunRegional composes) on the kind bridge, with a
// connector account holding only the attestation reads.
type collectorFixture struct {
	Kubeconfig         string `json:"kubeconfig"`
	CollectorNamespace string `json:"collectorNamespace"`
	DaemonSet          string `json:"daemonSet"`
	ServiceAccount     string `json:"serviceAccount"`
	InstallationID     string `json:"installationID"`
	ClusterID          string `json:"clusterID"`
	Listen             string `json:"listen"`
	ServerCertificate  string `json:"serverCertificate"`
	ServerKey          string `json:"serverKey"`
	Pause              string `json:"pause"`
	Busybox            string `json:"busybox"`
	S3                 string `json:"s3"`
	Work               string `json:"work"`
	Results            string `json:"results"`
	Runner             struct {
		KernelRelease string `json:"kernelRelease"`
		BTF           bool   `json:"btf"`
		Cgroup2       bool   `json:"cgroup2"`
	} `json:"runner"`
}

type lineLog struct {
	t     *testing.T
	mu    sync.Mutex
	lines []string
}

func (l *lineLog) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		l.lines = append(l.lines, line)
		l.t.Log(line)
	}
	return len(b), nil
}

func TestNodeCollectorWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_COLLECTOR_FIXTURES")
	if path == "" {
		t.Skip("run scripts/test-collector.py packet on a disposable runner (native.yml collector-packet)")
	}
	if st, err := os.Stat("/etc/asservat-disposable-host"); err != nil || !st.Mode().IsRegular() {
		t.Fatal("refused: not a disposable host")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f collectorFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	results := map[string]any{}
	defer func() {
		b, _ := json.MarshalIndent(results, "", "  ")
		_ = os.WriteFile(f.Results, b, 0o644)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
	defer cancel()
	admin, err := clientcmd.BuildConfigFromFlags("", f.Kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	k, err := kubernetes.NewForConfig(admin)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := k.CoreV1().Namespaces().Get(ctx, f.CollectorNamespace, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if ns.Labels["pod-security.kubernetes.io/enforce"] != "privileged" {
		t.Fatalf("collector namespace labels %v", ns.Labels)
	}

	// A Restricted synthetic workload namespace with one Pod that must stay
	// untouched by install, restart and uninstall of the collector.
	workload := "synthetic-restricted"
	if _, err := k.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: workload, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	pause, err := k.CoreV1().Pods(workload).Create(ctx, &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "pause"}, Spec: core.PodSpec{
		SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To[int64](65532), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
		Containers: []core.Container{{Name: "pause", Image: f.Pause, ImagePullPolicy: core.PullIfNotPresent,
			SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// The connector account: create tokenreviews, get nodes, and get pods and
	// daemonsets in the collector namespace. Nothing else.
	connectorNS := "synthetic-connector"
	if _, err := k.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: connectorNS, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := k.CoreV1().ServiceAccounts(connectorNS).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "connector"}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	subject := []rbac.Subject{{Kind: "ServiceAccount", Name: "connector", Namespace: connectorNS}}
	if _, err := k.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "synthetic-connector-nodes"}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}},
		{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"get"}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := k.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "synthetic-connector-nodes"}, Subjects: subject, RoleRef: rbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "synthetic-connector-nodes"}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := k.RbacV1().Roles(f.CollectorNamespace).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "connector-attestation"}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}, {APIGroups: []string{"apps"}, Resources: []string{"daemonsets"}, Verbs: []string{"get"}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := k.RbacV1().RoleBindings(f.CollectorNamespace).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "connector-attestation"}, Subjects: subject, RoleRef: rbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "connector-attestation"}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	token, err := k.CoreV1().ServiceAccounts(connectorNS).CreateToken(ctx, "connector", &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To[int64](3600)}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	scoped := &rest.Config{Host: admin.Host, BearerToken: token.Status.Token, TLSClientConfig: rest.TLSClientConfig{CAData: admin.CAData, CAFile: admin.CAFile, ServerName: admin.ServerName}}
	client, err := kube.NewPermissionClient(scoped, f.ClusterID, cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	attester, err := kube.NewNodeAttester(client, f.InstallationID, f.DaemonSet, f.ServiceAccount)
	if err != nil {
		t.Fatal(err)
	}
	server, err := tls.LoadX509KeyPair(f.ServerCertificate, f.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	log := &lineLog{t: t}
	s, err := bootstrap.NewNodeChannelServer(f.ClusterID, attester, server, log, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", f.Listen)
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stopServe := context.WithCancel(ctx)
	served := make(chan error, 1)
	go func() { served <- s.Serve(serveCtx, listener) }()
	defer func() { stopServe(); <-served }()

	wait := func(what string, limit time.Duration, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(limit)
		for !ok() {
			if time.Now().After(deadline) || ctx.Err() != nil {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	collectorPods := func() []core.Pod {
		l, err := k.CoreV1().Pods(f.CollectorNamespace).List(ctx, meta.ListOptions{LabelSelector: "app.kubernetes.io/name=asservat-node"})
		if err != nil {
			t.Fatal(err)
		}
		return l.Items
	}

	// 1. DaemonSet Ready and the process enrolled.
	start := time.Now()
	wait("collector Pod Running", 4*time.Minute, func() bool {
		p := collectorPods()
		for _, pod := range p {
			if pod.Status.Phase == core.PodFailed {
				t.Fatalf("collector Pod failed: %s: %s", pod.Status.Reason, pod.Status.Message)
			}
		}
		return len(p) == 1 && p[0].Status.Phase == core.PodRunning
	})
	first := collectorPods()[0]
	var firstReportAt time.Time
	var view delivery.NodeView
	wait("enrollment and first report", 2*time.Minute, func() bool {
		v := s.Channel.Nodes()
		if len(v) == 1 && v[0].Report != nil {
			view, firstReportAt = v[0], v[0].ReportedAt
			return true
		}
		return false
	})
	results["enrolledAfterSeconds"] = time.Since(start).Seconds()
	wait("Restricted workload Running", 3*time.Minute, func() bool {
		p, err := k.CoreV1().Pods(workload).Get(ctx, "pause", meta.GetOptions{})
		return err == nil && p.Status.Phase == core.PodRunning
	})
	if view.Identity.PodUID != string(first.UID) || view.Identity.PodName != first.Name || view.Identity.NodeName != first.Spec.NodeName {
		t.Fatalf("attested identity %+v for Pod %s/%s", view.Identity, first.Name, first.UID)
	}
	node, err := k.CoreV1().Nodes().Get(ctx, first.Spec.NodeName, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if view.Identity.NodeUID != string(node.UID) || view.Identity.BootID != node.Status.NodeInfo.BootID || view.Identity.Runtime != node.Status.NodeInfo.ContainerRuntimeVersion {
		t.Fatalf("node binding %+v vs %s %s", view.Identity, node.UID, node.Status.NodeInfo.BootID)
	}

	// 2. The probe reports the runner's real facts.
	facts := view.Report.Facts
	results["identity"] = map[string]string{"node": view.Identity.NodeName, "bootID": view.Identity.BootID, "runtime": view.Identity.Runtime, "epoch": view.Identity.Epoch}
	results["facts"] = facts
	results["mechanisms"] = view.Report.Mechanisms
	results["budget"] = view.Report.Budget
	if facts.KernelRelease != f.Runner.KernelRelease {
		t.Fatalf("kernel %q, runner %q", facts.KernelRelease, f.Runner.KernelRelease)
	}
	if (facts.BTF == collector.Supported) != f.Runner.BTF || (facts.CgroupV2 == collector.Supported) != f.Runner.Cgroup2 {
		t.Fatalf("BTF %s / cgroup2 %s disagree with the runner (%v/%v)", facts.BTF, facts.CgroupV2, f.Runner.BTF, f.Runner.Cgroup2)
	}
	if facts.BPF != collector.Supported || facts.TC != collector.Supported {
		t.Fatalf("BPF %s / tc %s: the granted capabilities must load a sched_cls program", facts.BPF, facts.TC)
	}
	wantTCX := collector.Unsupported
	if facts.Kernel.AtLeast(6, 6) {
		wantTCX = collector.Supported
	}
	if facts.TCX != wantTCX {
		t.Fatalf("TCX %s on kernel %s", facts.TCX, facts.Kernel)
	}
	if facts.HostProcesses != collector.Supported || facts.Runtime != collector.RuntimeContainerd || !facts.Engine.Linked || facts.Engine.Version != "v0.57.0" {
		t.Fatalf("host processes %s, runtime %s, engine %+v", facts.HostProcesses, facts.Runtime, facts.Engine)
	}
	// ADR-248: the packet recorder (the gadget's tc hook) is available; the
	// syscall recorder is not implemented yet.
	for _, m := range view.Report.Mechanisms {
		switch m.Mechanism {
		case collector.MechanismPacket:
			if m.Adapter != collector.AdapterAvailable || m.Hook != collector.HookTC || len(m.Reasons) != 0 {
				t.Fatalf("packet recorder: %+v", m)
			}
		default:
			if m.Adapter != collector.AdapterUnavailable || m.Reasons[len(m.Reasons)-1] != collector.ReasonRecorderNotImplemented {
				t.Fatalf("no syscall recorder exists yet: %+v", m)
			}
		}
	}
	if view.Report.Budget.Ceilings != (collector.Ceilings{RingBytes: 256 << 20, FrozenBytes: 256 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}) || view.Report.Budget.RingReserved != 0 {
		t.Fatalf("budget %+v", view.Report.Budget)
	}

	// 3. Status flows every 15 seconds.
	var second delivery.NodeView
	wait("second report", 40*time.Second, func() bool {
		v := s.Channel.Nodes()
		if len(v) == 1 && v[0].Reports >= 2 {
			second = v[0]
			return true
		}
		return false
	})
	interval := second.ReportedAt.Sub(firstReportAt)
	results["statusIntervalSeconds"] = interval.Seconds()
	if interval < collector.StatusInterval-time.Second || interval > collector.StatusInterval+3*time.Second || !second.Current {
		t.Fatalf("status interval %v", interval)
	}

	// 3b. ADR-248: manual networkHeaders captures through the real gadget.
	packetCaptureNative(t, ctx, k, admin, s.Channel, second, workload, f.Busybox, f.Work, f.S3, results)

	if b, err := k.CoreV1().Pods(f.CollectorNamespace).GetLogs(first.Name, &core.PodLogOptions{LimitBytes: ptr.To[int64](8 << 10)}).DoRaw(ctx); err == nil {
		results["collectorLog"] = strings.Split(strings.TrimSpace(string(b)), "\n")
	}

	// 4. A restart is a new collector generation: new Pod, new epoch; the old
	// process's certificate stops authenticating.
	if err := k.CoreV1().Pods(f.CollectorNamespace).Delete(ctx, first.Name, meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	restarted := time.Now()
	wait("restarted collector report", 3*time.Minute, func() bool {
		v := s.Channel.Nodes()
		return len(v) == 1 && v[0].Identity.PodUID != string(first.UID) && v[0].Identity.Epoch != view.Identity.Epoch && v[0].Report != nil
	})
	after := s.Channel.Nodes()[0]
	results["restart"] = map[string]any{"seconds": time.Since(restarted).Seconds(), "oldEpoch": view.Identity.Epoch, "newEpoch": after.Identity.Epoch, "sameBoot": after.Identity.BootID == view.Identity.BootID}

	// 5. Negative: the Restricted workload namespace rejects the collector's
	// Pod template.
	ds, err := k.AppsV1().DaemonSets(f.CollectorNamespace).Get(ctx, f.DaemonSet, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	probe := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "collector-in-restricted"}, Spec: *ds.Spec.Template.Spec.DeepCopy()}
	probe.Spec.ServiceAccountName = "default"
	_, err = k.CoreV1().Pods(workload).Create(ctx, probe, meta.CreateOptions{DryRun: []string{meta.DryRunAll}})
	if !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "violates PodSecurity") {
		t.Fatalf("Restricted namespace admitted the collector template: %v", err)
	}
	results["restrictedRejection"] = err.Error()

	// 6. Uninstall leaves the workload untouched.
	if err := k.AppsV1().DaemonSets(f.CollectorNamespace).Delete(ctx, f.DaemonSet, meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := k.CoreV1().Namespaces().Delete(ctx, f.CollectorNamespace, meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	wait("collector namespace removed", 3*time.Minute, func() bool {
		_, err := k.CoreV1().Namespaces().Get(ctx, f.CollectorNamespace, meta.GetOptions{})
		return apierrors.IsNotFound(err)
	})
	now, err := k.CoreV1().Pods(workload).Get(ctx, "pause", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	restarts := int32(0)
	for _, c := range now.Status.ContainerStatuses {
		restarts += c.RestartCount
	}
	if now.UID != pause.UID || now.Status.Phase != core.PodRunning || restarts != 0 {
		t.Fatalf("workload changed: uid %s->%s phase %s restarts %d", pause.UID, now.UID, now.Status.Phase, restarts)
	}
	results["workloadUntouched"] = true
	results["connectorLog"] = log.lines
}
