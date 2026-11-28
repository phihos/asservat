package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"asservat.local/asservat/internal/api"
)

// However many watches wait, the agent holds one Kubernetes watch of its
// node's pods. Each watch is told of its workload's pods only, and one that
// comes later takes the pods as it finds them for its baseline.
func TestWatchesShareOnePodWatch(t *testing.T) {
	pod := func(namespace, name, app, node string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID("uid-" + namespace + "-" + name), Labels: map[string]string{"app": app}},
			Spec:       corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "app"}}},
		}
	}
	kube := fake.NewClientset(pod("shop", "api-1", "api", "node-a"), pod("shop", "db-1", "db", "node-a"), pod("other", "api-9", "api", "node-a"), pod("shop", "api-2", "api", "node-b"))
	reports := make(chan string, 100)
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report api.Trigger
		json.NewDecoder(r.Body).Decode(&report)
		reports <- strings.Split(r.URL.Path, "/")[3] + " " + report.Pod
	}))
	defer hub.Close()
	a := &Agent{HubURL: hub.URL, Node: "node-a", Kube: kube, HTTP: http.DefaultClient, Proc: t.TempDir(), watching: map[string]context.CancelFunc{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	crashes := 0
	crash := func(namespace, name string, change func(*corev1.Pod)) {
		t.Helper()
		crashes++
		p, err := kube.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "app", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ContainerID: fmt.Sprint("c", crashes), ExitCode: 1, Reason: "Error"}}}}
		if change != nil {
			change(p)
		}
		if _, err := kube.CoreV1().Pods(namespace).Update(ctx, p, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// reported waits for the next report. A watch reports what happens
	// after it has first seen a pod: until then the pod crashes again.
	reported := func(again func()) string {
		t.Helper()
		for range 500 {
			if again != nil {
				again()
			}
			select {
			case report := <-reports:
				return report
			case <-time.After(20 * time.Millisecond):
			}
		}
		t.Fatal("no report")
		return ""
	}
	quiet := func(what string) {
		t.Helper()
		select {
		case report := <-reports:
			t.Fatalf("%s: reported %s", what, report)
		case <-time.After(200 * time.Millisecond):
		}
	}
	drain := func() {
		for {
			select {
			case <-reports:
			case <-time.After(200 * time.Millisecond):
				return
			}
		}
	}

	apis := api.Watch{ID: "apis", Selector: "app=api", CaptureRequest: api.CaptureRequest{Namespace: "shop", Workload: "Deployment/api", Recordings: []api.Recording{{Kind: api.KindPodState}}}}
	a.setWatches(ctx, []api.Watch{apis})
	if got := reported(func() { crash("shop", "api-1", nil) }); got != "apis api-1" {
		t.Fatal("the first watch reported", got)
	}
	drain()
	// Pods of other workloads, namespaces and nodes are not this watch's.
	crash("shop", "db-1", nil)
	crash("other", "api-9", nil)
	crash("shop", "api-2", nil)
	quiet("pods of others")

	// A second watch, of a single pod, takes the crash from before it for
	// that pod's state and reports the next.
	db := api.Watch{ID: "db", CaptureRequest: api.CaptureRequest{Namespace: "shop", Workload: "Pod/db-1", Recordings: []api.Recording{{Kind: api.KindPodState}}}}
	a.setWatches(ctx, []api.Watch{apis, db})
	quiet("a crash from before the watch")
	crash("shop", "db-1", nil)
	if got := reported(nil); got != "db db-1" {
		t.Fatal("the second watch reported", got)
	}
	// A pod that leaves the workload's selector is gone for its watch.
	crash("shop", "api-1", func(p *corev1.Pod) { p.Labels = map[string]string{"app": "retired"} })
	quiet("a pod that left the workload")

	watches := 0
	for _, action := range kube.Actions() {
		if action.GetVerb() == "watch" && action.GetResource().Resource == "pods" {
			watches++
		}
	}
	if watches != 1 {
		t.Fatal("Kubernetes watches of pods for two watches:", watches)
	}
	// The watch of the pods ends with the last watch that uses it.
	cancel()
	for range 500 {
		a.mu.Lock()
		users := a.pods.users
		a.mu.Unlock()
		if users == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the pods are still watched after the last watch ended")
}

// A core dump watch is for the cores of its workload's processes. One of
// them can die and leave a core while its container goes on, as a worker
// that its parent starts again: the kubelet reports no crash then, and the
// watch records all the same, with that core. A core whose container ends
// with it is recorded once, with the crash.
func TestACoreWithoutACrashIsRecorded(t *testing.T) {
	const uid = "uid-shop-api-1"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api-1", UID: uid, Labels: map[string]string{"app": "api"}},
		Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "app"}, {Name: "side"}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "app", ContainerID: "containerd://c0ffee", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
			{Name: "side", ContainerID: "containerd://decaf", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
		}},
	}
	kube := fake.NewClientset(pod)
	reports := make(chan api.Trigger, 100)
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A watch that has ended, which the agent observes a while longer.
		if strings.Contains(r.URL.Path, "/ended/") {
			http.NotFound(w, r)
			return
		}
		var report api.Trigger
		json.NewDecoder(r.Body).Decode(&report)
		reports <- report
	}))
	defer hub.Close()
	spool := CoreSpool(t.TempDir())
	os.MkdirAll(filepath.Dir(spool.marker(uid, "cores")), 0o700) // as the handler's installation leaves it
	const wait = 400 * time.Millisecond
	a := &Agent{HubURL: hub.URL, Node: "node-a", Kube: kube, HTTP: http.DefaultClient, Proc: t.TempDir(), Cores: spool, coreWait: wait, watching: map[string]context.CancelFunc{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Two watches for the same workload: a core is one's, not both's.
	watch := func(id string) api.Watch {
		return api.Watch{ID: id, Selector: "app=api", CaptureRequest: api.CaptureRequest{Namespace: "shop", Workload: "Deployment/api", Recordings: []api.Recording{{Kind: api.KindCoredump}}}}
	}
	// And one that has ended: what it takes and cannot report is the others'.
	a.setWatches(ctx, []api.Watch{watch("ended"), watch("cores"), watch("cores-too")})
	// The pod is marked for the node's handler, which then keeps its cores.
	for _, id := range []string{"ended", "cores", "cores-too"} {
		for i := 0; ; i++ {
			if _, err := os.Stat(spool.marker(uid, id)); err == nil {
				break
			} else if i == 250 {
				t.Fatal("the pod was not marked for the core handler:", err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	// core is what the handler does with a core: written, then named as finished.
	core := func(container, pid string) {
		t.Helper()
		dir := spool.cores(uid)
		os.MkdirAll(dir, 0o700)
		name := filepath.Join(dir, container+"."+pid+".1700000000")
		if err := os.WriteFile(name+".part", []byte("core of "+pid), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(name+".part", name+".core"); err != nil {
			t.Fatal(err)
		}
	}
	next := func(what string) api.Trigger {
		t.Helper()
		select {
		case report := <-reports:
			return report
		// A crash's report waits five seconds for a core that another watch took.
		case <-time.After(15 * time.Second):
			t.Fatal("no report of", what)
			return api.Trigger{}
		}
	}
	quiet := func(what string, long time.Duration) {
		t.Helper()
		select {
		case again := <-reports:
			t.Fatalf("%s: %+v", what, again)
		case <-time.After(long):
		}
	}
	taken := func(report api.Trigger) []string {
		files, _ := filepath.Glob(filepath.Join(spool.taken(report.ID), "*.core"))
		return files
	}

	// A worker dies; its container goes on. One of the two watches records.
	core("c0ffee", "4711")
	report := next("a core whose container goes on")
	if report.Pod != "api-1" || !strings.Contains(report.Message, "process 4711 of container app left a core dump") {
		t.Fatalf("reported %+v", report)
	}
	if len(taken(report)) != 1 {
		t.Fatalf("the core was not set aside for the report: %v", taken(report))
	}
	if left, _ := filepath.Glob(filepath.Join(spool.cores(uid), "*.core")); len(left) != 0 {
		t.Fatalf("the core stayed on the node: %v", left)
	}
	quiet("the other watch reported the same core, which it does not have", 3*wait)

	// Each core waits its own time: one that comes while another waits is
	// not reported with it, as its container may yet end.
	core("c0ffee", "4712")
	time.Sleep(wait * 3 / 4)
	core("decaf", "4713")
	var two []string
	for _, what := range []string{"the first of two cores", "the second of two cores"} {
		report = next(what)
		got := taken(report)
		if len(got) != 1 {
			t.Fatalf("%s: the report took %v", what, got)
		}
		two = append(two, strings.Split(filepath.Base(got[0]), ".")[1])
	}
	// Which comes first is not said: a watch that has ended may have held one of them up.
	if slices.Sort(two); !slices.Equal(two, []string{"4712", "4713"}) {
		t.Fatalf("the two reports took the cores of %v", two)
	}

	// The next one takes its container with it: the crash is reported, by
	// both watches as before, and the core is not reported once more.
	core("c0ffee", "4714")
	crashed, err := kube.CoreV1().Pods("shop").Get(ctx, "api-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	crashed.Status.ContainerStatuses[0] = corev1.ContainerStatus{Name: "app", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ContainerID: "containerd://c0ffee", ExitCode: 139, Reason: "Error"}}}
	if _, err := kube.CoreV1().Pods("shop").Update(ctx, crashed, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	with := 0
	for range 2 {
		report = next("a crash")
		if !strings.Contains(report.Message, "crashed") {
			t.Fatalf("reported %+v", report)
		}
		with += len(taken(report))
	}
	if with != 1 {
		var tree []string
		filepath.WalkDir(string(spool), func(path string, d os.DirEntry, err error) error {
			tree = append(tree, strings.TrimPrefix(path, string(spool)))
			return nil
		})
		t.Fatalf("the crash's reports hold %d cores, want 1; on the node: %v", with, tree)
	}
	quiet("the core of a crash was reported once more", 4*wait)
}
