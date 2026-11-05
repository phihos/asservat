package cri

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	execution "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	tasks "github.com/containerd/containerd/api/services/tasks/v1"
	task "github.com/containerd/containerd/api/types/task"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type processClient struct {
	runtime.RuntimeServiceClient
	statusCalls int
	wrongPod    bool
	ctx         context.Context
}

type processTasks struct {
	tasks.TasksClient
	t *testing.T
}

func (f processTasks) Get(ctx context.Context, r *tasks.GetRequest, _ ...grpc.CallOption) (*tasks.GetResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok || len(md.Get("containerd-namespace")) != 1 || md.Get("containerd-namespace")[0] != "k8s.io" || r.ExecID != "" {
		f.t.Fatal("unscoped or exec process request")
	}
	return &tasks.GetResponse{Process: &task.Process{ID: r.ContainerID, Pid: 572, Status: task.Status_RUNNING}}, nil
}

func (f *processClient) ListPodSandbox(ctx context.Context, r *runtime.ListPodSandboxRequest, _ ...grpc.CallOption) (*runtime.ListPodSandboxResponse, error) {
	f.ctx = ctx
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if r.Filter.LabelSelector[podUIDLabel] != "pod" {
		return nil, errors.New("unfiltered")
	}
	return &runtime.ListPodSandboxResponse{Items: []*runtime.PodSandbox{{Id: "sandbox", Metadata: &runtime.PodSandboxMetadata{Uid: "pod", Name: "app", Namespace: "ns"}, State: runtime.PodSandboxState_SANDBOX_READY}}}, nil
}
func (f *processClient) ListContainers(ctx context.Context, r *runtime.ListContainersRequest, _ ...grpc.CallOption) (*runtime.ListContainersResponse, error) {
	if r.Filter.PodSandboxId != "sandbox" {
		return nil, errors.New("unfiltered")
	}
	return &runtime.ListContainersResponse{Containers: []*runtime.Container{{Id: strings.Repeat("a", 64), PodSandboxId: "sandbox", Metadata: &runtime.ContainerMetadata{Name: "app", Attempt: 2}, State: runtime.ContainerState_CONTAINER_RUNNING}}}, nil
}
func (f *processClient) ContainerStatus(ctx context.Context, r *runtime.ContainerStatusRequest, _ ...grpc.CallOption) (*runtime.ContainerStatusResponse, error) {
	if r.Verbose {
		return nil, errors.New("metadata acquisition must not read OCI argv/environment")
	}
	f.statusCalls++
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	uid := "pod"
	if f.wrongPod {
		uid = "other"
	}
	return &runtime.ContainerStatusResponse{Status: &runtime.ContainerStatus{Id: r.ContainerId, Metadata: &runtime.ContainerMetadata{Name: "app", Attempt: 2}, State: runtime.ContainerState_CONTAINER_RUNNING, Labels: map[string]string{podUIDLabel: uid}}, Info: map[string]string{"info": `{"pid":572}`}}, nil
}

func TestProcessRuntimeUsesExactPodAndCallerContext(t *testing.T) {
	f := &processClient{}
	p := &Processes{client: f, tasks: processTasks{t: t}, runtime: "containerd"}
	original := context.WithValue(context.Background(), struct{}{}, "original")
	ctx, cancel := context.WithTimeout(original, 5*time.Second)
	defer cancel()
	rows, e := p.PodProcesses(ctx, artifact.PinnedPod{UID: "pod", Name: "app", Namespace: "ns"})
	if e != nil || len(rows) != 1 || rows[0].MainPID != 572 || rows[0].RestartCount != 2 || f.ctx != ctx {
		t.Fatal(rows, e)
	}
	f.wrongPod = true
	if _, e = p.CurrentProcessMember(ctx, rows[0]); e == nil {
		t.Fatal("replacement source accepted")
	}
}
func TestProcessRuntimeCanceledBeforeLookup(t *testing.T) {
	f := &processClient{}
	p := &Processes{client: f, tasks: processTasks{t: t}, runtime: "containerd"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := p.PodProcesses(ctx, artifact.PinnedPod{UID: "pod"}); e == nil || f.statusCalls != 0 {
		t.Fatal("canceled request performed runtime lookup")
	}
	if _, e := p.CurrentProcessMember(ctx, execution.ProcessRuntimeMember{}); e == nil {
		t.Fatal("missing identity")
	}
}

func TestProcessRuntimeRefusesMissingOrRenewedOwnerDeadlineBeforeRPC(t *testing.T) {
	for _, duration := range []time.Duration{0, 6 * time.Second} {
		f := &processClient{}
		p := &Processes{client: f, tasks: processTasks{t: t}, runtime: "containerd"}
		ctx := context.Background()
		cancel := func() {}
		if duration > 0 {
			ctx, cancel = context.WithTimeout(ctx, duration)
		}
		defer cancel()
		if _, e := p.PodProcesses(ctx, artifact.PinnedPod{UID: "pod"}); e == nil || f.ctx != nil {
			t.Fatal("unbounded original owner reached runtime")
		}
	}
}
