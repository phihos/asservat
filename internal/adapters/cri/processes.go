// Package cri implements bounded, caller-owned runtime reads. It performs no
// runtime mutation, namespace entry or host-wide process discovery.
package cri

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	execution "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	tasks "github.com/containerd/containerd/api/services/tasks/v1"
	task "github.com/containerd/containerd/api/types/task"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

var ErrProcessSource = errors.New("process runtime source unavailable")

const podUIDLabel = "io.kubernetes.pod.uid"

type Processes struct {
	client  runtime.RuntimeServiceClient
	tasks   tasks.TasksClient
	conn    *grpc.ClientConn
	runtime string
}

// NewProcesses uses only the installation-owned runtime socket. Existing
// runtime exposure is selected explicitly by the installer. The read-only
// socket mount does not confine daemon RPC authority; only these bounded
// metadata calls are used by this implementation.
func NewProcesses(name, socket string) (*Processes, error) {
	if name != "containerd" || socket != "/run/containerd/containerd.sock" {
		return nil, ErrProcessSource
	}
	c, e := grpc.NewClient("passthrough:///asservat-cri", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(2<<20)))
	if e != nil {
		return nil, ErrProcessSource
	}
	return &Processes{client: runtime.NewRuntimeServiceClient(c), tasks: tasks.NewTasksClient(c), conn: c, runtime: name}, nil
}

func (p *Processes) Close() error {
	if p == nil || p.conn == nil {
		return nil
	}
	return p.conn.Close()
}

func (p *Processes) PodProcesses(ctx context.Context, pin artifact.PinnedPod) ([]execution.ProcessRuntimeMember, error) {
	if p == nil || p.client == nil || !processContextBound(ctx) || pin.UID == "" {
		return nil, ErrProcessSource
	}
	sandboxes, e := p.client.ListPodSandbox(ctx, &runtime.ListPodSandboxRequest{Filter: &runtime.PodSandboxFilter{State: &runtime.PodSandboxStateValue{State: runtime.PodSandboxState_SANDBOX_READY}, LabelSelector: map[string]string{podUIDLabel: pin.UID}}})
	if e != nil || len(sandboxes.GetItems()) != 1 {
		return nil, ErrProcessSource
	}
	s := sandboxes.Items[0]
	if s.Metadata == nil || s.Metadata.Uid != pin.UID || s.Metadata.Namespace != pin.Namespace || s.Metadata.Name != pin.Name || s.State != runtime.PodSandboxState_SANDBOX_READY {
		return nil, ErrProcessSource
	}
	list, e := p.client.ListContainers(ctx, &runtime.ListContainersRequest{Filter: &runtime.ContainerFilter{PodSandboxId: s.Id}})
	if e != nil || len(list.GetContainers()) > artifact.ProcessMaxContainers {
		return nil, ErrProcessSource
	}
	out := make([]execution.ProcessRuntimeMember, 0, len(list.Containers))
	seen := map[string]bool{}
	for _, c := range list.Containers {
		if c == nil || c.Metadata == nil || c.PodSandboxId != s.Id || !validID(c.Id) || seen[c.Id] {
			return nil, ErrProcessSource
		}
		seen[c.Id] = true
		m := execution.ProcessRuntimeMember{ID: p.runtime + "://" + c.Id, SandboxID: s.Id, PodUID: pin.UID, RestartCount: c.Metadata.Attempt}
		if c.State == runtime.ContainerState_CONTAINER_RUNNING {
			m, e = p.CurrentProcessMember(ctx, m)
			if e != nil {
				return nil, e
			}
		}
		out = append(out, m)
	}
	slices.SortFunc(out, func(a, b execution.ProcessRuntimeMember) int { return strings.Compare(a.ID, b.ID) })
	return out, ctx.Err()
}

func (p *Processes) CurrentProcessMember(ctx context.Context, m execution.ProcessRuntimeMember) (execution.ProcessRuntimeMember, error) {
	var zero execution.ProcessRuntimeMember
	if p == nil || p.client == nil || p.tasks == nil || !processContextBound(ctx) || !strings.HasPrefix(m.ID, p.runtime+"://") || m.SandboxID == "" || m.PodUID == "" {
		return zero, ErrProcessSource
	}
	id := strings.TrimPrefix(m.ID, p.runtime+"://")
	if !validID(id) {
		return zero, ErrProcessSource
	}
	response, e := p.client.ContainerStatus(ctx, &runtime.ContainerStatusRequest{ContainerId: id, Verbose: false})
	if e != nil || response.GetStatus() == nil {
		return zero, ErrProcessSource
	}
	s := response.Status
	if s.Id != id || s.Metadata == nil || s.Metadata.Attempt != m.RestartCount || s.State != runtime.ContainerState_CONTAINER_RUNNING || s.Labels[podUIDLabel] != m.PodUID {
		return zero, ErrProcessSource
	}
	// Verbose CRI status contains the OCI process argv/environment. Read the
	// published metadata-only Tasks.Get API instead, in the fixed Kubernetes
	// namespace with empty ExecID: exactly the initial process, never an exec.
	call := metadata.AppendToOutgoingContext(ctx, "containerd-namespace", "k8s.io")
	current, e := p.tasks.Get(call, &tasks.GetRequest{ContainerID: id})
	if e != nil || current.GetProcess() == nil || current.Process.ID != id || current.Process.ContainerID != "" && current.Process.ContainerID != id || current.Process.Status != task.Status_RUNNING || current.Process.Pid <= 1 || current.Process.Pid > 4194304 {
		return zero, ErrProcessSource
	}
	// The original filtered list pins the immutable full runtime ID to its
	// sandbox. Status rechecks that ID, Pod label and restart count; no PID-only
	// or same-name lookup may substitute a replacement container.
	m.MainPID, m.Running = current.Process.Pid, true
	return m, ctx.Err()
}

func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Every runtime call retains an already bounded original owner; this adapter
// never invents or renews a five-second interval for an unbounded caller.
func processContextBound(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	until, ok := ctx.Deadline()
	return ok && !until.After(time.Now().Add(5*time.Second))
}
