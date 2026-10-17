// Package targets describes current whole-pod identities, not collection rights.
package targets

import (
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

var (
	ErrInvalid     = errors.New("invalid pinned target")
	ErrChanged     = errors.New("target identity changed")
	ErrUnavailable = errors.New("target observation unavailable")
	ErrDenied      = errors.New("target observation denied")
	ErrUnscheduled = errors.New("pod has no execution node")
	ErrUnsupported = errors.New("target owner kind unsupported by this resolver")
)

// Request comes from a previously authorized, pinned selection. The initial
// resolver handles Deployment, StatefulSet and explicitly unowned direct Pods.
// Discovery and other owner families require their own bounded resolution path.
type Request struct {
	ClusterID       string
	Namespace       configuration.NamespaceRef
	Workload        configuration.WorkloadRef
	PodName, PodUID string
}

func (r Request) Valid() bool {
	return authorization.UUID(r.ClusterID) && identity.Text(r.Namespace.Name, 63) && identity.Text(r.Namespace.UID, 64) && identity.Text(r.Workload.Name, 253) && identity.Text(r.Workload.UID, 64) && (r.Workload.Kind == "Deployment" || r.Workload.Kind == "StatefulSet" || (r.Workload.Kind == "Pod" && r.Workload.Name == r.PodName && r.Workload.UID == r.PodUID)) && identity.Text(r.PodName, 253) && identity.Text(r.PodUID, 64)
}

type PodResolution struct {
	ExecutionClass                                                   artifact.ContextExecutionClass `json:",omitempty"`
	Request                                                          Request
	Pin                                                              artifact.PinnedPod
	NodeUID, NodeBootID, PodResourceVersion, WorkloadResourceVersion string
	ObservedAt, FreshUntil                                           time.Time
}

func (p PodResolution) Target() authorization.Target {
	return authorization.Target{ClusterID: p.Request.ClusterID, NamespaceUID: p.Request.Namespace.UID, WorkloadUID: p.Request.Workload.UID, PodUID: p.Request.PodUID}
}
func (p PodResolution) Valid(now time.Time) bool {
	if !p.ExecutionClass.ValidNodeIdentity(p.NodeUID, p.NodeBootID) || (p.ExecutionClass == artifact.ContextAPIExecution && p.Pin.NodeName != "") || (p.ExecutionClass == artifact.ContextNodeExecution && !identity.Text(p.Pin.NodeName, 253)) {
		return false
	}
	if p.Request.Workload.Kind == "Pod" && p.Pin.ControllerUID != "" {
		return false
	}
	if p.Request.Workload.Kind == "StatefulSet" && p.Pin.ControllerUID != p.Request.Workload.UID {
		return false
	}
	return p.Request.Valid() && p.Pin.Namespace == p.Request.Namespace.Name && p.Pin.NamespaceUID == p.Request.Namespace.UID && p.Pin.Name == p.Request.PodName && p.Pin.UID == p.Request.PodUID && (p.ExecutionClass == artifact.ContextAPIExecution || identity.Text(p.NodeUID, 64)) && identity.Text(p.PodResourceVersion, 128) && identity.Text(p.WorkloadResourceVersion, 128) && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second) && (identity.Text(p.Pin.ControllerUID, 64) || p.Request.Workload.Kind == "Pod")
}
