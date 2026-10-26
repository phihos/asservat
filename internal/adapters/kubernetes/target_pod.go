package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	port "asservat.local/asservat/internal/application/targets"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/targets"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

// PodTargets reuses a fixed, bounded Kubernetes transport. Bootstrap selects the
// enrolled workload cluster credential; requests cannot choose an API endpoint.
type PodTargets struct {
	client         *PermissionClient
	executionClass artifact.ContextExecutionClass
	// alerts is the cluster's configured Alertmanager (ADR-231), if any.
	alerts *Alertmanager
}

var _ port.PodResolver = (*PodTargets)(nil)

func NewPodTargets(client *PermissionClient) (*PodTargets, error) {
	if client == nil {
		return nil, value.ErrInvalid
	}
	return &PodTargets{client: client}, nil
}

// NewAPIContextTargets selects the qualified API-only resolver at composition,
// never from a public request. It does not read Nodes or require scheduling.
func NewAPIContextTargets(client *PermissionClient) (*PodTargets, error) {
	c, err := NewPodTargets(client)
	if err != nil {
		return nil, err
	}
	c.executionClass = artifact.ContextAPIExecution
	return c, nil
}

type targetObject struct {
	ref          cfg.Resource
	owner        *meta.OwnerReference
	node, bootID string
}

func (c *PodTargets) object(ctx context.Context, path, kind, namespace, name, uid string) (targetObject, error) {
	var out targetObject
	raw, err := c.client.raw(ctx, path, nil)
	if err != nil {
		return out, targetReadError(err)
	}
	var fields, metadata map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || json.Unmarshal(fields["metadata"], &metadata) != nil {
		return out, value.ErrUnavailable
	}
	var observedKind, apiVersion string
	if json.Unmarshal(fields["kind"], &observedKind) != nil || json.Unmarshal(fields["apiVersion"], &apiVersion) != nil || observedKind != kind {
		return out, value.ErrChanged
	}
	expectedAPI := "apps/v1"
	if kind == "Pod" || kind == "Node" {
		expectedAPI = "v1"
	}
	if apiVersion != expectedAPI {
		return out, value.ErrChanged
	}
	ref := cfg.Resource{ClusterID: c.client.clusterID, Kind: kind}
	for key, dst := range map[string]*string{"name": &ref.Name, "uid": &ref.UID, "resourceVersion": &ref.ResourceVersion} {
		if json.Unmarshal(metadata[key], dst) != nil {
			return out, value.ErrUnavailable
		}
	}
	if namespace != "" && json.Unmarshal(metadata["namespace"], &ref.Namespace) != nil {
		return out, value.ErrUnavailable
	}
	if ref.Name != name || (uid != "" && ref.UID != uid) || ref.Namespace != namespace || !identity.Text(ref.UID, 64) || !identity.Text(ref.ResourceVersion, 128) || (metadata["deletionTimestamp"] != nil && string(metadata["deletionTimestamp"]) != "null") {
		return out, value.ErrChanged
	}
	var owners []map[string]json.RawMessage
	if v := metadata["ownerReferences"]; v != nil {
		if json.Unmarshal(v, &owners) != nil || len(owners) > 32 {
			return out, value.ErrUnavailable
		}
	}
	for _, fields := range owners {
		var owner meta.OwnerReference
		for key := range fields {
			if key != "apiVersion" && key != "kind" && key != "name" && key != "uid" && key != "controller" && key != "blockOwnerDeletion" {
				return out, value.ErrUnavailable
			}
		}
		var ownerUID string
		for key, dst := range map[string]*string{"apiVersion": &owner.APIVersion, "kind": &owner.Kind, "name": &owner.Name, "uid": &ownerUID} {
			if json.Unmarshal(fields[key], dst) != nil || !identity.Text(*dst, 253) {
				return out, value.ErrUnavailable
			}
		}
		owner.UID = types.UID(ownerUID)
		for key, dst := range map[string]**bool{"controller": &owner.Controller, "blockOwnerDeletion": &owner.BlockOwnerDeletion} {
			if v := fields[key]; v != nil {
				if string(v) == "null" || json.Unmarshal(v, dst) != nil {
					return out, value.ErrUnavailable
				}
			}
		}
		if owner.Controller != nil && *owner.Controller {
			if out.owner != nil || !identity.Text(string(owner.UID), 64) || len(validation.IsDNS1123Subdomain(owner.Name)) != 0 {
				return out, value.ErrChanged
			}
			copy := owner
			out.owner = &copy
		}
	}
	out.ref = ref
	if kind == "Pod" {
		var spec map[string]json.RawMessage
		if json.Unmarshal(fields["spec"], &spec) != nil {
			return out, value.ErrUnavailable
		}
		if node := spec["nodeName"]; node != nil && json.Unmarshal(node, &out.node) != nil {
			return out, value.ErrUnavailable
		}
	}
	if kind == "Node" {
		var status, info map[string]json.RawMessage
		if json.Unmarshal(fields["status"], &status) != nil || json.Unmarshal(status["nodeInfo"], &info) != nil || json.Unmarshal(info["bootID"], &out.bootID) != nil || !authorization.UUID(out.bootID) {
			return out, value.ErrUnavailable
		}
	}
	return out, nil
}
func targetReadError(err error) error {
	switch err {
	case cfg.ErrDenied:
		return value.ErrDenied
	case cfg.ErrChanged:
		return value.ErrChanged
	default:
		return value.ErrUnavailable
	}
}
func ownerMatches(owner *meta.OwnerReference, kind, name, uid string) bool {
	return owner != nil && owner.APIVersion == "apps/v1" && owner.Kind == kind && owner.Name == name && string(owner.UID) == uid
}
func (c *PodTargets) chain(ctx context.Context, r value.Request, pod targetObject) (string, error) {
	base := "/apis/apps/v1/namespaces/" + r.Namespace.Name + "/"
	root := r.Workload
	switch root.Kind {
	case "Pod":
		// Do not assign an owned pod its own workload budget or silently bypass a
		// Deployment/StatefulSet grant. Resolve it under its actual supported root.
		if pod.owner != nil {
			return "", value.ErrUnsupported
		}
		return pod.ref.ResourceVersion, nil
	case "StatefulSet":
		if !ownerMatches(pod.owner, root.Kind, root.Name, root.UID) {
			return "", value.ErrChanged
		}
		object, err := c.object(ctx, base+"statefulsets/"+root.Name, root.Kind, r.Namespace.Name, root.Name, root.UID)
		return object.ref.ResourceVersion, err
	case "Deployment":
		owner := pod.owner
		if owner == nil || owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" {
			return "", value.ErrChanged
		}
		rs, err := c.object(ctx, base+"replicasets/"+owner.Name, "ReplicaSet", r.Namespace.Name, owner.Name, string(owner.UID))
		if err != nil {
			return "", err
		}
		if !ownerMatches(rs.owner, root.Kind, root.Name, root.UID) {
			return "", value.ErrChanged
		}
		object, err := c.object(ctx, base+"deployments/"+root.Name, root.Kind, r.Namespace.Name, root.Name, root.UID)
		return object.ref.ResourceVersion, err
	}
	return "", value.ErrInvalid
}
func (c *PodTargets) ResolvePod(ctx context.Context, r value.Request) (value.PodResolution, error) {
	var out value.PodResolution
	if !r.Valid() || r.ClusterID != c.client.clusterID || len(validation.IsDNS1123Label(r.Namespace.Name)) != 0 || len(validation.IsDNS1123Subdomain(r.PodName)) != 0 || len(validation.IsDNS1123Subdomain(r.Workload.Name)) != 0 {
		return out, value.ErrInvalid
	}
	if c.executionClass == artifact.ContextAPIExecution {
		return c.resolveAPIContextPod(ctx, r)
	}
	if c.executionClass != artifact.ContextNodeExecution {
		return out, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.client.now()
	ns, err := c.client.namespace(ctx, r.Namespace)
	if err != nil {
		return out, targetReadError(err)
	}
	if ns.Deleting {
		return out, value.ErrChanged
	}
	path := "/api/v1/namespaces/" + r.Namespace.Name + "/pods/" + r.PodName
	first, err := c.object(ctx, path, "Pod", r.Namespace.Name, r.PodName, r.PodUID)
	if err != nil {
		return out, err
	}
	if first.node == "" {
		return out, value.ErrUnscheduled
	}
	if len(validation.IsDNS1123Subdomain(first.node)) != 0 {
		return out, value.ErrChanged
	}
	if _, err = c.chain(ctx, r, first); err != nil {
		return out, err
	}
	node, err := c.object(ctx, "/api/v1/nodes/"+first.node, "Node", "", first.node, "")
	if err != nil {
		return out, err
	}
	last, err := c.object(ctx, path, "Pod", r.Namespace.Name, r.PodName, r.PodUID)
	if err != nil {
		return out, err
	}
	if last.node != first.node || (last.owner == nil) != (first.owner == nil) || (last.owner != nil && *last.owner.Controller && !ownerMatches(last.owner, first.owner.Kind, first.owner.Name, string(first.owner.UID))) {
		return out, value.ErrChanged
	}
	workloadRV, err := c.chain(ctx, r, last)
	if err != nil {
		return out, err
	}
	nodeAgain, err := c.object(ctx, "/api/v1/nodes/"+first.node, "Node", "", first.node, node.ref.UID)
	if err != nil {
		return out, err
	}
	if nodeAgain.bootID != node.bootID {
		return out, value.ErrChanged
	}
	ns, err = c.client.namespace(ctx, r.Namespace)
	if err != nil {
		return out, targetReadError(err)
	}
	if ns.Deleting {
		return out, value.ErrChanged
	}
	out = value.PodResolution{Request: r, Pin: artifact.PinnedPod{Namespace: r.Namespace.Name, NamespaceUID: r.Namespace.UID, Name: r.PodName, UID: r.PodUID, NodeName: last.node}, NodeUID: node.ref.UID, NodeBootID: node.bootID, PodResourceVersion: last.ref.ResourceVersion, WorkloadResourceVersion: workloadRV, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}
	if last.owner != nil {
		out.Pin.ControllerUID = string(last.owner.UID)
	}
	if c.client.current(ctx, start, 5*time.Second) != nil || !out.Valid(c.client.now()) {
		return value.PodResolution{}, value.ErrUnavailable
	}
	return out, nil
}
