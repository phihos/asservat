package kubernetes

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/targets"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
)

// This finite preview path selects one pod. It is not the all-replica monitor or
// a general public inventory. Larger workloads can name the desired Pod until
// the separate paginated discovery workflow is qualified.
const workloadCandidateLimit = 256

// ResolveWorkload privately observes a named target and selects the first
// nonterminating owned pod in lexical name order. The node class additionally
// requires scheduling; the explicit API class can diagnose unscheduled Pods. A caller must
// authorize the exact returned target before disclosing metadata. Later capture
// admission uses ResolvePod with the returned Request, never name reselection.
//
// A Pod reference is resolved under its actual supported workload owner, so an
// owned Pod cannot acquire a separate permission or storage-budget identity.
func (c *PodTargets) ResolveWorkload(ctx context.Context, r value.WorkloadRequest) (value.PodResolution, error) {
	if !r.Valid() || r.ClusterID != c.client.clusterID || len(validation.IsDNS1123Label(r.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(r.Name)) != 0 {
		return value.PodResolution{}, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.client.now()
	ns, err := c.namedNamespace(ctx, r.Namespace)
	if err != nil {
		return value.PodResolution{}, err
	}
	pinned := value.Request{ClusterID: r.ClusterID, Namespace: ns}
	if r.Kind == "Pod" {
		pod, e := c.object(ctx, "/api/v1/namespaces/"+r.Namespace+"/pods/"+r.Name, "Pod", r.Namespace, r.Name, "")
		if e != nil {
			return value.PodResolution{}, e
		}
		pinned.PodName, pinned.PodUID = pod.ref.Name, pod.ref.UID
		pinned.Workload, err = c.podWorkload(ctx, ns.Name, pod)
	} else {
		var selector labels.Selector
		pinned.Workload, selector, err = c.namedWorkload(ctx, r)
		if err == nil {
			pinned.PodName, pinned.PodUID, err = c.selectWorkloadPod(ctx, pinned, selector, start)
		}
	}
	if err != nil {
		return value.PodResolution{}, err
	}
	// ResolvePod independently rechecks namespace, pod and owner chain, plus
	// node/boot only for node execution. It cannot renew the earlier interval.
	out, err := c.ResolvePod(ctx, pinned)
	if err != nil {
		return value.PodResolution{}, err
	}
	out.ObservedAt, out.FreshUntil = start, identity.Earlier(out.FreshUntil, start.Add(5*time.Second))
	if deadline, ok := ctx.Deadline(); ok {
		out.FreshUntil = identity.Earlier(out.FreshUntil, deadline)
	}
	if c.client.current(ctx, start, 5*time.Second) != nil || !out.Valid(c.client.now()) {
		return value.PodResolution{}, value.ErrUnavailable
	}
	return out, nil
}

func (c *PodTargets) namedNamespace(ctx context.Context, name string) (cfg.NamespaceRef, error) {
	raw, err := c.client.raw(ctx, "/api/v1/namespaces/"+name, nil)
	if err != nil {
		return cfg.NamespaceRef{}, targetReadError(err)
	}
	o, err := objectEnvelope(raw)
	if err != nil || o.APIVersion != "v1" || o.Kind != "Namespace" {
		return cfg.NamespaceRef{}, value.ErrUnavailable
	}
	m, err := decodeMetadata(o.Metadata, true)
	if err != nil {
		return cfg.NamespaceRef{}, value.ErrUnavailable
	}
	if m.Name != name || m.Deleting {
		return cfg.NamespaceRef{}, value.ErrChanged
	}
	return cfg.NamespaceRef{Name: name, UID: m.UID}, nil
}

func (c *PodTargets) namedWorkload(ctx context.Context, r value.WorkloadRequest) (cfg.WorkloadRef, labels.Selector, error) {
	plural := "deployments"
	if r.Kind == "StatefulSet" {
		plural = "statefulsets"
	}
	raw, err := c.client.raw(ctx, "/apis/apps/v1/namespaces/"+r.Namespace+"/"+plural+"/"+r.Name, nil)
	if err != nil {
		return cfg.WorkloadRef{}, nil, targetReadError(err)
	}
	o, err := objectEnvelope(raw)
	if err != nil || o.APIVersion != "apps/v1" || o.Kind != r.Kind {
		return cfg.WorkloadRef{}, nil, value.ErrUnavailable
	}
	m, err := decodeMetadata(o.Metadata, false)
	if err != nil {
		return cfg.WorkloadRef{}, nil, value.ErrUnavailable
	}
	if m.Name != r.Name || m.Namespace != r.Namespace || m.Deleting {
		return cfg.WorkloadRef{}, nil, value.ErrChanged
	}
	var spec, selectorFields map[string]json.RawMessage
	if json.Unmarshal(o.Spec, &spec) != nil || json.Unmarshal(spec["selector"], &selectorFields) != nil || selectorFields == nil {
		return cfg.WorkloadRef{}, nil, value.ErrUnavailable
	}
	var selector meta.LabelSelector
	for key, data := range selectorFields {
		switch key {
		case "matchLabels":
			if json.Unmarshal(data, &selector.MatchLabels) != nil {
				return cfg.WorkloadRef{}, nil, value.ErrUnavailable
			}
		case "matchExpressions":
			var expressions []map[string]json.RawMessage
			if json.Unmarshal(data, &expressions) != nil || len(expressions) > 64 {
				return cfg.WorkloadRef{}, nil, value.ErrUnavailable
			}
			for _, fields := range expressions {
				var expression meta.LabelSelectorRequirement
				for field := range fields {
					if field != "key" && field != "operator" && field != "values" {
						return cfg.WorkloadRef{}, nil, value.ErrUnavailable
					}
				}
				if json.Unmarshal(fields["key"], &expression.Key) != nil || json.Unmarshal(fields["operator"], &expression.Operator) != nil {
					return cfg.WorkloadRef{}, nil, value.ErrUnavailable
				}
				if data, ok := fields["values"]; ok && json.Unmarshal(data, &expression.Values) != nil {
					return cfg.WorkloadRef{}, nil, value.ErrUnavailable
				}
				selector.MatchExpressions = append(selector.MatchExpressions, expression)
			}
		default:
			return cfg.WorkloadRef{}, nil, value.ErrUnavailable
		}
	}
	if len(selector.MatchLabels) > 64 {
		return cfg.WorkloadRef{}, nil, value.ErrLimit
	}
	compiled, err := meta.LabelSelectorAsSelector(&selector)
	if err != nil || compiled.Empty() || len(compiled.String()) > 8192 {
		return cfg.WorkloadRef{}, nil, value.ErrUnavailable
	}
	return cfg.WorkloadRef{Kind: r.Kind, Name: m.Name, UID: m.UID}, compiled, nil
}

func (c *PodTargets) podWorkload(ctx context.Context, namespace string, pod targetObject) (cfg.WorkloadRef, error) {
	if pod.owner == nil {
		return cfg.WorkloadRef{Kind: "Pod", Name: pod.ref.Name, UID: pod.ref.UID}, nil
	}
	owner := pod.owner
	base := "/apis/apps/v1/namespaces/" + namespace + "/"
	if owner.APIVersion != "apps/v1" {
		return cfg.WorkloadRef{}, value.ErrUnsupported
	}
	if owner.Kind == "ReplicaSet" {
		rs, err := c.object(ctx, base+"replicasets/"+owner.Name, "ReplicaSet", namespace, owner.Name, string(owner.UID))
		if err != nil {
			return cfg.WorkloadRef{}, err
		}
		owner = rs.owner
		if owner == nil || owner.APIVersion != "apps/v1" || owner.Kind != "Deployment" {
			return cfg.WorkloadRef{}, value.ErrUnsupported
		}
	} else if owner.Kind != "StatefulSet" {
		return cfg.WorkloadRef{}, value.ErrUnsupported
	}
	plural := "deployments"
	if owner.Kind == "StatefulSet" {
		plural = "statefulsets"
	}
	root, err := c.object(ctx, base+plural+"/"+owner.Name, owner.Kind, namespace, owner.Name, string(owner.UID))
	if err != nil {
		return cfg.WorkloadRef{}, err
	}
	return cfg.WorkloadRef{Kind: root.ref.Kind, Name: root.ref.Name, UID: root.ref.UID}, nil
}

type workloadCandidate struct{ name, uid string }

func (c *PodTargets) selectWorkloadPod(ctx context.Context, r value.Request, selector labels.Selector, start time.Time) (string, string, error) {
	raw, err := c.client.raw(ctx, "/api/v1/namespaces/"+r.Namespace.Name+"/pods", map[string]string{"labelSelector": selector.String(), "limit": strconv.Itoa(workloadCandidateLimit + 1)})
	if err != nil {
		return "", "", targetReadError(err)
	}
	var fields, metadata map[string]json.RawMessage
	var version, kind, rv, next string
	var items []json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || json.Unmarshal(fields["apiVersion"], &version) != nil || version != "v1" || json.Unmarshal(fields["kind"], &kind) != nil || kind != "PodList" || json.Unmarshal(fields["metadata"], &metadata) != nil || json.Unmarshal(metadata["resourceVersion"], &rv) != nil || !identity.Text(rv, 128) || json.Unmarshal(fields["items"], &items) != nil || items == nil {
		return "", "", value.ErrUnavailable
	}
	if data, ok := metadata["continue"]; ok && json.Unmarshal(data, &next) != nil {
		return "", "", value.ErrUnavailable
	}
	if next != "" || len(items) > workloadCandidateLimit {
		return "", "", value.ErrLimit
	}
	if data, ok := metadata["remainingItemCount"]; ok {
		var remaining int64
		if json.Unmarshal(data, &remaining) != nil || remaining < 0 {
			return "", "", value.ErrUnavailable
		}
		if remaining != 0 {
			return "", "", value.ErrLimit
		}
	}
	candidates := make([]workloadCandidate, 0, len(items))
	seen := map[string]bool{}
	for _, data := range items {
		var object, m, spec map[string]json.RawMessage
		var name, uid, namespace, node string
		var podLabels map[string]string
		if json.Unmarshal(data, &object) != nil || json.Unmarshal(object["metadata"], &m) != nil || json.Unmarshal(object["spec"], &spec) != nil || json.Unmarshal(m["name"], &name) != nil || json.Unmarshal(m["uid"], &uid) != nil || json.Unmarshal(m["namespace"], &namespace) != nil || len(validation.IsDNS1123Subdomain(name)) != 0 || !identity.Text(uid, 64) || namespace != r.Namespace.Name || seen[name] || seen["uid:"+uid] {
			return "", "", value.ErrUnavailable
		}
		seen[name], seen["uid:"+uid] = true, true
		if data, ok := m["labels"]; ok && json.Unmarshal(data, &podLabels) != nil {
			return "", "", value.ErrUnavailable
		}
		if !selector.Matches(labels.Set(podLabels)) {
			return "", "", value.ErrUnavailable
		}
		if data, ok := spec["nodeName"]; ok && json.Unmarshal(data, &node) != nil {
			return "", "", value.ErrUnavailable
		}
		if (node == "" && c.executionClass == artifact.ContextNodeExecution) || (m["deletionTimestamp"] != nil && string(m["deletionTimestamp"]) != "null") {
			continue
		}
		candidates = append(candidates, workloadCandidate{name, uid})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })
	for _, candidate := range candidates {
		if c.client.current(ctx, start, 5*time.Second) != nil {
			return "", "", value.ErrUnavailable
		}
		pod, err := c.object(ctx, "/api/v1/namespaces/"+r.Namespace.Name+"/pods/"+candidate.name, "Pod", r.Namespace.Name, candidate.name, candidate.uid)
		if err != nil {
			return "", "", err
		}
		if pod.node == "" && c.executionClass == artifact.ContextNodeExecution {
			return "", "", value.ErrChanged
		}
		owner := pod.owner
		if r.Workload.Kind == "Deployment" && owner != nil && owner.APIVersion == "apps/v1" && owner.Kind == "ReplicaSet" {
			rs, err := c.object(ctx, "/apis/apps/v1/namespaces/"+r.Namespace.Name+"/replicasets/"+owner.Name, "ReplicaSet", r.Namespace.Name, owner.Name, string(owner.UID))
			if err != nil {
				return "", "", err
			}
			owner = rs.owner
		}
		if ownerMatches(owner, r.Workload.Kind, r.Workload.Name, r.Workload.UID) {
			return candidate.name, candidate.uid, nil
		}
	}
	if c.executionClass == artifact.ContextAPIExecution {
		return "", "", value.ErrNoEligiblePods
	}
	return "", "", value.ErrNoScheduledPods
}
