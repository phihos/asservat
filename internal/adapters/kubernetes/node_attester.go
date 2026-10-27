package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

// NodeAttester binds a collector's Pod-bound projected token to current
// Kubernetes state (ADR-246). TokenReview with the installation's dedicated
// node audience authenticates the token and names its Pod and Node; live
// reads then require that Pod to be a running, undeleted Pod of the named
// collector DaemonSet (by that DaemonSet's current UID) on that Node, using
// the collector service account, and the Node's kubelet-reported boot ID to
// equal the boot ID the process read from its kernel. The connector account
// needs only: create tokenreviews; get pods and daemonsets in the collector
// namespace; get nodes. It holds no write permission.
type NodeAttester struct {
	client         *PermissionClient
	audience       string
	namespace      string
	daemonSet      string
	serviceAccount string
}

var _ delivery.NodeAttester = (*NodeAttester)(nil)

func NewNodeAttester(c *PermissionClient, installationID, daemonSet, serviceAccount string) (*NodeAttester, error) {
	if c == nil || installationID == "" || len(validation.IsDNS1123Subdomain(daemonSet)) != 0 || len(validation.IsDNS1123Subdomain(serviceAccount)) != 0 {
		return nil, delivery.ErrNodeInvalid
	}
	return &NodeAttester{client: c, audience: contracts.NodeTokenAudience(installationID), namespace: c.control.Name, daemonSet: daemonSet, serviceAccount: serviceAccount}, nil
}

type nodeTokenUser struct {
	podName, podUID, nodeName, nodeUID string
}

func one(extra map[string][]string, key string) string {
	if v := extra[key]; len(v) == 1 && identity.Text(v[0], 253) {
		return v[0]
	}
	return ""
}

func (a *NodeAttester) review(ctx context.Context, token []byte) (nodeTokenUser, error) {
	body, e := json.Marshal(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": map[string]any{"token": string(token), "audiences": []string{a.audience}}})
	defer clear(body)
	if e != nil {
		return nodeTokenUser{}, delivery.ErrNodeInvalid
	}
	raw, e := a.client.api.Post().AbsPath("/apis/authentication.k8s.io/v1/tokenreviews").Body(body).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if e != nil {
		return nodeTokenUser{}, delivery.ErrNodeUnavailable
	}
	if permissionJSON(raw, 64<<10, 16384) != nil {
		return nodeTokenUser{}, delivery.ErrNodeDenied
	}
	var reply struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     struct {
			Authenticated bool     `json:"authenticated"`
			Error         string   `json:"error"`
			Audiences     []string `json:"audiences"`
			User          struct {
				Username string              `json:"username"`
				Extra    map[string][]string `json:"extra"`
			} `json:"user"`
		} `json:"status"`
	}
	if json.Unmarshal(raw, &reply) != nil || reply.APIVersion != "authentication.k8s.io/v1" || reply.Kind != "TokenReview" || !reply.Status.Authenticated || reply.Status.Error != "" ||
		len(reply.Status.Audiences) != 1 || reply.Status.Audiences[0] != a.audience || reply.Status.User.Username != "system:serviceaccount:"+a.namespace+":"+a.serviceAccount {
		return nodeTokenUser{}, delivery.ErrNodeDenied
	}
	x := reply.Status.User.Extra
	u := nodeTokenUser{podName: one(x, "authentication.kubernetes.io/pod-name"), podUID: one(x, "authentication.kubernetes.io/pod-uid"),
		nodeName: one(x, "authentication.kubernetes.io/node-name"), nodeUID: one(x, "authentication.kubernetes.io/node-uid")}
	// Node claims in bound tokens need Kubernetes 1.30 or later; without them
	// the token does not bind a node and is refused.
	if u.podName == "" || u.podUID == "" || u.nodeName == "" || u.nodeUID == "" || len(validation.IsDNS1123Subdomain(u.podName)) != 0 || len(validation.IsDNS1123Subdomain(u.nodeName)) != 0 {
		return nodeTokenUser{}, delivery.ErrNodeDenied
	}
	return u, nil
}

// object reads one object and returns its exact top-level fields and metadata.
func (a *NodeAttester) object(ctx context.Context, path, apiVersion, kind, name, uid string) (map[string]json.RawMessage, error) {
	raw, err := a.client.raw(ctx, path, nil)
	defer clear(raw)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, value.ErrUnavailable) {
			return nil, delivery.ErrNodeUnavailable
		}
		return nil, delivery.ErrNodeDenied
	}
	var fields map[string]json.RawMessage
	var meta struct {
		Name              string  `json:"name"`
		UID               string  `json:"uid"`
		DeletionTimestamp *string `json:"deletionTimestamp"`
	}
	if json.Unmarshal(raw, &fields) != nil || string(fields["apiVersion"]) != `"`+apiVersion+`"` || string(fields["kind"]) != `"`+kind+`"` ||
		exactFields(fields["metadata"], "name", "uid") != nil || json.Unmarshal(fields["metadata"], &meta) != nil || meta.Name != name || (uid != "" && meta.UID != uid) || meta.DeletionTimestamp != nil {
		return nil, delivery.ErrNodeDenied
	}
	return fields, nil
}

// exactFields requires each named key to be present exactly once with that
// spelling, so case-insensitive decoding cannot substitute another field.
func exactFields(b json.RawMessage, keys ...string) error {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return delivery.ErrNodeDenied
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return delivery.ErrNodeDenied
		}
	}
	return nil
}

// PrecheckNode reads the token's unverified claims and rejects, without an
// API call, anything TokenReview would refuse for this attester: not a
// three-part JWT of at most 16 KiB, another audience or subject, expired, or
// without a bound Pod. TokenReview remains the only authentication.
func (a *NodeAttester) PrecheckNode(token []byte) error {
	if !contracts.ValidWorkerToken(token) {
		return delivery.ErrNodeInvalid
	}
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 || len(parts[1]) > 12<<10 {
		return delivery.ErrNodeDenied
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	defer clear(payload)
	if err != nil {
		return delivery.ErrNodeDenied
	}
	var claims struct {
		Aud json.RawMessage `json:"aud"`
		Sub string          `json:"sub"`
		Exp int64           `json:"exp"`
		K8s struct {
			Pod struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"pod"`
		} `json:"kubernetes.io"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Sub != "system:serviceaccount:"+a.namespace+":"+a.serviceAccount ||
		claims.K8s.Pod.Name == "" || claims.K8s.Pod.UID == "" || !a.client.now().Before(time.Unix(claims.Exp, 0)) {
		return delivery.ErrNodeDenied
	}
	var one string
	var many []string
	if json.Unmarshal(claims.Aud, &one) == nil {
		many = []string{one}
	} else if json.Unmarshal(claims.Aud, &many) != nil {
		return delivery.ErrNodeDenied
	}
	for _, aud := range many {
		if aud == a.audience {
			return nil
		}
	}
	return delivery.ErrNodeDenied
}

func (a *NodeAttester) AttestNode(ctx context.Context, token []byte, bootID string) (collector.Identity, error) {
	if ctx == nil || !contracts.ValidWorkerToken(token) || bootID == "" {
		return collector.Identity{}, delivery.ErrNodeInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	u, err := a.review(ctx, token)
	if err != nil {
		return collector.Identity{}, err
	}
	pod, err := a.object(ctx, "/api/v1/namespaces/"+a.namespace+"/pods/"+u.podName, "v1", "Pod", u.podName, u.podUID)
	if err != nil {
		return collector.Identity{}, err
	}
	var p struct {
		Metadata struct {
			OwnerReferences []struct {
				APIVersion string `json:"apiVersion"`
				Kind       string `json:"kind"`
				Name       string `json:"name"`
				UID        string `json:"uid"`
				Controller *bool  `json:"controller"`
			} `json:"ownerReferences"`
		} `json:"metadata"`
		Spec struct {
			NodeName           string `json:"nodeName"`
			ServiceAccountName string `json:"serviceAccountName"`
		} `json:"spec"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	}
	if json.Unmarshal(mustObject(pod), &p) != nil || exactFields(pod["spec"], "nodeName", "serviceAccountName") != nil || p.Spec.NodeName != u.nodeName ||
		p.Spec.ServiceAccountName != a.serviceAccount || p.Status.Phase != "Running" || len(p.Metadata.OwnerReferences) != 1 {
		return collector.Identity{}, delivery.ErrNodeDenied
	}
	owner := p.Metadata.OwnerReferences[0]
	if owner.APIVersion != "apps/v1" || owner.Kind != "DaemonSet" || owner.Name != a.daemonSet || owner.Controller == nil || !*owner.Controller {
		return collector.Identity{}, delivery.ErrNodeDenied
	}
	if _, err := a.object(ctx, "/apis/apps/v1/namespaces/"+a.namespace+"/daemonsets/"+a.daemonSet, "apps/v1", "DaemonSet", a.daemonSet, owner.UID); err != nil {
		return collector.Identity{}, err
	}
	node, err := a.object(ctx, "/api/v1/nodes/"+u.nodeName, "v1", "Node", u.nodeName, u.nodeUID)
	if err != nil {
		return collector.Identity{}, err
	}
	var n struct {
		Status struct {
			NodeInfo struct {
				BootID                  string `json:"bootID"`
				ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
			} `json:"nodeInfo"`
		} `json:"status"`
	}
	if json.Unmarshal(mustObject(node), &n) != nil || n.Status.NodeInfo.BootID != bootID || !identity.Text(n.Status.NodeInfo.ContainerRuntimeVersion, 128) {
		return collector.Identity{}, delivery.ErrNodeDenied
	}
	if ctx.Err() != nil {
		return collector.Identity{}, delivery.ErrNodeUnavailable
	}
	return collector.Identity{NodeName: u.nodeName, NodeUID: u.nodeUID, PodName: u.podName, PodUID: u.podUID, BootID: bootID, Runtime: n.Status.NodeInfo.ContainerRuntimeVersion}, nil
}

func mustObject(fields map[string]json.RawMessage) []byte {
	b, err := json.Marshal(fields)
	if err != nil {
		return nil
	}
	return b
}
