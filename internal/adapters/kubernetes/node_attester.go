package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

// NodeAttester authenticates a collector's projected token (ADR-246,
// ADR-330 D3). TokenReview with the dedicated node audience must name the
// collector service account and bind a Pod and Node; the Asservat namespace
// is administrator-only, so that account belongs to the collector DaemonSet.
// One Node read supplies the kubelet-reported boot ID and runtime. The
// connector account needs only create tokenreviews and get nodes.
type NodeAttester struct {
	client   *PermissionClient
	audience string
	subject  string
}

var _ delivery.NodeAttester = (*NodeAttester)(nil)

func NewNodeAttester(c *PermissionClient, serviceAccount string) (*NodeAttester, error) {
	if c == nil || c.clusterID == "" || len(validation.IsDNS1123Subdomain(serviceAccount)) != 0 {
		return nil, delivery.ErrNodeInvalid
	}
	return &NodeAttester{client: c, audience: contracts.NodeTokenAudience, subject: "system:serviceaccount:" + c.control.Name + ":" + serviceAccount}, nil
}

func one(extra map[string][]string, key string) string {
	if v := extra[key]; len(v) == 1 && identity.Text(v[0], 253) {
		return v[0]
	}
	return ""
}

func (a *NodeAttester) AttestNode(ctx context.Context, token []byte) (collector.Identity, error) {
	if ctx == nil || !contracts.ValidWorkerToken(token) {
		return collector.Identity{}, delivery.ErrNodeInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	body, e := json.Marshal(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": map[string]any{"token": string(token), "audiences": []string{a.audience}}})
	defer clear(body)
	if e != nil {
		return collector.Identity{}, delivery.ErrNodeInvalid
	}
	raw, e := a.client.api.Post().AbsPath("/apis/authentication.k8s.io/v1/tokenreviews").Body(body).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if e != nil {
		return collector.Identity{}, delivery.ErrNodeUnavailable
	}
	var reply struct {
		Status struct {
			Authenticated bool     `json:"authenticated"`
			Audiences     []string `json:"audiences"`
			User          struct {
				Username string              `json:"username"`
				Extra    map[string][]string `json:"extra"`
			} `json:"user"`
		} `json:"status"`
	}
	if json.Unmarshal(raw, &reply) != nil || !reply.Status.Authenticated || len(reply.Status.Audiences) != 1 || reply.Status.Audiences[0] != a.audience || reply.Status.User.Username != a.subject {
		return collector.Identity{}, delivery.ErrNodeDenied
	}
	x := reply.Status.User.Extra
	id := collector.Identity{PodName: one(x, "authentication.kubernetes.io/pod-name"), PodUID: one(x, "authentication.kubernetes.io/pod-uid"),
		NodeName: one(x, "authentication.kubernetes.io/node-name"), NodeUID: one(x, "authentication.kubernetes.io/node-uid")}
	// Node claims in bound tokens need Kubernetes 1.30 or later; without them
	// the token does not bind a node and is refused.
	if id.PodName == "" || id.PodUID == "" || id.NodeName == "" || id.NodeUID == "" || len(validation.IsDNS1123Subdomain(id.NodeName)) != 0 {
		return collector.Identity{}, delivery.ErrNodeDenied
	}
	node, e := a.client.raw(ctx, "/api/v1/nodes/"+id.NodeName, nil)
	defer clear(node)
	if e != nil {
		return collector.Identity{}, delivery.ErrNodeUnavailable
	}
	var n struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
		Status struct {
			NodeInfo struct {
				BootID                  string `json:"bootID"`
				ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
			} `json:"nodeInfo"`
		} `json:"status"`
	}
	if json.Unmarshal(node, &n) != nil || n.Metadata.UID != id.NodeUID || !identity.Text(n.Status.NodeInfo.BootID, 128) || n.Status.NodeInfo.BootID == "" || !identity.Text(n.Status.NodeInfo.ContainerRuntimeVersion, 128) {
		return collector.Identity{}, delivery.ErrNodeDenied
	}
	id.BootID, id.Runtime = n.Status.NodeInfo.BootID, n.Status.NodeInfo.ContainerRuntimeVersion
	return id, nil
}
