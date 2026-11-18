package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// AccessBindingDeliveryMaxBytes bounds one connector's AccessBinding delivery
// on the lifecycle channel, the same byte budget as the hub cluster's LIST
// (ADR-329).
const AccessBindingDeliveryMaxBytes = 8 << 20

// AccessBindingDelivery is a connector's complete AccessBinding LIST of its
// own cluster (ADR-329): each object's identity, its namespace's UID and its
// raw spec. It names no cluster: the hub attributes it to the connector's
// authenticated cluster and validates every spec itself.
type AccessBindingDelivery struct {
	Unavailable     bool                     `json:"unavailable,omitempty"`
	ResourceVersion string                   `json:"resourceVersion"`
	Items           []DeliveredAccessBinding `json:"items"`
}

type DeliveredAccessBinding struct {
	Kind            string          `json:"kind,omitempty"` // Empty denotes the namespaced AccessBinding.
	Namespace       string          `json:"namespace"`
	NamespaceUID    string          `json:"namespaceUID"`
	Name            string          `json:"name"`
	UID             string          `json:"uid"`
	ResourceVersion string          `json:"resourceVersion"`
	Generation      int64           `json:"generation"`
	Deleting        bool            `json:"deleting,omitempty"`
	Spec            json.RawMessage `json:"spec"`
}

// Digest identifies a delivery's content for the hub's stored copy: the
// items only, since the LIST resource version changes with any write.
func (d AccessBindingDelivery) Digest() string {
	if d.Unavailable {
		return deliveryDigest("unavailable")
	}
	return deliveryDigest(d.Items)
}

// Bounded replaces a list that cannot fit the authenticated conversation
// with an explicit unavailable observation. A disconnected exchange still
// leaves the previous observation intact.
func (d AccessBindingDelivery) Bounded() AccessBindingDelivery {
	encoded, err := json.Marshal(d)
	if err != nil || len(encoded) > AccessBindingDeliveryMaxBytes {
		return AccessBindingDelivery{Unavailable: true}
	}
	return d
}

func deliveryDigest(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
