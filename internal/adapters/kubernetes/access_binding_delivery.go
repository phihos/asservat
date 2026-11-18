package kubernetes

import (
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

// AccessBindingDelivery lists both binding kinds in the connector's cluster.
// Namespaced bindings retain the UID of their application namespace.
func (c *PermissionClient) AccessBindingDelivery(ctx context.Context) (contracts.AccessBindingDelivery, error) {
	out := contracts.AccessBindingDelivery{Items: []contracts.DeliveredAccessBinding{}}
	size := 0
	appendItem := func(o permissionObject, r value.Resource) error {
		item := contracts.DeliveredAccessBinding{Name: r.Name, UID: r.UID, ResourceVersion: r.ResourceVersion, Generation: r.Generation, Deleting: r.Deleting}
		if r.Kind == value.ClusterAccessBindingKind {
			item.Kind = r.Kind
		} else {
			// A binding from an earlier namespace incarnation has no effect.
			if r.NamespaceUID == "" {
				return nil
			}
			item.Namespace, item.NamespaceUID = r.Namespace, r.NamespaceUID
		}
		// Account for the actual JSON on the wire, including escaped text,
		// separators and the envelope. Retain only the compact spec.
		if size == 0 {
			envelope, err := json.Marshal(out)
			if err != nil {
				return err
			}
			size = len(envelope)
		}
		spec, err := json.Marshal(o.Spec)
		if err != nil {
			return err
		}
		item.Spec = spec
		encoded, err := json.Marshal(item)
		if err != nil {
			return err
		}
		size += len(encoded)
		if len(out.Items) > 0 {
			size++
		}
		if size > contracts.AccessBindingDeliveryMaxBytes {
			return value.ErrLimit
		}
		out.Items = append(out.Items, item)
		return nil
	}
	if err := c.list(ctx, "AccessBinding", "accessbindings", &out.ResourceVersion, appendItem); err != nil {
		return contracts.AccessBindingDelivery{}, err
	}
	if err := c.list(ctx, value.ClusterAccessBindingKind, "clusteraccessbindings", &out.ClusterResourceVersion, appendItem); err != nil {
		return contracts.AccessBindingDelivery{}, err
	}
	return out, nil
}

// DeliveredBindings validates a connector's delivery for cluster, the
// connector's authenticated cluster, exactly like an observed binding: a
// spec the embedded schema refuses becomes an invalid entry that grants and
// denies nothing (ADR-329). Malformed identities refuse the whole delivery.
func (d *AccessBindingSpecDecoder) DeliveredBindings(cluster string, delivery contracts.AccessBindingDelivery) ([]value.Binding, error) {
	if d == nil || d.validator == nil || !identity.Text(delivery.ResourceVersion, 128) {
		return nil, value.ErrInvalid
	}
	out := make([]value.Binding, 0, len(delivery.Items))
	for _, item := range delivery.Items {
		if len(validation.IsDNS1123Subdomain(item.Name)) != 0 || len(item.Spec) == 0 {
			return nil, value.ErrInvalid
		}
		ref := value.Resource{ClusterID: cluster, Namespace: item.Namespace, NamespaceUID: item.NamespaceUID, Kind: "AccessBinding", Name: item.Name, UID: item.UID, ResourceVersion: item.ResourceVersion, Generation: item.Generation, Deleting: item.Deleting}
		obj := permissionObject{Spec: item.Spec}
		if item.Kind == value.ClusterAccessBindingKind {
			ref.Kind = item.Kind
			// No registered fleet names are supplied to a remote author.
			// Only the authenticated cluster is available as the default scope.
			for _, b := range d.validator.clusterBindings(obj, ref) {
				if b.UnavailableDeny {
					return nil, value.ErrLimit
				}
				if !value.BindingInCluster(b, cluster) {
					return nil, value.ErrInvalid
				}
				out = append(out, b)
			}
			continue
		}
		if item.Kind != "" || len(validation.IsDNS1123Label(item.Namespace)) != 0 {
			return nil, value.ErrInvalid
		}
		b := d.validator.observedBinding(obj, ref)
		if b.UnavailableDeny {
			return nil, value.ErrLimit
		}
		if !value.BindingInCluster(b, cluster) {
			return nil, value.ErrInvalid
		}
		out = append(out, b)
	}
	return out, nil
}
