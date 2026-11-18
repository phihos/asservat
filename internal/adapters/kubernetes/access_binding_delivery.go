package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

// AccessBindingDelivery lists both binding kinds in the connector's cluster.
// Namespaced bindings retain the UID of their application namespace.
func (c *PermissionClient) AccessBindingDelivery(ctx context.Context) (contracts.AccessBindingDelivery, error) {
	d, unplaced, err := c.bindingDelivery(ctx)
	if err != nil || len(unplaced) == 0 {
		return d, err
	}
	place, cancel := context.WithTimeout(ctx, bindingNamespaceResolve)
	defer cancel()
	for _, m := range unplaced {
		if _, err = c.placeBinding(place, m); err != nil {
			return contracts.AccessBindingDelivery{}, err
		}
	}
	if d, unplaced, err = c.bindingDelivery(ctx); err == nil && len(unplaced) != 0 {
		return contracts.AccessBindingDelivery{}, value.ErrUnavailable
	}
	return d, err
}

func (c *PermissionClient) bindingDelivery(ctx context.Context) (contracts.AccessBindingDelivery, []permissionMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rv, objects, refs, unplaced, err := c.list(ctx, "AccessBinding", "accessbindings", c.now())
	if err != nil || len(unplaced) != 0 {
		return contracts.AccessBindingDelivery{}, unplaced, err
	}
	out := contracts.AccessBindingDelivery{ResourceVersion: rv, Items: make([]contracts.DeliveredAccessBinding, 0, len(objects))}
	for i, o := range objects {
		r := refs[i]
		out.Items = append(out.Items, contracts.DeliveredAccessBinding{Namespace: r.Namespace, NamespaceUID: r.NamespaceUID, Name: r.Name, UID: r.UID, ResourceVersion: r.ResourceVersion, Generation: r.Generation, Deleting: r.Deleting, Spec: o.Spec})
	}
	out.ClusterResourceVersion, objects, refs, _, err = c.list(ctx, value.ClusterAccessBindingKind, "clusteraccessbindings", c.now())
	if err != nil {
		return contracts.AccessBindingDelivery{}, nil, err
	}
	for i, o := range objects {
		r := refs[i]
		out.Items = append(out.Items, contracts.DeliveredAccessBinding{Kind: value.ClusterAccessBindingKind, Name: r.Name, UID: r.UID, ResourceVersion: r.ResourceVersion, Generation: r.Generation, Deleting: r.Deleting, Spec: o.Spec})
	}
	return out, nil, nil
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
		if !value.BindingInCluster(b, cluster) {
			return nil, value.ErrInvalid
		}
		out = append(out, b)
	}
	return out, nil
}
