package bootstrap

import (
	"slices"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

func TestFederationLocatesOwnerFromReadyNativeEndpointSlices(t *testing.T) {
	id := connectorTestID
	owner := fleet.OwnerBinding{InstallationID: id("00"), ClusterID: id("01"), IssuerEpoch: id("02"), PodUID: id("03"), ProcessEpoch: id("04")}
	item := func(name, service, ip string, family discovery.AddressType) *discovery.EndpointSlice {
		return &discovery.EndpointSlice{
			ObjectMeta:  meta.ObjectMeta{Name: name, Namespace: "hub", Labels: map[string]string{discovery.LabelServiceName: service}},
			AddressType: family,
			Ports:       []discovery.EndpointPort{{Name: ptr.To("native"), Port: ptr.To(int32(9444))}, {Name: ptr.To("operation"), Port: ptr.To(int32(9448))}},
			Endpoints:   []discovery.Endpoint{{TargetRef: &core.ObjectReference{Kind: "Pod", UID: types.UID(owner.PodUID)}, Conditions: discovery.EndpointConditions{Ready: ptr.To(true)}, Addresses: []string{ip}}},
		}
	}
	const service = "asservat-hub-api-native"
	v4 := item("v4", service, "10.1.0.11", discovery.AddressTypeIPv4)
	v6 := item("v6", service, "fd00::11", discovery.AddressTypeIPv6)
	other := item("other", service, "10.1.0.12", discovery.AddressTypeIPv4)
	other.Endpoints[0].TargetRef.UID = types.UID(id("05"))
	unready := item("unready", service, "10.1.0.13", discovery.AddressTypeIPv4)
	unready.Endpoints[0].Conditions.Ready = ptr.To(false)
	terminating := item("terminating", service, "10.1.0.14", discovery.AddressTypeIPv4)
	terminating.Endpoints[0].Conditions.Terminating = ptr.To(true)
	api := fake.NewClientset(v4, v6, other, unready, terminating, item("unrelated", "other", "10.1.0.15", discovery.AddressTypeIPv4))
	s := federationSettings{api: api, namespace: "hub", prefix: "asservat", ids: contracts.ServiceIDs{InstallationID: owner.InstallationID, ClusterID: owner.ClusterID, IssuerEpoch: owner.IssuerEpoch}}
	got, err := s.ownerEndpoints(t.Context(), owner)
	if err != nil || !slices.Equal(got, []string{"10.1.0.11:9444", "[fd00::11]:9444"}) {
		t.Fatal(got, err)
	}
	owner.ClusterID = id("06")
	if _, err := s.ownerEndpoints(t.Context(), owner); err == nil {
		t.Fatal("foreign binding accepted")
	}
	a := api.Actions()
	if len(a) != 1 || a[0].GetVerb() != "list" || a[0].GetResource().Resource != "endpointslices" || a[0].GetNamespace() != "hub" {
		t.Fatal("dial must use one namespaced EndpointSlice list", a)
	}
}
