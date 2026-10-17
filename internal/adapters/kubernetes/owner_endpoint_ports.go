package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Only the explicitly accepted fresh bootstrap profile uses the installed
// three-port graph. It never infers a profile from observed Service contents.
// EndpointSlice order is controller-owned; names must form this exact set.
func installedOwnerPorts(p value.OwnerPool) map[string]int32 {
	if p.NativeBootstrap != value.OwnerBootstrapProfile || p.Port != 9443 || p.NativePort != contracts.OwnerInstalledNativePort {
		return nil
	}
	return map[string]int32{"owner": 9443, "observation": contracts.OwnerInstalledNativePort, "public": contracts.OwnerInstalledPublicPort}
}

func ownerServicePorts(p value.OwnerPool, ports []core.ServicePort) bool {
	if p.NativeBootstrap == "" {
		// Preserve the original single-port contract and bytes.
		return len(ports) == 1 && ports[0].Name == "owner-control" && ports[0].Protocol == core.ProtocolTCP && ports[0].TargetPort.Type == intstr.Int && int(ports[0].TargetPort.IntVal) == p.Port && ports[0].NodePort == 0
	}
	want := installedOwnerPorts(p)
	if len(want) != 3 || len(ports) != len(want) {
		return false
	}
	for _, port := range ports {
		n, exists := want[port.Name]
		if !exists || port.Port != n || port.TargetPort.Type != intstr.Int || port.TargetPort.IntVal != n || port.Protocol != core.ProtocolTCP || port.NodePort != 0 || port.AppProtocol != nil {
			return false
		}
		delete(want, port.Name)
	}
	return len(want) == 0
}

func ownerSlicePorts(p value.OwnerPool, ports []discovery.EndpointPort) bool {
	if p.NativeBootstrap == "" {
		return len(ports) == 1 && ports[0].Name != nil && *ports[0].Name == "owner-control" && ports[0].Port != nil && int(*ports[0].Port) == p.Port && ports[0].Protocol != nil && *ports[0].Protocol == core.ProtocolTCP
	}
	want := installedOwnerPorts(p)
	if len(want) != 3 || len(ports) != len(want) {
		return false
	}
	for _, port := range ports {
		if port.Name == nil || port.Port == nil || port.Protocol == nil || port.AppProtocol != nil {
			return false
		}
		n, exists := want[*port.Name]
		if !exists || *port.Port != n || *port.Protocol != core.ProtocolTCP {
			return false
		}
		delete(want, *port.Name)
	}
	return len(want) == 0
}
