package targets

import (
	"net/netip"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

const MaxProfilePodPorts = 256

// ProfilePortName matches EvidenceRecipe.spec.endpointBindings.portName. A
// declaration is a routing hint for the whole Pod, never process attribution.
func ProfilePortName(s string) bool {
	if len(s) == 0 || len(s) > 15 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if c != '-' || i == len(s)-1 {
			return false
		}
	}
	return true
}

type ProfilePodPort struct {
	Name, Protocol string
	Port           uint16
}

// ProfileNetwork contains only public routing observations from one exact Pod
// resource version. There is no container selector, credential or netns handle.
// HostNetwork is retained to explain an unavailable capability, not to authorize
// node-loopback access. Target retains its original observation interval.
type ProfileNetwork struct {
	Target      PodResolution
	HostNetwork bool
	Ports       []ProfilePodPort
	PrimaryIP   netip.Addr
	PodIPs      []netip.Addr
}

func (p ProfileNetwork) Valid(now time.Time) bool {
	if !p.Target.Valid(now) || p.Target.ExecutionClass != artifact.ContextNodeExecution || len(p.Ports) > MaxProfilePodPorts || len(p.PodIPs) > 2 {
		return false
	}
	// Public bindings intentionally retain their existing narrower name grammar.
	// Unrelated valid Kubernetes port names must not invalidate a whole Pod;
	// the Kubernetes adapter checks declaration syntax with its native library.
	for _, port := range p.Ports {
		if port.Port == 0 || (port.Name != "" && !identity.Text(port.Name, 15)) || (port.Protocol != "TCP" && port.Protocol != "UDP" && port.Protocol != "SCTP") {
			return false
		}
	}
	if !p.PrimaryIP.IsValid() {
		return len(p.PodIPs) == 0
	}
	if !profilePodIP(p.PrimaryIP) || (len(p.PodIPs) > 0 && p.PodIPs[0] != p.PrimaryIP) {
		return false
	}
	seenFamily := map[bool]bool{}
	for _, ip := range p.PodIPs {
		if !profilePodIP(ip) || seenFamily[ip.Is4()] {
			return false
		}
		seenFamily[ip.Is4()] = true
	}
	return true
}

func profilePodIP(ip netip.Addr) bool {
	return ip.IsValid() && ip.Zone() == "" && !ip.Is4In6() && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}
