package analysis

import (
	"net/netip"
	"slices"

	"asservat.local/asservat/internal/domain/authorization"
)

const (
	RawPacketSummaryDisplayVersion       = "approved-raw-pcap-summary/v1"
	PacketSummaryDisplayVersion          = "approved-pcap-summary/v1"
	PacketSummaryQueryUnits              = 2
	PacketSummaryWorkerBytes             = 256 << 20
	PacketSummaryMaxConversations        = 100
	PacketSummaryMaxAggregates           = 16384
	PacketSummaryMaxCount          int64 = 1_000_000_000_000
)

type PacketSummaryRequest struct{ CaseID, ArtifactID string }

func (r PacketSummaryRequest) Valid() bool {
	return authorization.UUID(r.CaseID) && authorization.UUID(r.ArtifactID)
}

// PacketSummary counts saved records and producer-reported exclusions, never
// unique datagrams or measured network loss. Nil drops means unreported.
type PacketSummary struct {
	UnclassifiedPackets    *int64               `json:"unclassified_packets,omitempty"`
	CaptureMode            string               `json:"capture_mode"`
	Packets                int64                `json:"packets"`
	Drops                  *int64               `json:"drops"`
	DropReporting          string               `json:"drop_reporting"`
	Conversations          []PacketConversation `json:"conversations"`
	ConversationsTotal     int                  `json:"conversations_total"`
	ConversationsTruncated bool                 `json:"conversations_truncated"`
}
type PacketConversation struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Packets     int64  `json:"packets"`
}

func (r PacketSummary) Valid() bool {
	classified := r.Packets
	switch r.CaptureMode {
	case "networkHeaders":
		if r.UnclassifiedPackets != nil {
			return false
		}
	case "rawPackets":
		if r.UnclassifiedPackets == nil || *r.UnclassifiedPackets < 0 || *r.UnclassifiedPackets > r.Packets {
			return false
		}
		classified -= *r.UnclassifiedPackets
	default:
		return false
	}
	if r.Packets < 0 || r.Packets > PacketSummaryMaxCount || r.Conversations == nil || r.ConversationsTotal < 0 || r.ConversationsTotal > PacketSummaryMaxAggregates || int64(r.ConversationsTotal) > classified || len(r.Conversations) != min(r.ConversationsTotal, PacketSummaryMaxConversations) || r.ConversationsTruncated != (r.ConversationsTotal > len(r.Conversations)) {
		return false
	}
	if r.Drops == nil {
		if r.DropReporting != "unavailable" {
			return false
		}
	} else if *r.Drops < 0 || *r.Drops > PacketSummaryMaxCount || (r.DropReporting != "captureExclusions" && r.DropReporting != "snapshotOutputLimit") {
		return false
	}
	var count int64
	seen := make(map[[3]string]bool, len(r.Conversations))
	for i, c := range r.Conversations {
		ports := c.Protocol == "TCP" || c.Protocol == "UDP"
		if !ports && c.Protocol != "ICMPv4" && c.Protocol != "ICMPv6" || !packetEndpoint(c.Source, ports, c.Protocol) || !packetEndpoint(c.Destination, ports, c.Protocol) || c.Packets < 1 || c.Packets > classified || i > 0 && !PacketConversationBefore(r.Conversations[i-1], c) {
			return false
		}
		key := [3]string{c.Protocol, c.Source, c.Destination}
		if seen[key] {
			return false
		}
		seen[key] = true
		count += c.Packets
	}
	return count <= classified && (r.ConversationsTruncated || count == classified)
}
func packetEndpoint(s string, ports bool, protocol string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	var ip netip.Addr
	if ports {
		v, e := netip.ParseAddrPort(s)
		if e != nil || v.String() != s {
			return false
		}
		ip = v.Addr()
	} else {
		v, e := netip.ParseAddr(s)
		if e != nil || v.String() != s {
			return false
		}
		ip = v
	}
	return ip.IsValid() && ip.Zone() == "" && !ip.Is4In6() && (protocol != "ICMPv4" || ip.Is4()) && (protocol != "ICMPv6" || ip.Is6())
}

// PacketConversationBefore fixes the public ranking and deterministic ties.
func PacketConversationBefore(a, b PacketConversation) bool {
	if a.Packets != b.Packets {
		return a.Packets > b.Packets
	}
	if a.Protocol != b.Protocol {
		return a.Protocol < b.Protocol
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	return a.Destination < b.Destination
}
func ClonePacketSummary(r PacketSummary) PacketSummary {
	r.Conversations = slices.Clone(r.Conversations)
	if r.UnclassifiedPackets != nil {
		v := *r.UnclassifiedPackets
		r.UnclassifiedPackets = &v
	}
	if r.Drops != nil {
		v := *r.Drops
		r.Drops = &v
	}
	return r
}
