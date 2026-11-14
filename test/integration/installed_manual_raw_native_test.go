package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"asservat.local/asservat/internal/domain/artifact"
)

// ADR-279 manual-raw focus: the namespace CaptureProfile "raw-capture" v1 is
// the builtin network profile republished with rawPackets caps. The default
// prefix is 96 bytes and TCP frames keep up to 200 bytes.
const (
	manualRawProfileName    = "raw-capture"
	manualRawProfileVersion = "v1"
	manualRawTCPCap         = 200
)

// manualRawProfileDefinition copies the builtin network-connections v1
// definition with a rawPackets profile and sensitiveRead impact.
func manualRawProfileDefinition() (map[string]any, error) {
	return builtinNetworkDefinitionWith(map[string]any{"kind": "rawPackets", "snaplen": 96, "protocolSnaplen": []any{map[string]any{"protocol": "tcp", "bytes": manualRawTCPCap}}})
}

// builtinNetworkDefinitionWith copies the builtin network-connections v1
// definition with the given packet profile and sensitiveRead impact.
func builtinNetworkDefinitionWith(profile map[string]any) (map[string]any, error) {
	raw, err := os.ReadFile("../../internal/application/planning/profiles/network-connections-v1.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Definition map[string]any `json:"definition"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	actions, _ := doc.Definition["recipe"].(map[string]any)["actions"].([]any)
	if len(actions) != 1 {
		return nil, fmt.Errorf("builtin network profile has %d actions", len(actions))
	}
	action := actions[0].(map[string]any)
	action["parameters"].(map[string]any)["profile"] = profile
	action["impact"] = "sensitiveRead"
	return doc.Definition, nil
}

// manualRawArguments is the public finite raw request: one on-trigger
// action, no history, five seconds after start, a reviewed filter.
func manualRawArguments(cluster, namespace, workload string) map[string]any {
	return map[string]any{
		"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"requested_retention_seconds": 600,
		"profile_composition": map[string]any{
			"components": []any{map[string]any{
				"id":         "network",
				"profileRef": map[string]string{"catalog": "namespace", "name": manualRawProfileName, "version": manualRawProfileVersion},
				"overrides": []any{
					map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"},
					map[string]any{"actionID": "sample", "field": "actionExecutionMode", "value": "onTrigger"},
					map[string]any{"actionID": "sample", "field": "packetBefore", "value": "0s"},
					map[string]any{"actionID": "sample", "field": "packetAfter", "value": "5s"},
					map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "15s"},
				},
			}},
			"maxTotalBytes": 16 << 20,
			"maxDuration":   "15s",
		},
	}
}

// manualRawPCAP is the tshark view of the downloaded raw recording.
type manualRawPCAP struct {
	Packets, Payload, MaxCaptured int
}

// checkManualRawFields checks tshark's tcp.port, frame.cap_len and frame.len
// fields: every packet on the reviewed port, every TCP frame within its
// approved cap, and at least one frame kept beyond the header-only prefix.
func checkManualRawFields(out string) (manualRawPCAP, error) {
	var s manualRawPCAP
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return s, fmt.Errorf("packet fields %q", line)
		}
		captured, e1 := strconv.Atoi(fields[1])
		length, e2 := strconv.Atoi(fields[2])
		ports := strings.Split(fields[0], ",")
		if e1 != nil || e2 != nil || len(ports) != 2 || (ports[0] != "8080" && ports[1] != "8080") {
			return s, fmt.Errorf("packet outside the reviewed TCP port: %q", line)
		}
		if captured < 1 || captured > manualRawTCPCap || captured > length {
			return s, fmt.Errorf("TCP frame kept %d of %d bytes over the approved %d-byte cap", captured, length, manualRawTCPCap)
		}
		s.Packets++
		if captured > artifact.RecordingSnaplen {
			s.Payload++
		}
		s.MaxCaptured = max(s.MaxCaptured, captured)
	}
	if s.Packets == 0 {
		return s, fmt.Errorf("no captured packets")
	}
	if s.Payload == 0 {
		return s, fmt.Errorf("no frame kept beyond the %d-byte header-only prefix", artifact.RecordingSnaplen)
	}
	return s, nil
}
