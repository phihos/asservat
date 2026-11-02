package conversion

import (
	"bytes"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/planning"
	"encoding/json"
)

// composition converts typed literal values. Fields whose value types this
// release does not model stay Unmodeled; the compiler refuses them by path.
func CompositionFromWire(in contracts.CaptureComposition) (*value.ProfileComposition, error) {
	out := &value.ProfileComposition{MaxTotalBytes: in.MaxTotalBytes, MaxDuration: in.MaxDuration}
	for _, c := range in.Components {
		component := value.ProfileComponent{ID: c.ID, Profile: value.ProfileRef{Catalog: c.ProfileRef.Catalog, Name: c.ProfileRef.Name, Version: c.ProfileRef.Version}}
		for _, o := range c.Overrides {
			e := value.ProfileEdit{ActionID: o.ActionID, Field: o.Field}
			var err error
			switch o.Field {
			case "packetFilter", "packetBefore", "packetAfter", "syscallMode", "syscallBefore", "syscallAfter", "actionTimeout", "actionExecutionMode", "filePath", "profileDuration":
				err = json.Unmarshal(o.Value, &e.Text)
				e.TextSet = err == nil && e.Text == "" // present but empty: the field validator gives the remedy
			case "syscallMaxEvents", "syscallRate", "actionMaxBytes":
				err = json.Unmarshal(o.Value, &e.Number)
			case "packetRing", "syscallRing":
				var r contracts.CaptureRing
				err = json.Unmarshal(o.Value, &r)
				e.Ring = &value.RingSettings{MaxAge: r.MaxAge, MaxBytes: r.MaxBytes, SegmentBytes: r.SegmentBytes, MaxSegments: r.MaxSegments, Medium: r.Medium, StorageProfileRef: r.StorageProfileRef}
			case "packetPeers":
				e.Peers, e.Unmodeled, err = peersFromWire(o.Value)
			case "syscallFilter":
				var f struct {
					Mode  string   `json:"mode"`
					Names []string `json:"names"`
				}
				err = json.Unmarshal(o.Value, &f)
				e.Syscalls = &value.SyscallSelection{Mode: f.Mode, Names: f.Names}
			default:
				e.Unmodeled = true
			}
			if err != nil {
				return nil, err
			}
			component.Edits = append(component.Edits, e)
		}
		out.Components = append(out.Components, component)
	}
	return out, nil
}

// peersFromWire models a cidrs-only peer selection (ADR-283). A Kubernetes
// entry (podSelector, resourceRef) stays Unmodeled so the compiler refuses it
// by path with its remedy.
func peersFromWire(raw json.RawMessage) (*value.PeerSelection, bool, error) {
	var p struct {
		Entries      []map[string]json.RawMessage `json:"entries"`
		Protocol     string                       `json:"protocol"`
		Ports        []int                        `json:"ports"`
		Resolution   string                       `json:"resolution"`
		MaxEndpoints int                          `json:"maxEndpoints"`
		MaxStaleness string                       `json:"maxStaleness"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return nil, false, err
	}
	out := &value.PeerSelection{Protocol: p.Protocol, Ports: p.Ports, Resolution: p.Resolution, MaxEndpoints: p.MaxEndpoints, MaxStaleness: p.MaxStaleness, CIDRs: [][]string{}}
	for _, entry := range p.Entries {
		cidrs, ok := entry["cidrs"]
		if !ok || len(entry) != 1 {
			return nil, true, nil
		}
		var list []string
		if err := json.Unmarshal(cidrs, &list); err != nil {
			return nil, false, err
		}
		out.CIDRs = append(out.CIDRs, list)
	}
	return out, false, nil
}
