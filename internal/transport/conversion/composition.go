package conversion

import (
	"bytes"
	"fmt"
	"io"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
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
			case "packetFilter", "packetBefore", "packetAfter", "syscallMode", "syscallBefore", "syscallAfter", "actionTimeout", "actionExecutionMode", "filePath", "profileDuration", "logBefore", "logAfter", "logStream":
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
			case "syscallArguments":
				e.SyscallArguments, err = syscallArgumentsFromWire(o.Value)
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

func syscallArgumentsFromWire(raw json.RawMessage) (*value.SyscallArgumentsEdit, error) {
	var in struct {
		MaxBytesPerEvent *int64 `json:"maxBytesPerEvent"`
		CaptureBuffers   *bool  `json:"captureBuffers"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&in); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF || in.MaxBytesPerEvent == nil || in.CaptureBuffers == nil {
		return nil, fmt.Errorf("syscallArguments requires maxBytesPerEvent and captureBuffers")
	}
	out := &value.SyscallArgumentsEdit{MaxBytesPerEvent: *in.MaxBytesPerEvent, CaptureBuffers: *in.CaptureBuffers}
	if !out.Bounded() {
		return nil, fmt.Errorf("syscallArguments maxBytesPerEvent must be from 1 to 4096")
	}
	return out, nil
}

// peersFromWire models a packetPeers value (ADR-283): cidrs entries and the
// Kubernetes podSelector/resourceRef entries. Any other entry shape stays
// Unmodeled so the compiler refuses it by path.
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
		if len(entry) != 1 {
			return nil, true, nil
		}
		if cidrs, ok := entry["cidrs"]; ok {
			var list []string
			if err := json.Unmarshal(cidrs, &list); err != nil {
				return nil, false, err
			}
			out.CIDRs = append(out.CIDRs, list)
			continue
		}
		e, ok := kubernetesPeerFromWire(entry)
		if !ok {
			return nil, true, nil
		}
		out.Kubernetes = append(out.Kubernetes, e)
	}
	return out, false, nil
}

func kubernetesPeerFromWire(entry map[string]json.RawMessage) (targets.PeerEntry, bool) {
	strictly := func(raw json.RawMessage, out any) bool {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		return d.Decode(out) == nil
	}
	if raw, ok := entry["podSelector"]; ok {
		var w struct {
			Namespace   string            `json:"namespace"`
			MatchLabels map[string]string `json:"matchLabels"`
		}
		if !strictly(raw, &w) || w.MatchLabels == nil {
			return targets.PeerEntry{}, false
		}
		return targets.PeerEntry{Pods: &targets.PeerPodSelector{Namespace: w.Namespace, MatchLabels: w.MatchLabels}}, true
	}
	raw, ok := entry["resourceRef"]
	var w struct {
		Kind        string  `json:"kind"`
		Namespace   string  `json:"namespace"`
		Name        string  `json:"name"`
		ServiceMode *string `json:"serviceMode"`
		ReadyOnly   *bool   `json:"readyOnly"`
	}
	if !ok || !strictly(raw, &w) || (w.ServiceMode == nil) != (w.ReadyOnly == nil) || (w.ServiceMode != nil) != (w.Kind == "Service") {
		return targets.PeerEntry{}, false
	}
	r := &targets.PeerResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}
	if w.ServiceMode != nil {
		r.ServiceMode, r.ReadyOnly = *w.ServiceMode, *w.ReadyOnly
	}
	return targets.PeerEntry{Resource: r}, true
}
