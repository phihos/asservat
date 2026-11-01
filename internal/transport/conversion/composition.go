package conversion

import (
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
