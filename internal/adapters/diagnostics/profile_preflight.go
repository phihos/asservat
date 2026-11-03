package diagnostics

import (
	"asservat.local/asservat/internal/domain/artifact"
	"google.golang.org/protobuf/encoding/protowire"
)

// Fixed supported pprof shape, checked before the library allocates its object
// graph. Byte limits alone do not bound repeated protobuf object overhead.
// These are input limits, not a per-query Go heap guarantee. The separately
// contained process still supplies the hard memory and eventual-join boundary.
const (
	MaxPprofSamples   = 100000
	MaxPprofLocations = 100000
	MaxPprofFunctions = 100000
	MaxPprofStrings   = 300000
	// Empirical structural allowance, not Go heap bytes: sample=2,
	// location/function=1, label=8. It preserves the qualified full-table
	// shape while allowing ordinary heap bytes labels with smaller tables.
	// Independent byte/array bounds and process containment still apply.
	MaxPprofObjectUnits        = 662144
	MaxPprofSampleLabels       = 64
	MaxPprofLocationReferences = 1 << 20
	MaxPprofSampleLocations    = 4096
	MaxPprofLines              = 1 << 20
	MaxPprofLocationLines      = 4096
	MaxPprofComments           = 4096
)

type pprofShape struct{ locations, lines, objects int }

// preflightPprof counts allocation-bearing fields using the maintained wire
// decoder. It has fixed nesting and does not interpret IDs, symbols or values.
// The unchanged pprof parser and CheckValid remain the semantic authority.
func preflightPprof(data []byte) error {
	var tables [14]int
	var shape pprofShape
	return pprofFields(data, func(field protowire.Number, typ protowire.Type, payload []byte) error {
		if field >= 1 && field <= 6 || field == 11 {
			if typ != protowire.BytesType {
				return ErrNotProfile
			}
			tables[field]++
			switch field {
			case 2:
				shape.objects += 2
			case 4, 5:
				shape.objects++
			}
			if shape.objects > MaxPprofObjectUnits {
				return artifact.ErrLimit
			}
			limit := 0
			switch field {
			case 1, 11:
				limit = maxPprofSampleTypes
			case 2:
				limit = MaxPprofSamples
			case 3:
				limit = MaxPprofMappings
			case 4:
				limit = MaxPprofLocations
			case 5:
				limit = MaxPprofFunctions
			case 6:
				limit = MaxPprofStrings
			}
			if tables[field] > limit {
				return artifact.ErrLimit
			}
			switch field {
			case 2:
				return shape.sample(payload)
			case 4:
				return shape.location(payload)
			}
		}
		if field == 13 {
			return pprofNumbers(typ, payload, &tables[13], MaxPprofComments)
		}
		return nil
	})
}

func (s *pprofShape) sample(data []byte) error {
	labels, locations, values := 0, 0, 0
	return pprofFields(data, func(field protowire.Number, typ protowire.Type, payload []byte) error {
		switch field {
		case 1:
			before := locations
			if err := pprofNumbers(typ, payload, &locations, MaxPprofSampleLocations); err != nil {
				return err
			}
			s.locations += locations - before
			if s.locations > MaxPprofLocationReferences {
				return artifact.ErrLimit
			}
		case 2:
			return pprofNumbers(typ, payload, &values, maxPprofSampleTypes)
		case 3:
			if typ != protowire.BytesType {
				return ErrNotProfile
			}
			labels++
			s.objects += 8
			if s.objects > MaxPprofObjectUnits {
				return artifact.ErrLimit
			}
			if labels > MaxPprofSampleLabels {
				return artifact.ErrLimit
			}
		}
		return nil
	})
}

func (s *pprofShape) location(data []byte) error {
	lines := 0
	return pprofFields(data, func(field protowire.Number, typ protowire.Type, _ []byte) error {
		if field == 4 {
			if typ != protowire.BytesType {
				return ErrNotProfile
			}
			lines++
			s.lines++
			if lines > MaxPprofLocationLines || s.lines > MaxPprofLines {
				return artifact.ErrLimit
			}
		}
		return nil
	})
}

// pprofNumbers accepts packed, unpacked and split repeated numeric fields, as
// does pprof. Every value is counted, including zero and malformed-tail inputs.
func pprofNumbers(typ protowire.Type, payload []byte, count *int, limit int) error {
	if typ != protowire.BytesType && typ != protowire.VarintType {
		return ErrNotProfile
	}
	for len(payload) > 0 {
		_, n := protowire.ConsumeVarint(payload)
		if n < 0 {
			return ErrNotProfile
		}
		payload = payload[n:]
		*count++
		if *count > limit {
			return artifact.ErrLimit
		}
	}
	return nil
}

// pprofFields never descends into unknown messages or groups. Pprof supports
// only wire types 0,1,2,5; groups are refused here too. Byte payloads are slices
// of the already bounded input, with no copied strings or allocated tables.
func pprofFields(data []byte, visit func(protowire.Number, protowire.Type, []byte) error) error {
	for len(data) > 0 {
		field, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return ErrNotProfile
		}
		data = data[n:]
		var payload []byte
		switch typ {
		case protowire.BytesType:
			payload, n = protowire.ConsumeBytes(data)
		case protowire.VarintType:
			_, n = protowire.ConsumeVarint(data)
			if n >= 0 {
				payload = data[:n]
			}
		case protowire.Fixed32Type:
			_, n = protowire.ConsumeFixed32(data)
		case protowire.Fixed64Type:
			_, n = protowire.ConsumeFixed64(data)
		default:
			return ErrNotProfile
		}
		if n < 0 {
			return ErrNotProfile
		}
		if err := visit(field, typ, payload); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
