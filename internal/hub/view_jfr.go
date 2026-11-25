package hub

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/pprof/profile"
	"github.com/grafana/jfr-parser/parser"
	"github.com/grafana/jfr-parser/parser/types"
)

// A JVM's flight recording (*.jfr) holds many kinds of events and is made
// for JDK Mission Control. The console shows the part of it that answers
// the usual first questions, in pprof's viewer: where the threads ran
// (jdk.ExecutionSample, which the recorder takes of threads that run Java
// code) and where they allocated (jdk.ObjectAllocationSample, or the
// events of earlier JVMs about thread-local allocation buffers). The rest
// of the recording is for the download.

// flightRecordingProfile turns a flight recording into a profile of its
// samples.
func flightRecordingProfile(recording []byte) (converted *profile.Profile, err error) {
	if !strings.HasPrefix(string(recording[:min(len(recording), 4)]), "FLR\x00") {
		return nil, errors.New("the file does not begin as a flight recording")
	}
	// The parser reads the recording as it is laid out in memory and stops
	// a damaged one, as one that was cut short, with a panic.
	defer func() {
		if r := recover(); r != nil {
			converted, err = nil, fmt.Errorf("the flight recording is damaged: %v", r)
		}
	}()
	const ran, allocated = 0, 1
	p := parser.NewParser(recording, parser.Options{})
	converted = &profile.Profile{SampleType: []*profile.ValueType{{Type: "samples", Unit: "count"}, {Type: "allocated", Unit: "bytes"}}}
	functions := map[string]*profile.Function{}
	type line struct {
		function *profile.Function
		number   uint32
	}
	locations := map[line]*profile.Location{}
	// A chunk of the recording numbers its stacks for itself: a sample is
	// resolved when it is read, and equal stacks are found by their frames.
	samples := map[string]*profile.Sample{}
	var total [2]int64
	add := func(ref types.StackTraceRef, kind int, weight int64) {
		stack := p.GetStacktrace(ref)
		if stack == nil || len(stack.Frames) == 0 {
			return
		}
		var key strings.Builder
		at := make([]*profile.Location, 0, len(stack.Frames))
		for _, frame := range stack.Frames {
			name := "[unknown]"
			if m := p.GetMethod(frame.Method); m != nil {
				name = p.GetSymbolString(m.Name)
				if c := p.GetClass(m.Type); c != nil {
					name = strings.ReplaceAll(p.GetSymbolString(c.Name), "/", ".") + "." + name
				}
			}
			f := functions[name]
			if f == nil {
				f = &profile.Function{ID: uint64(len(functions) + 1), Name: name, SystemName: name}
				functions[name] = f
				converted.Function = append(converted.Function, f)
			}
			l := locations[line{f, frame.LineNumber}]
			if l == nil {
				l = &profile.Location{ID: uint64(len(locations) + 1), Line: []profile.Line{{Function: f, Line: int64(frame.LineNumber)}}}
				locations[line{f, frame.LineNumber}] = l
				converted.Location = append(converted.Location, l)
			}
			at = append(at, l)
			fmt.Fprintf(&key, "%d,", l.ID)
		}
		s := samples[key.String()]
		if s == nil {
			s = &profile.Sample{Location: at, Value: make([]int64, 2)}
			samples[key.String()] = s
			converted.Sample = append(converted.Sample, s)
		}
		s.Value[kind] += weight
		total[kind] += weight
	}
	for {
		event, err := p.ParseEvent()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the flight recording is damaged: %w", err)
		}
		switch event {
		case p.TypeMap.T_EXECUTION_SAMPLE:
			add(p.ExecutionSample.StackTrace, ran, 1)
		case p.TypeMap.T_ALLOC_SAMPLE:
			add(p.ObjectAllocationSample.StackTrace, allocated, int64(p.ObjectAllocationSample.Weight))
		case p.TypeMap.T_ALLOC_IN_NEW_TLAB:
			add(p.ObjectAllocationInNewTLAB.StackTrace, allocated, int64(p.ObjectAllocationInNewTLAB.TlabSize))
		case p.TypeMap.T_ALLOC_OUTSIDE_TLAB:
			add(p.ObjectAllocationOutsideTLAB.StackTrace, allocated, int64(p.ObjectAllocationOutsideTLAB.AllocationSize))
		}
	}
	switch {
	case total[ran] > 0:
		converted.DefaultSampleType = "samples"
	case total[allocated] > 0:
		converted.DefaultSampleType = "allocated"
	default:
		return nil, errors.New("the flight recording holds no samples of threads that ran or allocated; download it for JDK Mission Control to see its other events")
	}
	return converted, converted.CheckValid()
}
