//go:build gadget && linux

// Package gadget is the embedded observation engine adapter (ADR-246, S1).

package gadget

import (
	"runtime/debug"
	"strings"

	"asservat.local/asservat/internal/domain/collector"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

const module = "github.com/inspektor-gadget/inspektor-gadget"

func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, d := range info.Deps {
		if d.Path == module {
			if d.Replace != nil {
				return d.Replace.Version
			}
			return d.Version
		}
	}
	return ""
}

// Initialize starts the embedded Inspektor Gadget local runtime (S1). Its
// host initialization terminates the whole process when debugfs or tracefs
// is missing or on a WSL2 kernel, so those facts are checked first and the
// engine is reported uninitialized instead. No gadget image is loaded and no
// registry is contacted.
func Initialize(f collector.Facts) collector.Engine {
	e := collector.Engine{Linked: true, Version: version()}
	if f.DebugFS != collector.Supported || f.TraceFS != collector.Supported || strings.HasSuffix(f.KernelRelease, "-WSL2") {
		return e
	}
	r := local.New()
	if err := r.Init(nil); err != nil {
		return e
	}
	_ = r.Close()
	e.Initialized = true
	return e
}
