package bootstrap

import (
	"encoding/hex"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/pcap"
	"asservat.local/asservat/internal/adapters/syscalls"
	planningapp "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
)

// The public planner uses the existing packet compiler and the release's
// closed argument definitions. Resolving these pins grants no acquisition
// authority; admission and the node still check the accepted mechanism.
type publicRecorderCompiler struct{ *pcap.Compiler }

var _ planningapp.ArgumentCompiler = (*publicRecorderCompiler)(nil)

func newPublicRecorderCompiler() planningapp.FilterCompiler {
	return &publicRecorderCompiler{Compiler: pcap.NewCompiler()}
}

func (*publicRecorderCompiler) CompileArguments(names []string, buffers bool, maximum int64) (artifact.RecordingArguments, error) {
	var out artifact.RecordingArguments
	if maximum < 1 || maximum > 4096 {
		return out, syscalls.ErrArgumentUnsupported
	}
	defs, err := syscalls.ArgumentDefinitions(names, buffers, int(maximum))
	if err != nil {
		return out, err
	}
	program, err := hex.DecodeString(gadget.ArgumentObjectSHA256)
	if err != nil || len(program) != len(out.ProgramDigest) {
		return out, syscalls.ErrArgumentUnsupported
	}
	copy(out.ProgramDigest[:], program)
	out.DefinitionDigest = artifact.Digest(syscalls.ArgumentDefinitionDigest(defs))
	out.AccountingRule = artifact.Digest(collector.ArgumentObservationAccountingRule())
	out.MaxProbeBytes = int64(syscalls.ArgumentMaxProbeBytes(defs))
	out.MaxBytesPerEvent, out.MaxBytesPerSecond = maximum, planning.SensitiveMaxBytesPerSecond
	out.CaptureBuffers = buffers
	return out, nil
}
