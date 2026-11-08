package syscalls

import v "asservat.local/asservat/internal/domain/live"

// LiveMetadata reads only the already paired fixed metadata record. A missing
// return has unknown error semantics and is omitted with a projection gap by
// the caller, rather than classifying it as a successful call.
func LiveMetadata(record []byte) (v.SyscallFields, bool) {
	c, err := UnmarshalRecord(record)
	if err != nil || c.Status != Returned && c.Status != Unmatched || c.PID < 1 || c.PID > 4194304 {
		return v.SyscallFields{}, false
	}
	out := v.SyscallFields{PID: int(c.PID), Name: Name(c.Number), Paired: c.Status == Returned}
	errno := 0
	if c.Ret < 0 && c.Ret >= -4095 {
		errno = int(-c.Ret)
		out.Error = true
	}
	out.Errno = &errno
	if out.Paired {
		if c.ExitedBoot < c.EnteredBoot || c.ExitedBoot-c.EnteredBoot > 1000000000000 {
			return v.SyscallFields{}, false
		}
		ns := int64(c.ExitedBoot - c.EnteredBoot)
		out.Duration = &ns
	}
	if out.Name == "" || len(out.Name) > 64 {
		return v.SyscallFields{}, false
	}
	return out, true
}
