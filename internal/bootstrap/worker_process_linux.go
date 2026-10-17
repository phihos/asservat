package bootstrap

import "syscall"

// Process-local limits and dumpability only. A zero RLIMIT_CORE alone does not
// suppress Linux piped core handlers. Never change this host's core_pattern.
func disableWorkerCoreDumps() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		return err
	}
	if _, _, err := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0, 0, 0, 0); err != 0 {
		return err
	}
	flag, _, err := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0, 0, 0, 0)
	if err != 0 {
		return err
	}
	if flag != 0 {
		return syscall.EPERM
	}
	return nil
}
