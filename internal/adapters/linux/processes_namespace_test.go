//go:build linux

package linux

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func TestProcessNamespaceRestoresAndJoinsBeforeReturning(t *testing.T) {
	for _, restoreFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "joined success", true: "restore failure returns no source"}[restoreFailure], func(t *testing.T) {
			s, r, f := syntheticProcesses(t)
			calls := []string{}
			f.post = func() { calls = append(calls, "runtime-postcheck") }
			open := func(path string) (*os.File, error) {
				calls = append(calls, path)
				return os.Open(s.proc + "/sys/kernel/random/boot_id")
			}
			count := 0
			setns := func(_ int, kind int) error {
				if kind != unix.CLONE_NEWCGROUP {
					t.Fatal("wrong namespace")
				}
				count++
				calls = append(calls, "setns")
				if count == 2 && restoreFailure {
					return errors.New("synthetic restore failure")
				}
				return nil
			}
			p, err := s.captureInNodeNamespace(context.Background(), r, open, setns)
			if count != 2 || len(calls) != 5 || calls[3] != "runtime-postcheck" || calls[4] != "setns" {
				t.Fatal("returned before source join and restore", calls)
			}
			if restoreFailure {
				if err == nil || p.Format != "" {
					t.Fatal("unrestored source escaped")
				}
			} else if err != nil || len(p.Processes) != 1 {
				t.Fatal(err)
			}
		})
	}
}
func TestProcessNamespaceCanceledBeforeEntryHasNoSideEffects(t *testing.T) {
	s, r, _ := syntheticProcesses(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := s.captureInNodeNamespace(ctx, r, func(string) (*os.File, error) { called = true; return nil, errors.New("unexpected") }, func(int, int) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("canceled request entered namespace")
	}
}
