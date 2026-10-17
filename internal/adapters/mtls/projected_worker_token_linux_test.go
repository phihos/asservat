//go:build linux

package mtls

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestProjectedWorkerTokenRejectsFIFOWithoutWaiting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := (projectedWorkerToken{path}).ReadDownloadPeerToken(context.Background())
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(200 * time.Millisecond):
		// Unblock the previous implementation before reporting the regression.
		f, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("blocked reader did not stop")
		}
		t.Fatal("credential open blocked on a FIFO before checking its type")
	}
}
