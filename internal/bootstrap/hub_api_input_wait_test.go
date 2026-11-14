package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A first install starts hub-api before the hub-worker writes the capacity
// qualification: the loader waits in process instead of exiting.
func TestHubAPIInputsWaitForCapacityQualification(t *testing.T) {
	first, max := startupWaitFirst, startupWaitMax
	startupWaitFirst, startupWaitMax = time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() { startupWaitFirst, startupWaitMax = first, max })
	var out bytes.Buffer
	calls := 0
	want := &ownerInputs{}
	got, err := waitHubAPIInputs(context.Background(), &out, func(context.Context) (*ownerInputs, error) {
		calls++
		switch calls {
		case 1, 2:
			return nil, hubAPIInputError("capacity-qualification")
		case 3:
			return nil, hubAPIInputError("worker-roots")
		}
		return want, nil
	})
	if err != nil || got != want || calls != 4 {
		t.Fatalf("got %v %v after %d calls", got, err, calls)
	}
	log := out.String()
	if strings.Count(log, "waiting for input-capacity-qualification") != 1 || !strings.Contains(log, "waiting for input-worker-roots") || !strings.Contains(log, "ok after 3 failed attempts") {
		t.Fatalf("log %q", log)
	}
}

func TestHubAPIInputsInvalidConfigurationStaysFatal(t *testing.T) {
	for _, err := range []error{hubAPIInputError("config"), hubAPIInputError("capture-policy"), hubAPIInputError("ca-x"), errors.New("other")} {
		calls := 0
		_, got := waitHubAPIInputs(context.Background(), &bytes.Buffer{}, func(context.Context) (*ownerInputs, error) {
			calls++
			return nil, err
		})
		if got != err || calls != 1 {
			t.Fatalf("%v: got %v after %d calls", err, got, calls)
		}
	}
}

func TestHubAPIInputsWaitEndsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, err := waitHubAPIInputs(ctx, &bytes.Buffer{}, func(context.Context) (*ownerInputs, error) {
		if calls++; calls == 2 {
			cancel()
		}
		return nil, hubAPIInputError("browser-settings-uid")
	})
	if !errors.Is(err, hubAPIInputError("browser-settings-uid")) || calls != 2 {
		t.Fatalf("got %v after %d calls", err, calls)
	}
}
