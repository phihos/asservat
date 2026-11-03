package manifest

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSharedManifestValidatorConcurrentUse(t *testing.T) {
	original, e, l, c := profileExpectation(t, "cpu")
	started := e.TriggeredAt.Add(time.Second)
	var workers sync.WaitGroup
	failures := make(chan error, 32)
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			v, err := New()
			if err != nil || v != original {
				failures <- fmt.Errorf("embedded compilation not shared: %v", err)
				return
			}
			for range 16 {
				b, err := v.MarshalContext(e, l, c, started, started.Add(time.Second))
				if err != nil {
					failures <- err
					return
				}
				if _, err = v.ParseContext(b, e, c); err != nil {
					failures <- err
					return
				}
				bad := bytes.Replace(b, []byte(`"dataClass":"raw"`), []byte(`"dataClass":"metadata"`), 1)
				if bytes.Equal(b, bad) {
					failures <- fmt.Errorf("missing corruption target")
					return
				}
				if _, err = v.ParseContext(bad, e, c); err == nil {
					failures <- fmt.Errorf("shared validation accepted mutated profile")
					return
				}
			}
		}()
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}
