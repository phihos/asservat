package kubernetes

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestProcessesLocalStartMatchesActualTypedAPIProducer(t *testing.T) {
	r := startRequest(time.Now().UTC().Truncate(time.Microsecond))
	b := r.Binding
	b.ExecutionClass = artifact.ContextAPIExecution
	b.ExecutorPodUID, b.ExecutorAccountUID = b.PodUID, b.PodUID
	b.NodeUID, b.NodeBootID = "", ""
	b.ActionID = "a000000000000000000000001"
	b.NativeType, b.NativeBytes = artifact.ProcessesArtifact, artifact.ProcessNativeLimit
	b.NotAfter = b.NotBefore.Add(5 * time.Second)
	for _, size := range []int64{1, 1048576, artifact.ProcessNativeLimit} {
		current := b
		current.NativeBytes = size
		s, err := LocalStartSpec(current)
		if !current.Valid() || err != nil || s.NativeType != artifact.ProcessesArtifact || s.NativeBytes != size || s.Profile != "apiContextStart/v1" || s.ExecutorPodUID != b.ExecutorPodUID || s.ExecutorAccountUID != b.ExecutorAccountUID {
			t.Fatal("actual typed process producer cannot reach local start", size, err)
		}
	}
	for name, mutate := range map[string]func(){
		"zero": func() { b.NativeBytes = 0 }, "overlimit": func() { b.NativeBytes = artifact.ProcessNativeLimit + 1 }, "node": func() { b.NodeUID = b.PodUID }, "boot": func() { b.NodeBootID = b.PodUID }, "executor": func() { b.ExecutorPodUID = "" }, "account": func() { b.ExecutorAccountUID = "" }, "deadline": func() { b.NotAfter = b.NotBefore.Add(5*time.Second + time.Microsecond) }, "action": func() { b.ActionID = "pod-status" },
	} {
		t.Run(name, func(t *testing.T) {
			original := b
			defer func() { b = original }()
			mutate()
			if b.Valid() {
				t.Fatal("process permit widened identity/limit/deadline")
			}
			if _, err := LocalStartSpec(b); err == nil {
				t.Fatal("invalid process start serialized")
			}
		})
	}
}
