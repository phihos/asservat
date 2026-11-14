package integration

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
	batch "k8s.io/api/batch/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// This reproduces fixture scheduling only: the next paid result may arrive
// after normal product retirement removed the first Pod. It grants no SQL,
// Kubernetes or terminal authority, and never treats absence as live proof.
func TestInstalledProfileComparisonProofCapturesLiveBeforeDeferredTerminal(t *testing.T) {
	var cohort installedSyscallProofCohort
	var order []string
	for index := 0; index < 2; index++ {
		live := true
		handle, operation := fmt.Sprintf("query-%d", index), fmt.Sprintf("operation-%d", index)
		proof := &installedProfileComparisonProof{capture: func(h, o string) func() func() {
			if !live {
				t.Fatal("exact live Pod was retired before fixture evidence capture")
			}
			if h != handle || o != operation {
				t.Fatal("original failure locators changed")
			}
			order = append(order, "live-"+h)
			return func() func() {
				order = append(order, "terminal-"+h)
				return func() { order = append(order, "retirement-"+h) }
			}
		}}
		cohort.add(t, func() func() { return proof.join(handle, operation) })
		proof.observe(handle, operation)
		// Ordinary later demand can retire the worker; no serial terminal wait
		// should be required before allowing the next genuine query to start.
		live = false
	}
	beforeJoin := append([]string(nil), order...)
	cohort.flush(t)
	if !reflect.DeepEqual(beforeJoin, []string{"live-query-0", "live-query-1"}) {
		t.Fatal("terminal wait serialized live captures", beforeJoin)
	}
	if !reflect.DeepEqual(order, []string{"live-query-0", "live-query-1", "terminal-query-0", "terminal-query-1"}) || cohort.joined != 2 || cohort.retired != 0 {
		t.Fatal("joined terminal proof or retained final charges changed", order, cohort)
	}
}

func TestInstalledProfileComparisonProofFailureStillUsesKnownOriginalLocators(t *testing.T) {
	var cohort installedSyscallProofCohort
	var seen [2]string
	proof := &installedProfileComparisonProof{capture: func(h, o string) func() func() { seen = [2]string{h, o}; return func() func() { return func() {} } }}
	handle, operation := "", ""
	cohort.add(t, func() func() { return proof.join(handle, operation) })
	// A pending reply supplied its original locators before later result/UI
	// validation failed. Deferred cleanup must still attempt the known proof.
	handle, operation = "original-handle", "original-operation"
	cohort.flush(t)
	if seen != ([2]string{handle, operation}) || cohort.joined != 1 {
		t.Fatal("failure discarded original query locators", seen)
	}
}

// This is a synthetic post-terminal API/SQL-port check, not native retirement
// qualification. Absence needs positive proof even in the final cohort, where
// a later-demand callback may never run.
func TestInstalledProfileComparisonRetirementAfterTerminalRequiresStoredProof(t *testing.T) {
	for _, mode := range []string{"original-job", "missing-positive", "missing-unproved", "replacement-job"} {
		t.Run(mode, func(t *testing.T) {
			w := value.AcquisitionWorker{Intent: value.AcquisitionWorkerIntent{RunUntil: time.Now()}, Binding: value.AcquisitionWorkerBinding{Namespace: "workers", Job: "original", JobUID: "original-uid"}}
			var objects []runtime.Object
			if mode == "original-job" || mode == "replacement-job" {
				id := w.Binding.JobUID
				if mode == "replacement-job" {
					id = "replacement-uid"
				}
				objects = append(objects, &batch.Job{ObjectMeta: meta.ObjectMeta{Namespace: w.Binding.Namespace, Name: w.Binding.Job, UID: types.UID(id)}})
			}
			api := fake.NewClientset(objects...)
			reads := 0
			check := func(ctx context.Context) error {
				reads++
				until, ok := ctx.Deadline()
				if !ok || until.After(w.Intent.RunUntil.Add(30*time.Second)) || ctx.Err() != nil {
					t.Fatal("post-terminal proof extended original deadline")
				}
				if mode != "missing-positive" {
					return errors.New("no positive retirement")
				}
				return nil
			}
			err := installedProfileComparisonRetirementAfterTerminal(t.Context(), api, w, check)
			wantReads := 0
			if mode == "missing-positive" || mode == "missing-unproved" {
				wantReads = 1
			}
			wantError := mode == "missing-unproved" || mode == "replacement-job"
			if (err != nil) != wantError || reads != wantReads {
				t.Fatal("missing or replaced Job accepted without exact stored retirement", mode, err, reads)
			}
		})
	}
}
