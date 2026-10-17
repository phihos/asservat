package kubernetes

import (
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func TestConfigurationWorkerAutomaticRunRetainsOriginalUncertaintyAcrossReadFailure(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		r := configurationWorkerInputRun{}
		original := ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputSpent,
			Snapshot: contracts.InitialRuntimeResourceSnapshot{UID: ownerID(17220), ResourceVersion: "71"}, receiptUncertain: true}
		r.observed(original, cfg.ErrUnavailable)
		if !r.continueAfter(original, cfg.ErrUnavailable, true) {
			t.Fatal("first unknown receipt lost its one inspection")
		}
		var got ConfigurationWorkerInputAdvance
		if interrupted {
			got = r.interrupted()
		} else {
			got = r.observed(ConfigurationWorkerInputAdvance{}, cfg.ErrUnavailable)
		}
		if got.Progress != ConfigurationWorkerInputSpent || got.Snapshot.UID != original.Snapshot.UID || got.Snapshot.ResourceVersion != original.Snapshot.ResourceVersion || !got.receiptUncertain {
			t.Fatal("failed inspection erased original uncertain effect")
		}
		if r.continueAfter(got, cfg.ErrUnavailable, true) {
			t.Fatal("unavailable inspection admitted another effect or poll")
		}
	}
	r := configurationWorkerInputRun{}
	if r.interrupted().Progress != 0 {
		t.Fatal("pre-claim interruption invented an effect")
	}
	r.observed(ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputPending}, nil)
	if r.interrupted().Progress != ConfigurationWorkerInputSpent {
		t.Fatal("interruption returned old positive read as current")
	}
}

// Finite run disposition only. These synthetic phase results confer no native,
// SQL, provider or receipt authority; transport lost-reply tests are separate.
func TestConfigurationWorkerAutomaticRunKeepsUncertainReceiptInspectOnly(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "still pending", true: "exact committed receipt"}[committed], func(t *testing.T) {
			r := configurationWorkerInputRun{}
			if !r.continueAfter(ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputPending}, nil, true) || r.calls != 1 || r.receiptUncertain {
				t.Fatal("positive original CREATE did not select its one receipt phase")
			}
			if !r.continueAfter(ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputSpent, receiptUncertain: true}, cfg.ErrUnavailable, true) || !r.receiptUncertain || r.calls != 2 {
				t.Fatal("unknown receipt reply lost its exact inspection disposition")
			}
			progress := ConfigurationWorkerInputPending
			if committed {
				progress = ConfigurationWorkerInputAcknowledged
			}
			if r.continueAfter(ConfigurationWorkerInputAdvance{Progress: progress}, nil, true) || !r.receiptUncertain || r.calls != 3 {
				t.Fatal("same automatic run admitted another receipt write or poll")
			}
		})
	}
}

func TestConfigurationWorkerAutomaticRunHasNoUnboundedRecovery(t *testing.T) {
	r := configurationWorkerInputRun{}
	for i := 1; i <= 3; i++ {
		if got := r.continueAfter(ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputSpent, needsInspection: true}, cfg.ErrUnavailable, true); got != (i < 3) {
			t.Fatal("unknown original effect created an unbounded retry loop", i)
		}
	}
	for _, result := range []ConfigurationWorkerInputAdvance{{}, {Progress: ConfigurationWorkerInputSpent}, {Progress: ConfigurationWorkerInputPending}} {
		r = configurationWorkerInputRun{}
		if r.continueAfter(result, cfg.ErrUnavailable, false) {
			t.Fatal("expired original root admitted another phase")
		}
	}
	r = configurationWorkerInputRun{}
	if r.continueAfter(ConfigurationWorkerInputAdvance{}, cfg.ErrUnavailable, true) {
		t.Fatal("pre-claim failure was treated as a recoverable effect")
	}
	r = configurationWorkerInputRun{}
	if r.continueAfter(ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputSpent}, cfg.ErrUnavailable, true) {
		t.Fatal("known claim without admitted effect became generic retry")
	}
	r = configurationWorkerInputRun{}
	if !r.continueAfter(ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputSpent, receiptUncertain: true}, cfg.ErrUnavailable, true) {
		t.Fatal("preexisting pending claim lost its one current inspection")
	}
	if r.continueAfter(ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputSpent}, cfg.ErrUnavailable, true) {
		t.Fatal("absent or unavailable receipt read allowed another inspection")
	}
}
