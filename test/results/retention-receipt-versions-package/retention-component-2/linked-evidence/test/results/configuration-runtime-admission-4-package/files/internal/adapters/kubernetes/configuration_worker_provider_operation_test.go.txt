package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func configurationProviderRuntimePair(ctx context.Context, f *configurationProviderRuntimeFixture) error {
	op, err := f.reader.BeginConfigurationProviderOperation(ctx, f.manifest.Roles[0].Claim.Sources.IssuerEpoch, f.manifest, f.mounted)
	if err != nil {
		return err
	}
	defer op.Close()
	_, err = f.reader.FinishConfigurationProviderOperation(ctx, op)
	return err
}

func TestConfigurationProviderRuntimeSharedLimiterFitsOriginalBound(t *testing.T) {
	f := newConfigurationProviderRuntimeFixture(t)
	// No refill sleeps or new clients between the three complete operations.
	// Start with both real production-sized buckets drained. The test does not
	// include SQL/provider latency and cannot qualify complete installed startup.
	for f.observerLimiter.TryAccept() {
	}
	for f.probeLimiter.TryAccept() {
	}
	for i := 0; i < 3; i++ {
		beforeS, beforeP := f.observer.Load(), f.probe.Load()
		call, end := context.WithTimeout(t.Context(), 5*time.Second)
		started := time.Now()
		err := configurationProviderRuntimePair(call, f)
		end()
		if err != nil {
			t.Fatalf("pair%d failed original bound after%s observer%d probe%d: %v", i, time.Since(started), f.observer.Load()-beforeS, f.probe.Load()-beforeP, err)
		}
		if f.observer.Load()-beforeS != 40 || f.probe.Load()-beforeP != 9 {
			t.Fatal("native count changed", f.observer.Load()-beforeS, f.probe.Load()-beforeP)
		}
	}
	for _, n := range []int{0, 1, 2} {
		if f.denials[n].Load() != 3 {
			t.Fatal("a genuine initial denial was omitted or repeated", n)
		}
	}
}

func TestConfigurationProviderRuntimeFinalRejectsCurrentMutation(t *testing.T) {
	for _, mode := range []string{"source", "source during final guard", "account", "Pod", "ReplicaSet", "worker input", "journal", "SQL material", "audit material", "guard"} {
		t.Run(mode, func(t *testing.T) {
			f := newConfigurationProviderRuntimeFixture(t)
			call, end := context.WithTimeout(t.Context(), 5*time.Second)
			defer end()
			op, err := f.reader.BeginConfigurationProviderOperation(call, f.manifest.Roles[0].Claim.Sources.IssuerEpoch, f.manifest, f.mounted)
			if err != nil {
				t.Fatal("initial", err)
			}
			defer op.Close()
			base := "/api/v1/namespaces/" + f.input.Namespace.Name
			changeSource := func() {
				obj := f.objects[base+"/configmaps/"+f.input.OwnerSource.Name].(*core.ConfigMap)
				var value contracts.OwnerConfiguration
				if json.Unmarshal([]byte(obj.Data["owner-pool.json"]), &value) != nil {
					t.Fatal("fixture source")
				}
				value.Revision++
				raw, _ := json.Marshal(value)
				obj.Data["owner-pool.json"] = string(raw)
				obj.ResourceVersion = "changed"
			}
			f.mu.Lock()
			switch mode {
			case "source":
				changeSource()
			case "source during final guard":
				var reads atomic.Int32
				f.extra = func(_ http.ResponseWriter, r *http.Request) bool {
					if strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicybindings/"+f.input.OwnerGuard.Name) && reads.Add(1) == 1 {
						f.mu.Lock()
						changeSource()
						f.mu.Unlock()
					}
					return false
				}
			case "account":
				f.fault.Store(1)
			case "Pod":
				for _, object := range f.objects {
					if pod, ok := object.(*core.Pod); ok {
						pod.Spec.Containers[0].Command = []string{"changed"}
					}
				}
			case "ReplicaSet":
				for _, object := range f.objects {
					if rs, ok := object.(*apps.ReplicaSet); ok {
						rs.OwnerReferences[0].UID = types.UID(ownerID(18999))
					}
				}
			case "worker input":
				obj := f.objects[base+"/configmaps/"+runtimeResourceNames(f.input.InstallationID).WorkerInputs].(*core.ConfigMap)
				delete(obj.Data, "deployment.json")
			case "journal":
				obj := f.objects[base+"/secrets/"+f.input.Activation.Resources.Name].(*core.Secret)
				obj.UID = types.UID(ownerID(18999))
			case "SQL material":
				obj := f.objects[base+"/secrets/"+f.input.ProviderInputs.SQLProjection.Name].(*core.Secret)
				obj.Data["sql-fleet.json"] = []byte(`{"username":"changed","password":"changed"}`)
			case "audit material":
				obj := f.objects[base+"/secrets/"+f.input.ProviderAuthentication.AuditCredentials.Name].(*core.Secret)
				obj.Data[contracts.ConfigurationProviderAuditCredentialFile] = []byte(`{"accessKeyID":"changed","secretAccessKey":"changed"}`)
			case "guard":
				path := "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/" + f.input.OwnerGuard.Name
				obj := f.objects[path].(meta.Object)
				obj.SetResourceVersion("changed")
			}
			f.mu.Unlock()
			if _, err = f.reader.FinishConfigurationProviderOperation(call, op); err == nil {
				t.Fatal("final adopted changed current input", mode)
			}
			requests := f.observer.Load() + f.probe.Load()
			if _, err = f.reader.FinishConfigurationProviderOperation(call, op); err == nil || f.observer.Load()+f.probe.Load() != requests {
				t.Fatal("failed final observation retried")
			}
		})
	}
}

func TestConfigurationProviderRuntimeCopyAndForeignReaderDoNotConsumeOriginal(t *testing.T) {
	f := newConfigurationProviderRuntimeFixture(t)
	call, end := context.WithTimeout(t.Context(), 5*time.Second)
	defer end()
	op, err := f.reader.BeginConfigurationProviderOperation(call, f.manifest.Roles[0].Claim.Sources.IssuerEpoch, f.manifest, f.mounted)
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	// Reflect performs an actual by-value copy without teaching vet that
	// application code should copy a mutex-bearing opaque handle.
	var copy ConfigurationWorkerProviderOperation
	reflect.ValueOf(&copy).Elem().Set(reflect.ValueOf(op).Elem())
	copy.Close()
	if _, err = f.reader.FinishConfigurationProviderOperation(call, &copy); err == nil {
		t.Fatal("copied operation consumed phase")
	}
	other := *f.reader
	if _, err = other.FinishConfigurationProviderOperation(call, op); err == nil {
		t.Fatal("foreign reader consumed phase")
	}
	if _, err = f.reader.FinishConfigurationProviderOperation(call, op); err != nil {
		t.Fatal("rejected copies poisoned original", err)
	}
	if _, err = f.reader.FinishConfigurationProviderOperation(call, op); err == nil {
		t.Fatal("successful final phase replayed")
	}
}

func TestConfigurationProviderRuntimeOwnsMaterial(t *testing.T) {
	f := newConfigurationProviderRuntimeFixture(t)
	call, end := context.WithTimeout(t.Context(), 5*time.Second)
	defer end()
	op, err := f.reader.BeginConfigurationProviderOperation(call, f.manifest.Roles[0].Claim.Sources.IssuerEpoch, f.manifest, f.mounted)
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	// Caller mutation cannot change the already cloned original material.
	f.mounted["sql-fleet.json"][0] = '!'
	f.manifest.RootUID = ownerID(18999)
	if _, err = f.reader.FinishConfigurationProviderOperation(call, op); err != nil {
		t.Fatal("caller mutation changed owned original material", err)
	}
}

func TestConfigurationProviderRuntimeKeepsEarlierEnd(t *testing.T) {
	f := newConfigurationProviderRuntimeFixture(t)
	call, end := context.WithTimeout(t.Context(), 5*time.Second)
	defer end()
	op, err := f.reader.BeginConfigurationProviderOperation(call, f.manifest.Roles[0].Claim.Sources.IssuerEpoch, f.manifest, f.mounted)
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	short, stop := context.WithTimeout(call, 40*time.Millisecond)
	defer stop()
	// The preceding native bracket depleted the shared observer bucket. The
	// shorter caller may expire in the real limiter before any HTTP handler is
	// entered. That is a valid denial, not evidence that a handler renewed time.
	original, _ := short.Deadline()
	if _, err = f.reader.FinishConfigurationProviderOperation(short, op); err == nil {
		t.Fatal("short original child was accepted past its available interval")
	}
	if got := op.FreshUntil(); !got.IsZero() && !got.Equal(original) {
		t.Fatal("shorter admitted caller deadline was not retained", got, original)
	}
	if !op.FreshUntil().Before(time.Now().Add(time.Second)) {
		t.Fatal("earliest child bound forgotten")
	}
	requests := f.observer.Load() + f.probe.Load()
	if _, err = f.reader.FinishConfigurationProviderOperation(call, op); err == nil || requests != f.observer.Load()+f.probe.Load() {
		t.Fatal("later parent reopened original phase")
	}
}

func TestConfigurationProviderRuntimeCloseJoinsAdmittedRead(t *testing.T) {
	f := newConfigurationProviderRuntimeFixture(t)
	call, end := context.WithTimeout(t.Context(), 5*time.Second)
	defer end()
	op, err := f.reader.BeginConfigurationProviderOperation(call, f.manifest.Roles[0].Claim.Sources.IssuerEpoch, f.manifest, f.mounted)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var blocked atomic.Bool
	f.setExtra(func(_ http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/validatingadmissionpolicies/") && blocked.CompareAndSwap(false, true) {
			close(entered)
			<-release
			return true
		}
		return false
	})
	done := make(chan error, 1)
	go func() { _, e := f.reader.FinishConfigurationProviderOperation(call, op); done <- e }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("read not entered")
	}
	closed := make(chan struct{})
	go func() { op.Close(); close(closed) }()
	// Client cancellation joins its native HTTP owner; server-handler lifetime
	// is separately released below and never claimed owned by the caller.
	select {
	case <-closed:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("local native cancellation did not join")
	}
	close(release)
	if err = <-done; !errors.Is(err, cfg.ErrUnavailable) {
		t.Fatal("closed phase returned success", err)
	}
	if !op.FreshUntil().IsZero() || op.mounted != nil {
		t.Fatal("closed ownership retained usable material")
	}
}

// ADR148 supplies bounded independent-enforcement freshness, not instantaneous
// detection of changed enforcement between otherwise identical API values.
func TestConfigurationProviderRuntimeDenialBelongsOnlyToOriginalOperation(t *testing.T) {
	f := newConfigurationProviderRuntimeFixture(t)
	call, end := context.WithTimeout(t.Context(), 5*time.Second)
	defer end()
	op, err := f.reader.BeginConfigurationProviderOperation(call, f.manifest.Roles[0].Claim.Sources.IssuerEpoch, f.manifest, f.mounted)
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	f.fault.Store(2)
	if _, err = f.reader.FinishConfigurationProviderOperation(call, op); err != nil {
		t.Fatal("original denial interval was not retained", err)
	}
	for i := range f.denials {
		if f.denials[i].Load() != 1 {
			t.Fatal("final repeated denial", i)
		}
	}
	next, err := f.reader.BeginConfigurationProviderOperation(call, f.manifest.Roles[0].Claim.Sources.IssuerEpoch, f.manifest, f.mounted)
	if next != nil {
		next.Close()
	}
	if err == nil {
		t.Fatal("another operation reused original denial")
	}
}

func TestConfigurationProviderRuntimeRotatedTokenDoesNotAdoptSameClient(t *testing.T) {
	for _, name := range []string{"observer", "probe"} {
		t.Run(name, func(t *testing.T) {
			f := newConfigurationProviderRuntimeFixture(t)
			call, end := context.WithTimeout(t.Context(), 5*time.Second)
			defer end()
			op, err := f.reader.BeginConfigurationProviderOperation(call, f.manifest.Roles[0].Claim.Sources.IssuerEpoch, f.manifest, f.mounted)
			if err != nil {
				t.Fatal(err)
			}
			defer op.Close()
			if err = os.WriteFile(filepath.Join(f.tokenDirectory, "kube-"+name+".token"), []byte(name+"-rotated"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = f.reader.FinishConfigurationProviderOperation(call, op); err == nil {
				t.Fatal("same client pointer adopted another projected token")
			}
			count := f.observer.Load() + f.probe.Load()
			if err = os.WriteFile(filepath.Join(f.tokenDirectory, "kube-"+name+".token"), []byte(name), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = f.reader.FinishConfigurationProviderOperation(call, op); err == nil || count != f.observer.Load()+f.probe.Load() {
				t.Fatal("restored bytes reopened failed operation")
			}
		})
	}
}

func TestConfigurationProviderRuntimeInitialProbeStillRequiresOriginalAccount(t *testing.T) {
	f := newConfigurationProviderRuntimeFixture(t)
	f.fault.Store(3)
	op, err := f.reader.BeginConfigurationProviderOperation(t.Context(), f.manifest.Roles[0].Claim.Sources.IssuerEpoch, f.manifest, f.mounted)
	if op != nil {
		op.Close()
	}
	if err == nil {
		t.Fatal("initial probe used another account")
	}
}
