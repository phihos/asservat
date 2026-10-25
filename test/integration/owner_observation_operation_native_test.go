package integration

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	value "asservat.local/asservat/internal/domain/fleet"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// This is the actual native two-boundary primitive, not owner authentication or
// an installed observation route. The owned fixture supplies administrator pins
// and process identifiers. Current Pod/ReplicaSet/Deployment, endpoint and
// independent admission-denial checks all use the real API and original 20/20
// clients. No SQL, TLS owner leaf, background reconciler or result authority is
// supplied by this test.
func TestOwnerObservationOperationWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("owned context Kubernetes fixture required")
	}
	raw, err := os.ReadFile(path)
	var f fixture
	if err != nil || json.Unmarshal(raw, &f) != nil || len(f.Clusters) == 0 {
		t.Fatal("owned fixture unavailable")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	x := newOwnerObservationNativeCostFixture(t, ctx, f)
	observer, guard := x.readers(t)
	reader, err := kube.NewOwnerObservationOperationReader(observer, guard, x.pin)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := kubernetes.NewForConfig(x.config)
	if err != nil {
		t.Fatal(err)
	}
	binding := value.OwnerBinding{InstallationID: x.pool.InstallationID, ClusterID: x.pool.ClusterID, IssuerEpoch: x.pool.IssuerEpoch, PodUID: string(x.pod.UID), ProcessEpoch: custodyID()}
	begin := func(t *testing.T) (*kube.OwnerObservationOperation, context.Context, context.CancelFunc, time.Time) {
		t.Helper()
		now := time.Now().UTC()
		r := value.OwnerObservationRequest{RootID: x.pin.RootID, ID: custodyID(), Challenge: custodyID(), RequestedAt: now, NotAfter: now.Add(5 * time.Second)}
		call, stop := context.WithDeadline(ctx, r.NotAfter)
		op, err := reader.Begin(call, r, []value.OwnerBinding{binding})
		if err != nil {
			stop()
			t.Fatal("initial native boundary", err)
		}
		return op, call, stop, now
	}
	// Reuse exactly the same clients without sleeps or a new token bucket between
	// operations. Each request owns a distinct original five-second interval.
	for i := 0; i < 6; i++ {
		t.Run([]string{"cold", "consecutive-1", "consecutive-2", "consecutive-3", "consecutive-4", "consecutive-5"}[i], func(t *testing.T) {
			x.counter.arm()
			op, call, stop, started := begin(t)
			defer stop()
			defer op.Close()
			first, err := op.Original(call)
			if err != nil || first.Final {
				t.Fatal("original native facts", err)
			}
			before := x.counter.snapshot()
			original, err := op.Original(call)
			if err != nil || !reflect.DeepEqual(first, original) || x.counter.snapshot() != before {
				t.Fatal("original facts changed or performed another API read")
			}
			last, err := op.Final(call)
			if err != nil || !last.Final || !last.ObservedAt.Equal(first.ObservedAt) || last.FreshUntil.After(first.FreshUntil) || !reflect.DeepEqual(first.Peers, last.Peers) || call.Err() != nil || !time.Now().Before(last.FreshUntil) {
				t.Fatal("independent final native boundary", err)
			}
			counts := x.counter.snapshot()
			var reads, probes int64
			for _, n := range counts.Requests[0] {
				reads += n
			}
			for _, n := range counts.Requests[1] {
				probes += n
			}
			// Each of the two independent denial probes already permits at most
			// two exact resource-version conflicts. Every such retry adds one
			// actual observer GET and one failed probe PUT; nothing else retries.
			// Each boundary also reads the absent ADR-227 release record (404).
			retries := reads - 30
			if retries < 0 || retries > 4 || probes != 6+retries || counts.Requests[0][9] != 2 || counts.Requests[0][10] != 0 || counts.Requests[1][10] != 0 || counts.TransportFailures != 0 || counts.HTTPFailures != 4+retries {
				t.Fatal("unexpected real native graph", counts)
			}
			t.Logf("native primitive elapsed=%s remaining=%s observer=%d probe=%d expected-denials=%d", time.Since(started), time.Until(last.FreshUntil), reads, probes, counts.HTTPFailures)
			if _, err := op.Final(call); err == nil || x.counter.snapshot() != counts {
				t.Fatal("completed native operation replayed its final boundary")
			}
		})
	}
	t.Run("actual-pod-change-between-boundaries", func(t *testing.T) {
		x.counter.arm()
		op, call, stop, _ := begin(t)
		defer stop()
		defer op.Close()
		body := []byte(`{"metadata":{"annotations":{"asservat.io/synthetic-native-mutation":"changed"}}}`)
		if _, err := admin.CoreV1().Pods(x.pool.Namespace).Patch(call, x.pod.Name, types.MergePatchType, body, meta.PatchOptions{}); err != nil {
			t.Fatal("owned administrator mutation", err)
		}
		last, err := op.Final(call)
		if err == nil || last.Final || len(last.Peers) != 0 {
			t.Fatal("changed actual Pod released final facts")
		}
		counts := x.counter.snapshot()
		if _, err := op.Original(call); err == nil || x.counter.snapshot() != counts {
			t.Fatal("failed native operation was reusable")
		}
	})
}
