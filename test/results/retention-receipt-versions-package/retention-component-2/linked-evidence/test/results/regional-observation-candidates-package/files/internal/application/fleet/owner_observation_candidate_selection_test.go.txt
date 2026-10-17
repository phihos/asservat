package fleet

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

type observationSelectionSource struct {
	read func(context.Context, bool) (value.APIContextOwnerCandidates, error)
}

func (s observationSelectionSource) ReadContextStartOwners(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	return s.read(ctx, false)
}
func (s observationSelectionSource) ReadOwnerObservationCandidates(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	return s.read(ctx, true)
}

func observationSelectionPool() value.OwnerPool {
	const id = "11111111-1111-4111-8111-111111111111"
	return value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "owner", ServiceUID: id, Deployment: "owner", DeploymentUID: id, ServiceAccount: "owner", AccountUID: id, Port: 9443, NativePort: 9444, NativeBootstrap: value.OwnerBootstrapProfile}
}

func TestOwnerObservationCandidateSelectionKeepsOriginalProfileAndNeverFallsBack(t *testing.T) {
	for _, mode := range []string{"legacy", "opted", "legacy-error", "opted-error", "legacy-overflow", "opted-overflow", "changed-pool", "changed-limit", "cancelled", "cancel-during-read"} {
		t.Run(mode, func(t *testing.T) {
			pool := observationSelectionPool()
			opted := mode != "legacy" && mode != "legacy-error" && mode != "legacy-overflow"
			if opted {
				pool.NativeCandidateLimit = 17
			}
			now := time.Now()
			out := value.APIContextOwnerCandidates{Pool: pool, ObservedAt: now, ValidUntil: now.Add(500 * time.Millisecond)}
			count := 16
			if opted {
				count = 17
			}
			if mode == "legacy-overflow" || mode == "opted-overflow" {
				count++
			}
			for i := 1; i <= count; i++ {
				out.Owners = append(out.Owners, value.OwnerBinding{InstallationID: pool.InstallationID, ClusterID: pool.ClusterID, IssuerEpoch: pool.IssuerEpoch, PodUID: pool.AccountUID, ProcessEpoch: fmt.Sprintf("00000000-0000-4000-8000-%012d", i)})
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			original, _ := ctx.Deadline()
			legacy, installed := 0, 0
			selectedError := errors.New("selected source unavailable")
			source := observationSelectionSource{read: func(call context.Context, selected bool) (value.APIContextOwnerCandidates, error) {
				if selected {
					installed++
				} else {
					legacy++
				}
				if selected != opted {
					t.Fatal("original pool selected another reader")
				}
				if deadline, ok := call.Deadline(); !ok || !deadline.Equal(original) {
					t.Fatal("original caller deadline changed")
				}
				if mode == "legacy-error" || mode == "opted-error" {
					return value.APIContextOwnerCandidates{}, selectedError
				}
				v := out
				if mode == "changed-pool" {
					v.Pool.NamespaceUID = "22222222-2222-4222-8222-222222222222"
				}
				if mode == "changed-limit" {
					v.Pool.NativeCandidateLimit = 18
				}
				if mode == "cancel-during-read" {
					cancel()
				}
				return v, nil
			}}
			s, err := NewOwnerObservationCandidateSelection(pool, source)
			if err != nil || !s.BoundTo(pool) {
				t.Fatal("original selection", err)
			}
			changed := pool
			changed.NativeCandidateLimit++
			if s.BoundTo(changed) {
				t.Fatal("bound selection accepted another original limit")
			}
			if mode == "cancelled" {
				cancel()
			}
			got, err := s.ReadOwnerObservationCandidates(ctx)
			good := mode == "legacy" || mode == "opted"
			if (err == nil) != good {
				t.Fatal("selected source result", err)
			}
			if mode == "legacy-error" || mode == "opted-error" {
				if !errors.Is(err, selectedError) {
					t.Fatal("selected error was replaced by fallback")
				}
			}
			want := 1
			if mode == "cancelled" {
				want = 0
			}
			if legacy+installed != want || opted && legacy != 0 || !opted && installed != 0 {
				t.Fatal("unselected source called", legacy, installed)
			}
			if good {
				if !got.Valid(now) || !got.ObservedAt.Equal(out.ObservedAt) || !got.ValidUntil.Equal(out.ValidUntil) || len(got.Owners) != count {
					t.Fatal("source interval or complete original population changed")
				}
				got.Owners[0].ProcessEpoch = "22222222-2222-4222-8222-222222222222"
				second, err := s.ReadOwnerObservationCandidates(ctx)
				if err != nil || second.Owners[0] == got.Owners[0] || legacy+installed != 2 {
					t.Fatal("cached observation or retained caller slice", err)
				}
			}
		})
	}
}

func TestOwnerObservationCandidateSelectionRequiresTypedSourceAndOriginalPool(t *testing.T) {
	p := observationSelectionPool()
	if _, err := NewOwnerObservationCandidateSelection(p, nil); err == nil {
		t.Fatal("missing source accepted")
	}
	p.NativeCandidateLimit = value.OwnerRegistrationsPerPool + 1
	if _, err := NewOwnerObservationCandidateSelection(p, observationSelectionSource{}); err == nil {
		t.Fatal("invalid original bound accepted")
	}
	var empty *OwnerObservationCandidateSelection
	if empty.BoundTo(observationSelectionPool()) {
		t.Fatal("missing selection accepted")
	}
	if _, err := empty.ReadOwnerObservationCandidates(context.Background()); err == nil {
		t.Fatal("missing selection read")
	}
}
