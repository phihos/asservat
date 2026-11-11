package bootstrap

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

type smallKeycloakFakeState struct {
	retained                      *core.Secret
	reads, creates, databaseReads int
	databaseExists                bool
	unknown, mismatch             bool
	onRead                        func(context.Context)
}

func (s *smallKeycloakFakeState) Read(ctx context.Context) (*core.Secret, error) {
	s.reads++
	if s.onRead != nil {
		s.onRead(ctx)
	}
	if s.retained == nil {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "state")
	}
	return s.retained.DeepCopy(), nil
}
func (s *smallKeycloakFakeState) Create(ctx context.Context, v *core.Secret) (*core.Secret, error) {
	s.creates++
	s.retained = v.DeepCopy()
	s.retained.UID = types.UID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	s.retained.ResourceVersion = "1"
	if s.mismatch {
		s.retained.Data[contracts.SmallKeycloakAdminPassword] = []byte(strings.Repeat("A", 43))
	}
	if s.unknown {
		return nil, errors.New("unknown reply")
	}
	return s.retained.DeepCopy(), nil
}
func (s *smallKeycloakFakeState) DatabaseStateExists(context.Context) (bool, error) {
	s.databaseReads++
	return s.databaseExists, nil
}

func TestSmallKeycloakStateCreateExactUnknownReadbackAndReplay(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "acknowledged", true: "unknown"}[unknown], func(t *testing.T) {
			store := &smallKeycloakFakeState{unknown: unknown}
			settings := smallKeycloakTestSettings()
			settings.MCPRedirectURIs = []string{}
			prepare, err := NewSmallKeycloakPreparation(store, settings)
			if err != nil {
				t.Fatal(err)
			}
			first, err := prepare.Prepare(t.Context())
			if err != nil || first.UID == "" {
				t.Fatal("initial preparation", err)
			}
			original := store.retained.DeepCopy()
			second, err := prepare.Prepare(t.Context())
			if err != nil || second != first {
				t.Fatal("replay changed original Secret", err)
			}
			if store.creates != 1 || store.databaseReads != 1 || store.reads != 2+map[bool]int{false: 0, true: 1}[unknown] {
				t.Fatalf("unexpected API effects reads=%d creates=%d database=%d", store.reads, store.creates, store.databaseReads)
			}
			for key, value := range original.Data {
				if string(value) != string(store.retained.Data[key]) {
					t.Fatal("replay modified retained private material")
				}
			}
		})
	}
	store := &smallKeycloakFakeState{unknown: true, mismatch: true}
	prepare, _ := NewSmallKeycloakPreparation(store, smallKeycloakTestSettings())
	if _, err := prepare.Prepare(t.Context()); err == nil || store.creates != 1 || store.reads != 2 {
		t.Fatal("unknown reply adopted mismatched private bytes or repeated CREATE")
	}
}

func TestSmallKeycloakStateLostMaterialOverRetainedDatabaseRefuses(t *testing.T) {
	store := &smallKeycloakFakeState{databaseExists: true}
	prepare, _ := NewSmallKeycloakPreparation(store, smallKeycloakTestSettings())
	if _, err := prepare.Prepare(t.Context()); err == nil || store.creates != 0 || store.databaseReads != 1 {
		t.Fatal("regenerated identity keys over retained database")
	}
}

func TestSmallKeycloakStateRejectsForeignOrChangedRetainedObjects(t *testing.T) {
	settings := smallKeycloakTestSettings()
	valid, err := BuildSmallKeycloakMaterial(settings, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid.UID = types.UID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	valid.ResourceVersion = "1"
	for _, tc := range []struct {
		name   string
		change func(*core.Secret)
	}{
		{"foreign role", func(s *core.Secret) { s.Labels["asservat.io/private-role"] = "other" }},
		{"owned child", func(s *core.Secret) {
			s.OwnerReferences = []meta.OwnerReference{{Name: "other", UID: types.UID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")}}
		}},
		{"finalizer", func(s *core.Secret) { s.Finalizers = []string{"foreign"} }},
		{"missing UID", func(s *core.Secret) { s.UID = "" }},
		{"mutable", func(s *core.Secret) { v := false; s.Immutable = &v }},
		{"unknown material", func(s *core.Secret) { s.Data["foreign"] = []byte("private") }},
		{"changed group", func(s *core.Secret) {
			s.Data[contracts.SmallKeycloakUsersGroup] = []byte("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			retained := valid.DeepCopy()
			tc.change(retained)
			store := &smallKeycloakFakeState{retained: retained}
			prepare, _ := NewSmallKeycloakPreparation(store, settings)
			if _, err := prepare.Prepare(t.Context()); err == nil || store.creates != 0 || store.databaseReads != 0 {
				t.Fatal("adopted foreign state or tried replacement")
			}
		})
	}
}

func TestSmallKeycloakStateKeepsOriginalDeadlineAndCancellation(t *testing.T) {
	ctx, end := context.WithTimeout(t.Context(), time.Second)
	defer end()
	deadline, _ := ctx.Deadline()
	store := &smallKeycloakFakeState{}
	store.onRead = func(observed context.Context) {
		got, ok := observed.Deadline()
		if !ok || !got.Equal(deadline) {
			t.Error("preparation extended original parent deadline")
		}
		end()
	}
	prepare, _ := NewSmallKeycloakPreparation(store, smallKeycloakTestSettings())
	if _, err := prepare.Prepare(ctx); err == nil || store.creates != 0 || store.databaseReads != 0 {
		t.Fatal("cancelled read triggered another operation")
	}
	if _, err := prepare.Prepare(ctx); err == nil || store.reads != 1 {
		t.Fatal("cancelled caller performed another API read")
	}
}
