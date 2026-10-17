package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type bootstrapPassiveFixture struct {
	*bootstrapObserverFixture
	mu                                         sync.Mutex
	producer                                   *InitialBootstrap
	metadata                                   meta.PartialObjectMetadata
	history                                    *core.Secret
	seedFullReads, metadataReads, historyReads int
	metadataStatus                             int
	fullInstead                                bool
	changeFinal                                bool
	missingHistory                             bool
	rootExists                                 bool
	blockFinal                                 bool
	entered                                    chan struct{}
	allowBroad                                 bool
	createCalls                                int
	loseCreate                                 bool
	failLookup                                 int
	loseLocator                                bool
}

func newBootstrapPassiveFixture(t *testing.T, retired bool) *bootstrapPassiveFixture {
	return newBootstrapPassiveFixtureVersion(t, retired, contracts.InitialBootstrapPassiveFormat)
}
func newBootstrapPassiveFixtureVersion(t *testing.T, retired bool, format string) *bootstrapPassiveFixture {
	t.Helper()
	f := &bootstrapPassiveFixture{bootstrapObserverFixture: newBootstrapObserverFixtureVersion(t, context.Background(), format), entered: make(chan struct{}, 1)}
	state := cloneBootstrapState(t, f.state)
	state.PassiveHistory = &contracts.InitialBootstrapCreate{Step: "passive-history", OperationID: ownerID(81), Receipt: &contracts.InitialPreparationReceipt{UID: ownerID(82), ResourceVersion: "1"}}
	if retired {
		at := state.Manager.StartedAt
		state.Manager.Closing = &contracts.InitialBootstrapClose{OperationID: ownerID(83), StartedAt: at, Until: at.Add(30 * time.Second)}
		state.Manager.RetiredAt = &at
	}
	if !bootstrapStateValid(f.desired, state) {
		t.Fatal("invalid passive fixture state")
	}
	f.state = state
	n := bootstrapNames(f.desired)
	f.metadata = meta.PartialObjectMetadata{TypeMeta: meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: meta.ObjectMeta{Name: n.seed, Namespace: f.desired.BootstrapNamespace, UID: types.UID(state.SeedUID), ResourceVersion: "17", Annotations: bootstrapSeedAnnotations(f.desired, state)}}
	var err error
	f.history, err = bootstrapPassiveObject(f.desired, state, f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.history.UID = types.UID(state.PassiveHistory.Receipt.UID)
	f.history.ResourceVersion = "1"
	f.extra = func(w http.ResponseWriter, r *http.Request) bool {
		prefix := "/api/v1/namespaces/" + f.desired.BootstrapNamespace
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == http.MethodGet && r.URL.Path == prefix+"/secrets/"+n.seed {
			if r.Header.Get("Accept") != bootstrapPartialMetadataAccept {
				f.seedFullReads++
				if f.allowBroad {
					body, _ := json.Marshal(f.state)
					permissionReply(w, &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: f.metadata.ObjectMeta, Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": body}})
					return true
				}
				t.Error("broad seed requested by passive reader")
				http.Error(w, "forbidden", 403)
				return true
			}
			f.metadataReads++
			if f.metadataStatus != 0 {
				http.Error(w, "metadata negotiation unavailable", f.metadataStatus)
				return true
			}
			if f.fullInstead {
				permissionReply(w, core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: f.metadata.ObjectMeta, Data: map[string][]byte{"state.json": []byte("must never be accepted")}})
				return true
			}
			if f.blockFinal && f.metadataReads == 2 {
				f.entered <- struct{}{}
				<-r.Context().Done()
				return true
			}
			value := f.metadata.DeepCopy()
			if f.changeFinal && f.metadataReads == 2 {
				value.Annotations[initialBootstrapRetiredAnnotation] = time.Now().UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
			}
			permissionReply(w, value)
			return true
		}
		if r.Method == http.MethodGet && r.URL.Path == prefix+"/secrets/"+n.passiveHistory {
			f.historyReads++
			if f.failLookup > 0 {
				f.failLookup--
				http.Error(w, "unknown read result", 503)
				return true
			}
			if f.missingHistory || f.history == nil {
				bootstrapPassiveNotFound(w)
				return true
			}
			permissionReply(w, f.history)
			return true
		}
		if f.allowBroad && r.Method == http.MethodPut && r.URL.Path == prefix+"/secrets/"+n.seed {
			var incoming core.Secret
			if json.NewDecoder(r.Body).Decode(&incoming) != nil || incoming.UID != f.metadata.UID || incoming.ResourceVersion != f.metadata.ResourceVersion {
				http.Error(w, "conflict", 409)
				return true
			}
			var next contracts.InitialBootstrapState
			if json.Unmarshal(incoming.Data["state.json"], &next) != nil || !bootstrapStateTransition(f.desired, f.state, next) {
				http.Error(w, "invalid state transition", 422)
				return true
			}
			incoming.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}
			loseReply := f.loseLocator && f.metadata.Annotations[initialBootstrapPassiveAnnotation] == "" && incoming.Annotations[initialBootstrapPassiveAnnotation] != ""
			f.state = next
			rv, _ := strconv.Atoi(f.metadata.ResourceVersion)
			incoming.ResourceVersion = strconv.Itoa(rv + 1)
			f.metadata.ObjectMeta = incoming.ObjectMeta
			if loseReply {
				f.loseLocator = false
				http.Error(w, "committed locator reply lost", 503)
				return true
			}
			permissionReply(w, &incoming)
			return true
		}
		if f.allowBroad && r.Method == http.MethodPost && r.URL.Path == prefix+"/secrets" {
			var incoming core.Secret
			if json.NewDecoder(r.Body).Decode(&incoming) != nil || incoming.Name != n.passiveHistory || f.history != nil {
				http.Error(w, "unexpected create", 409)
				return true
			}
			f.createCalls++
			incoming.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}
			incoming.UID = types.UID(ownerID(82))
			incoming.ResourceVersion = "1"
			f.history = &incoming
			if f.loseCreate {
				f.failLookup = 1
				http.Error(w, "committed reply lost", 503)
				return true
			}
			permissionReply(w, &incoming)
			return true
		}
		if r.Method == http.MethodGet && (r.URL.Path == "/api/v1/namespaces/"+f.desired.TargetNamespace || r.URL.Path == prefix+"/configmaps/"+n.root) {
			if f.rootExists {
				permissionReply(w, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: f.desired.TargetNamespace, UID: types.UID(ownerID(99))}})
			} else {
				bootstrapPassiveNotFound(w)
			}
			return true
		}
		return false
	}
	f.producer, err = NewInitialBootstrap(context.Background(), f.apiConfig, f.desired)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.producer.Close)
	return f
}
func bootstrapPassiveNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonNotFound, Code: 404})
}
func TestInitialBootstrapPassiveReplayNeverReadsBroadSeed(t *testing.T) {
	for _, retired := range []bool{false, true} {
		t.Run(fmt.Sprintf("manager-retired-%t", retired), func(t *testing.T) {
			f := newBootstrapPassiveFixture(t, retired)
			ctx, end := context.WithTimeout(context.Background(), 4*time.Second)
			defer end()
			original, _ := ctx.Deadline()
			got, err := f.producer.ReadPassiveHistory(ctx)
			if err != nil || got == nil {
				t.Fatal("purpose-scoped replay unavailable", err)
			}
			if got.ManagerRetired != retired || got.ValidUntil.After(original) || !got.ValidUntil.After(time.Now()) {
				t.Fatal("historical disposition or original deadline changed")
			}
			if got.Bundle.History.Password != f.state.Passwords.History || got.Bundle.Seed.UID != f.state.SeedUID {
				t.Fatal("original history binding changed")
			}
			body, _ := json.Marshal(got.Bundle)
			for _, secret := range []string{f.state.Passwords.Manager, f.state.Passwords.Preparation, f.state.Passwords.Audit, f.state.Passwords.Activation, f.state.Material.IssuerToken, f.state.Material.Storage.SecretAccessKey} {
				if strings.Contains(string(body), secret) {
					t.Fatal("setup material disclosed by passive bundle")
				}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.seedFullReads != 0 || f.metadataReads != 2 || f.historyReads != 1 {
				t.Fatal("unexpected metadata/purpose-only read accounting", f.seedFullReads, f.metadataReads, f.historyReads)
			}
		})
	}
}
func TestInitialBootstrapPassiveMetadataCannotFallbackOrAdopt(t *testing.T) {
	cases := map[string]func(*bootstrapPassiveFixture){
		"legacy-seed-is-not-adopted": func(f *bootstrapPassiveFixture) {
			old := f.desired
			old.Format = contracts.InitialBootstrapFormat
			f.metadata.Annotations[initialBootstrapAnnotation] = bootstrapDigest(old)
		},
		"unsupported-negotiation": func(f *bootstrapPassiveFixture) { f.metadataStatus = 406 },
		"full-secret-response":    func(f *bootstrapPassiveFixture) { f.fullInstead = true },
		"missing-history":         func(f *bootstrapPassiveFixture) { f.missingHistory = true },
		"missing-locator-existing-root": func(f *bootstrapPassiveFixture) {
			delete(f.metadata.Annotations, initialBootstrapPassiveAnnotation)
			f.rootExists = true
		},
		"unknown-annotation": func(f *bootstrapPassiveFixture) { f.metadata.Annotations["unrecognized"] = "value" },
		"oversized-locator": func(f *bootstrapPassiveFixture) {
			f.metadata.Annotations[initialBootstrapPassiveAnnotation] = strings.Repeat("x", 2049)
		},
		"changed-history-uid":    func(f *bootstrapPassiveFixture) { f.history.UID = types.UID(ownerID(99)) },
		"changed-final-metadata": func(f *bootstrapPassiveFixture) { f.changeFinal = true },
		"wrong-original-seed":    func(f *bootstrapPassiveFixture) { f.producer.seedUID = ownerID(99) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBootstrapPassiveFixture(t, false)
			edit(f)
			if got, err := f.producer.ReadPassiveHistory(context.Background()); err == nil || got != nil {
				t.Fatal("invalid/unknown history permitted fallback")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.seedFullReads != 0 {
				t.Fatal("failure caused broad seed lookup")
			}
		})
	}
}
func TestInitialBootstrapPassiveMissingLocatorRequiresAbsentEffectRoots(t *testing.T) {
	f := newBootstrapPassiveFixture(t, false)
	delete(f.metadata.Annotations, initialBootstrapPassiveAnnotation)
	got, err := f.producer.ReadPassiveHistory(context.Background())
	if err != nil || got != nil || f.producer.seedUID != f.state.SeedUID {
		t.Fatal("exact incomplete pre-effect state unavailable", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.historyReads != 0 || f.seedFullReads != 0 {
		t.Fatal("absence inspection acquired private bytes")
	}
}
func TestInitialBootstrapPassiveFinalReadPreservesCancellation(t *testing.T) {
	f := newBootstrapPassiveFixture(t, false)
	f.blockFinal = true
	ctx, end := context.WithCancel(context.Background())
	defer end()
	done := make(chan error, 1)
	go func() { _, err := f.producer.ReadPassiveHistory(ctx); done <- err }()
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("final metadata check not reached")
	}
	end()
	if err := <-done; err == nil {
		t.Fatal("cancelled final metadata read delivered history")
	}
}
func TestInitialBootstrapPassiveReceiptCannotBeReplacedOrReset(t *testing.T) {
	d, old := bootstrapStateFixture(t)
	d.Format = contracts.InitialBootstrapPassiveFormat
	old.DesiredDigest = bootstrapDigest(d)
	pending := cloneBootstrapState(t, old)
	pending.PassiveHistory = &contracts.InitialBootstrapCreate{Step: "passive-history", OperationID: ownerID(81)}
	if !bootstrapStateTransition(d, old, pending) {
		t.Fatal("first fixed passive claim denied")
	}
	accepted := cloneBootstrapState(t, pending)
	accepted.PassiveHistory.Receipt = &contracts.InitialPreparationReceipt{UID: ownerID(82), ResourceVersion: "1"}
	if !bootstrapStateTransition(d, pending, accepted) {
		t.Fatal("original receipt denied")
	}
	for _, edit := range []func(*contracts.InitialBootstrapState){func(s *contracts.InitialBootstrapState) { s.PassiveHistory = nil }, func(s *contracts.InitialBootstrapState) { s.PassiveHistory.OperationID = ownerID(83) }, func(s *contracts.InitialBootstrapState) { s.PassiveHistory.Receipt.UID = ownerID(83) }, func(s *contracts.InitialBootstrapState) { s.PassiveHistory.Receipt.ResourceVersion = "2" }} {
		next := cloneBootstrapState(t, accepted)
		edit(&next)
		if bootstrapStateTransition(d, accepted, next) {
			t.Fatal("fixed passive receipt changed")
		}
	}
	legacy := d
	legacy.Format = contracts.InitialBootstrapFormat
	incompatible := cloneBootstrapState(t, accepted)
	incompatible.DesiredDigest = bootstrapDigest(legacy)
	if bootstrapStateValid(legacy, incompatible) {
		t.Fatal("new persisted capability accepted by historical profile")
	}
	for _, s := range []contracts.InitialBootstrapState{old, pending} {
		next := cloneBootstrapState(t, s)
		next.Manager.Closing = &contracts.InitialBootstrapClose{OperationID: ownerID(84), StartedAt: s.Manager.StartedAt, Until: s.Manager.StartedAt.Add(30 * time.Second)}
		if bootstrapStateTransition(d, s, next) {
			t.Fatal("closure before passive receipt permitted")
		}
	}
}

// The server commits the exact first create but loses both that reply and the
// immediate lookup. A new adapter must recover the same UID/operation without
// another POST. Synthetic API responses are not native SQL or guard authority.
func TestInitialBootstrapPassiveLostCreateRestartIsExactLookupOnly(t *testing.T) {
	f := newBootstrapPassiveFixture(t, false)
	f.allowBroad = true
	f.loseCreate = true
	f.state.PassiveHistory = nil
	f.metadata.Annotations = bootstrapSeedAnnotations(f.desired, f.state)
	f.history = nil
	if _, err := f.producer.Open(context.Background(), nil); err != nil {
		t.Fatal("original seed reopen", err)
	}
	if err := f.producer.PreparePassiveHistory(context.Background()); err == nil {
		t.Fatal("unknown create/lookup returned success")
	}
	f.mu.Lock()
	if f.createCalls != 1 || f.state.PassiveHistory == nil || f.state.PassiveHistory.Receipt != nil || f.history == nil {
		t.Fatal("unknown operation not retained")
	}
	want, buildErr := bootstrapPassiveObject(f.desired, f.state, f.config)
	if buildErr != nil || !bootstrapObjectMatches(want, f.history) {
		t.Fatal("persisted passive object mismatch", buildErr)
	}
	original := f.state.PassiveHistory.OperationID
	f.mu.Unlock()
	f.producer.Close()
	next, err := NewInitialBootstrap(context.Background(), f.apiConfig, f.desired)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, err = next.Open(context.Background(), nil); err != nil {
		t.Fatal("same seed could not reopen", err)
	}
	if err = next.PreparePassiveHistory(context.Background()); err != nil {
		t.Fatal("exact original receipt recovery", err)
	}
	f.mu.Lock()
	if f.createCalls != 1 || f.state.PassiveHistory.OperationID != original || f.state.PassiveHistory.Receipt == nil || f.state.PassiveHistory.Receipt.UID != string(f.history.UID) {
		t.Fatal("replay reissued or adopted another operation")
	}
	f.allowBroad = false
	f.mu.Unlock()
	if got, err := next.ReadPassiveHistory(context.Background()); err != nil || got == nil {
		t.Fatal("recovered purpose-only replay unavailable", err)
	}
}

func TestInitialBootstrapPassiveLostLocatorCASReopensWithoutBroadSeed(t *testing.T) {
	f := newBootstrapPassiveFixture(t, false)
	f.allowBroad = true
	f.loseLocator = true
	f.state.PassiveHistory = nil
	f.metadata.Annotations = bootstrapSeedAnnotations(f.desired, f.state)
	f.history = nil
	if _, err := f.producer.Open(context.Background(), nil); err != nil {
		t.Fatal("original seed reopen", err)
	}
	if err := f.producer.PreparePassiveHistory(context.Background()); err == nil {
		t.Fatal("lost final receipt reply returned success")
	}
	f.mu.Lock()
	if f.createCalls != 1 || f.state.PassiveHistory == nil || f.state.PassiveHistory.Receipt == nil || f.metadata.Annotations[initialBootstrapPassiveAnnotation] == "" {
		t.Fatal("final receipt was not committed with locator")
	}
	uid := f.state.PassiveHistory.Receipt.UID
	f.allowBroad = false
	f.seedFullReads = 0
	f.mu.Unlock()
	f.producer.Close()
	next, err := NewInitialBootstrap(context.Background(), f.apiConfig, f.desired)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	// There is deliberately no Open call here: a new command can classify
	// current history from the committed locator without acquiring seed data.
	got, err := next.ReadPassiveHistory(context.Background())
	if err != nil || got == nil || got.Bundle.Seed.UID != f.state.SeedUID {
		t.Fatal("lost locator CAS cannot recover passively", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seedFullReads != 0 || f.createCalls != 1 || uid != string(f.history.UID) {
		t.Fatal("locator recovery repeated creation or read broad seed")
	}
}

func TestInitialBootstrapPassiveNewCopyCannotOutliveOriginalSetup(t *testing.T) {
	f := newBootstrapPassiveFixture(t, false)
	f.allowBroad = true
	f.state.PassiveHistory = nil
	f.state.Manager.StartedAt = time.Now().UTC().Add(-31 * time.Minute).Truncate(time.Microsecond)
	f.state.Manager.Until = f.state.Manager.StartedAt.Add(30 * time.Minute)
	f.metadata.Annotations = bootstrapSeedAnnotations(f.desired, f.state)
	f.history = nil
	if _, err := f.producer.Open(context.Background(), nil); err != nil {
		t.Fatal("historical original seed", err)
	}
	if err := f.producer.PreparePassiveHistory(context.Background()); err == nil {
		t.Fatal("expired setup created another managed private copy")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createCalls != 0 || f.state.PassiveHistory != nil {
		t.Fatal("expired setup consumed a new create claim")
	}
}
