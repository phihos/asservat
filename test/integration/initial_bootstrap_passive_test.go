package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// This native API case deliberately supplies a synthetic SQL manager receipt
// solely to reach the bootstrap projection. It makes no SQL/provider call and
// proves no installation activation or manager retirement. Those require the
// independent real-service and original-Pod handover cases.
func TestInitialBootstrapPassiveWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run owned context-integration fixture")
	}
	var f fixture
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &f) != nil || len(f.Clusters) == 0 {
		t.Fatal("owned fixture unavailable")
	}
	ctx, end := context.WithTimeout(context.Background(), 120*time.Second)
	defer end()
	kc, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	api, err := kubernetes.NewForConfig(kc)
	if err != nil {
		t.Fatal(err)
	}
	who, err := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	nsName := "bootstrap-passive-" + custodyID()[:8]
	desired := initialBootstrapGuardDesired(t, kc, nsName, who.Status.UserInfo.Username)
	desired.Format = contracts.InitialBootstrapPassiveFormat
	ns, err := api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: nsName, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	guard := nsName + "-" + desired.Name + "-bootstrap"
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 40*time.Second)
		defer stop()
		// All names derive from this test's random namespace and fixed plan. Read
		// current UIDs before exact deletion; remove guards before namespace GC.
		owned := []string{guard, nsName + "-" + desired.Name + "-continuity", desired.TargetNamespace + "-" + desired.Name + "-staging"}
		for _, name := range owned {
			binding, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(clean, name, meta.GetOptions{})
			if e == nil {
				e = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(clean, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &binding.UID}})
			}
			if e != nil && !apierrors.IsNotFound(e) {
				t.Error("owned binding cleanup", e)
			}
			policy, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(clean, name, meta.GetOptions{})
			if e == nil {
				e = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(clean, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &policy.UID}})
			}
			if e != nil && !apierrors.IsNotFound(e) {
				t.Error("owned policy cleanup", e)
			}
		}
		for {
			e := api.CoreV1().Namespaces().Delete(clean, nsName, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &ns.UID}})
			if e == nil || apierrors.IsNotFound(e) {
				break
			}
			// The API server's admission cache can briefly keep any just-deleted
			// owned policy, not only the bootstrap guard.
			if !initialBootstrapGuardDenial(e, guard) && !ownedPolicyDenial(e, owned) || clean.Err() != nil {
				t.Error("owned namespace deletion", e)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		for clean.Err() == nil {
			_, e := api.CoreV1().Namespaces().Get(clean, nsName, meta.GetOptions{})
			if apierrors.IsNotFound(e) {
				return
			}
			if e != nil {
				t.Error(e)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Error("owned namespace cleanup did not join")
	})
	trace := &initialBootstrapPassiveTrace{seed: desired.Name + "-bootstrap-state", history: desired.Name + "-passive-history"}
	observedConfig := rest.CopyConfig(kc)
	prior := observedConfig.WrapTransport
	observedConfig.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		if prior != nil {
			next = prior(next)
		}
		trace.mu.Lock()
		trace.next = next
		trace.mu.Unlock()
		return trace
	}
	producer, err := kube.NewInitialBootstrap(ctx, observedConfig, desired)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { producer.Close() }()
	material := &contracts.InitialBootstrapMaterial{Format: contracts.InitialBootstrapMaterialFormat, IssuerToken: "synthetic-unused-issuer", Storage: contracts.OwnerStorageCredential{AccessKeyID: "synthetic-unused-access", SecretAccessKey: "synthetic-unused-secret"}, StorageUseUntil: time.Now().UTC().Add(time.Hour)}
	var state contracts.InitialBootstrapState
	for {
		state, err = producer.Open(ctx, material)
		if !errors.Is(err, kube.ErrInitialPreparationPolicyPending) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("original guard pending", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err != nil {
		t.Fatal("actual protected seed", err)
	}
	claim, err := producer.ClaimManager(ctx, 4242, time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond))
	if err != nil {
		t.Fatal("synthetic SQL-provenance claim", err)
	}
	manager := contracts.InitialSQLHistoryManager{Name: "asservat_init_" + strings.ReplaceAll(state.InstallationID, "-", "") + "_manager", OID: 4243}
	if err = producer.CompleteManager(ctx, claim, manager); err != nil {
		t.Fatal("synthetic SQL-provenance receipt", err)
	}
	for {
		_, ready, e := producer.PrepareProjection(ctx)
		if errors.Is(e, kube.ErrInitialPreparationPolicyPending) {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		if e != nil {
			t.Fatal("protected original projection", e)
		}
		if ready {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
	}
	trace.mu.Lock()
	trace.armed = true
	trace.mu.Unlock()
	if err = producer.PreparePassiveHistory(ctx); err == nil {
		t.Fatal("lost actual create and lookup replies returned success")
	}
	saved, err := api.CoreV1().Secrets(nsName).Get(ctx, trace.history, meta.GetOptions{})
	if err != nil {
		t.Fatal("actual committed history Secret missing", err)
	}
	producer.Close()
	producer, err = kube.NewInitialBootstrap(ctx, observedConfig, desired)
	if err != nil {
		t.Fatal(err)
	}
	if value, e := producer.ReadPassiveHistory(ctx); e != nil || value != nil {
		t.Fatal("unknown pre-effect locator gained authority", e)
	}
	if _, err = producer.Open(ctx, nil); err != nil {
		t.Fatal("original restart seed", err)
	}
	if err = producer.PreparePassiveHistory(ctx); err != nil {
		t.Fatal("exact post-restart lookup", err)
	}
	trace.mu.Lock()
	trace.metadataOnly = true
	posts := trace.posts
	trace.mu.Unlock()
	if posts != 1 {
		t.Fatal("history create was replayed", posts)
	}
	for i := 0; i < 2; i++ {
		value, e := producer.ReadPassiveHistory(ctx)
		if e != nil || value == nil || value.ManagerRetired || value.Bundle.Seed.UID != state.SeedUID {
			t.Fatal("native history-only original replay", e)
		}
	}
	trace.mu.Lock()
	badFull := trace.forbiddenFull
	trace.mu.Unlock()
	if badFull != 0 {
		t.Fatal("passive replay requested broad Secret data", badFull)
	}
	current, err := api.CoreV1().Secrets(nsName).Get(ctx, trace.seed, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	const locator = "asservat.io/bootstrap-passive-history"
	original := current.Annotations[locator]
	if original == "" {
		t.Fatal("original receipt locator absent")
	}
	t.Run("locator-replacement-and-removal-denied", func(t *testing.T) {
		for _, remove := range []bool{false, true} {
			next := current.DeepCopy()
			if remove {
				delete(next.Annotations, locator)
			} else {
				next.Annotations[locator] = original + " "
			}
			_, e := api.CoreV1().Secrets(nsName).Update(ctx, next, meta.UpdateOptions{})
			if !initialBootstrapGuardDenial(e, guard) {
				t.Fatal("native locator mutation not denied by exact guard", e)
			}
		}
	})
	t.Run("history-update-and-delete-denied", func(t *testing.T) {
		next := saved.DeepCopy()
		next.Annotations["unexpected"] = "value"
		_, e := api.CoreV1().Secrets(nsName).Update(ctx, next, meta.UpdateOptions{})
		if !initialBootstrapGuardDenial(e, guard) {
			t.Fatal("native history mutation not denied", e)
		}
		e = api.CoreV1().Secrets(nsName).Delete(ctx, saved.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &saved.UID}})
		if !initialBootstrapGuardDenial(e, guard) {
			t.Fatal("native original history deletion not denied", e)
		}
	})
	t.Log("actual native seed/guard/projection, one committed lost create, exact restart and metadata-only replay; SQL manager receipt synthetic, no SQL/provider effects")
}

type initialBootstrapPassiveTrace struct {
	mu                              sync.Mutex
	next                            http.RoundTripper
	seed, history                   string
	armed, lostLookup, metadataOnly bool
	posts, forbiddenFull            int
}

func (s *initialBootstrapPassiveTrace) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	if s.metadataOnly && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets/"+s.seed) && r.Header.Get("Accept") != "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1" {
		s.forbiddenFull++
		s.mu.Unlock()
		return nil, errors.New("fixture forbids broad seed read")
	}
	if s.lostLookup && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets/"+s.history) {
		s.lostLookup = false
		s.mu.Unlock()
		return nil, errors.New("fixture lost lookup reply")
	}
	armed := s.armed
	next := s.next
	s.mu.Unlock()
	historyCreate := false
	if armed && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/secrets") {
		body, e := io.ReadAll(io.LimitReader(r.Body, 256<<10))
		if e != nil {
			return nil, e
		}
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		var secret core.Secret
		historyCreate = json.Unmarshal(body, &secret) == nil && secret.Name == s.history
	}
	response, err := next.RoundTrip(r)
	if historyCreate {
		s.mu.Lock()
		s.posts++
		s.mu.Unlock()
		if err == nil && response.StatusCode == http.StatusCreated {
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			s.mu.Lock()
			s.armed = false
			s.lostLookup = true
			s.mu.Unlock()
			return nil, errors.New("fixture lost committed CREATE reply")
		}
	}
	return response, err
}

// ownedPolicyDenial reports an admission denial by one of the named policies.
func ownedPolicyDenial(err error, policies []string) bool {
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		return false
	}
	s := status.Status()
	if !(s.Code == 422 && s.Reason == meta.StatusReasonInvalid || s.Code == 403 && s.Reason == meta.StatusReasonForbidden) {
		return false
	}
	for _, policy := range policies {
		if strings.Contains(s.Message, "ValidatingAdmissionPolicy '"+policy+"' with binding '"+policy+"' denied request") {
			return true
		}
	}
	return false
}
