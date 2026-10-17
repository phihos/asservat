package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	auth "k8s.io/api/authentication/v1"
	access "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// This is test-owned evidence observation, never product completion authority.
// One actual event retains only the fields needed to prove original retirement;
// private payloads are cleared without logging. Missing/compacted/closed watches
// fail; no completed state is reconstructed from the sanitized final seed.
type bootstrapRetirementEvidence struct {
	State                contracts.InitialBootstrapState
	UID, ResourceVersion string
	Err                  error
}
type bootstrapRetirementWatch struct {
	cancel context.CancelFunc
	watch  watch.Interface
	joined chan struct{}
	result chan bootstrapRetirementEvidence
}

func initialBootstrapWatchRetirement(t *testing.T, parent context.Context, api kubernetes.Interface, d contracts.InitialBootstrap) *bootstrapRetirementWatch {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	selector := "metadata.name=" + d.Name + "-bootstrap-state"
	list, err := api.CoreV1().Secrets(d.BootstrapNamespace).List(ctx, meta.ListOptions{FieldSelector: selector, Limit: 2})
	if err != nil || len(list.Items) != 0 || list.ResourceVersion == "" {
		cancel()
		t.Fatal("original seed watch requires exact fresh absence")
	}
	stream, err := api.CoreV1().Secrets(d.BootstrapNamespace).Watch(ctx, meta.ListOptions{FieldSelector: selector, ResourceVersion: list.ResourceVersion})
	if err != nil {
		cancel()
		t.Fatal("original seed watch unavailable")
	}
	out := &bootstrapRetirementWatch{cancel: cancel, watch: stream, joined: make(chan struct{}), result: make(chan bootstrapRetirementEvidence, 1)}
	go func() {
		defer close(out.joined)
		defer stream.Stop()
		fail := func() {
			out.result <- bootstrapRetirementEvidence{Err: errors.New("original positive seed event unavailable")}
		}
		uid, last := "", ""
		events := 0
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-stream.ResultChan():
				if !ok || event.Type == watch.Error || event.Type == watch.Deleted {
					fail()
					return
				}
				if event.Type != watch.Added && event.Type != watch.Modified {
					continue
				}
				events++
				if events > 128 {
					fail()
					return
				}
				seed, ok := event.Object.(*core.Secret)
				if !ok || seed.Name != d.Name+"-bootstrap-state" || seed.Namespace != d.BootstrapNamespace || seed.UID == "" || seed.ResourceVersion == "" || seed.ResourceVersion == last || uid != "" && uid != string(seed.UID) {
					fail()
					return
				}
				uid, last = string(seed.UID), seed.ResourceVersion
				raw := seed.Data["state.json"]
				if len(raw) == 0 || len(raw) > contracts.InitialBootstrapStateMaxBytes {
					for _, b := range seed.Data {
						clear(b)
					}
					fail()
					return
				}
				state, err := contracts.DecodeInitialBootstrapState(bytes.NewReader(raw))
				for _, b := range seed.Data {
					clear(b)
				}
				if err != nil {
					fail()
					return
				}
				if state.Manager == nil || state.Manager.Receipt == nil || state.Manager.RetiredAt == nil {
					continue
				}
				if state.SeedUID != uid || state.Prelude.CopyMarker == nil || state.Manager.Closing == nil || state.Passwords.Manager == "" || state.Projection == nil || state.PassiveHistory == nil || state.PassiveHistory.Receipt == nil {
					fail()
					return
				}
				// Retain one original manager password for its actual rejection assertion.
				// Other setup credentials/material never enter the evidence channel.
				state.Material = nil
				state.Passwords = contracts.InitialBootstrapPasswords{Manager: state.Passwords.Manager}
				out.result <- bootstrapRetirementEvidence{State: state, UID: uid, ResourceVersion: last}
				return
			}
		}
	}()
	return out
}
func (w *bootstrapRetirementWatch) Take(t *testing.T, ctx context.Context) bootstrapRetirementEvidence {
	t.Helper()
	select {
	case v := <-w.result:
		if v.Err != nil {
			t.Fatal(v.Err)
		}
		return v
	case <-ctx.Done():
		t.Fatal("original manager-retired event missing")
	}
	return bootstrapRetirementEvidence{}
}
func (w *bootstrapRetirementWatch) Close() {
	w.cancel()
	w.watch.Stop()
	<-w.joined
	select {
	case v := <-w.result:
		v.State.Passwords = contracts.InitialBootstrapPasswords{}
	default:
	}
}
func equalJSONForBootstrap(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func initialBootstrapVerifyCopyClosure(t *testing.T, ctx context.Context, api kubernetes.Interface, connection *rest.Config, d contracts.InitialBootstrap, original bootstrapRetirementEvidence) *core.Secret {
	t.Helper()
	seed, err := api.CoreV1().Secrets(d.BootstrapNamespace).Get(ctx, d.Name+"-bootstrap-state", meta.GetOptions{})
	if err != nil || string(seed.UID) != original.UID || seed.ResourceVersion == original.ResourceVersion || seed.Immutable == nil || !*seed.Immutable || len(seed.Data) != 1 || string(seed.Data["retired"]) != "true" {
		t.Fatal("original seed was not positively sanitized and frozen")
	}
	claim, err := contracts.DecodeInitialBootstrapCopyClaim(strings.NewReader(seed.Annotations["asservat.io/bootstrap-copy-claim"]))
	if err != nil || claim.Seed.UID != original.UID || claim.InstallationID != original.State.InstallationID || claim.ManagerCloseID != original.State.Manager.Closing.OperationID || !claim.ManagerRetiredAt.Equal(*original.State.Manager.RetiredAt) || claim.Until.Sub(claim.StartedAt) != contracts.InitialBootstrapCopyCleanupDuration || seed.Annotations["asservat.io/bootstrap-copy-complete"] == "" {
		t.Fatal("final cleanup changed original identity or interval")
	}
	d.Format = contracts.InitialBootstrapVersionedAuditFormat
	want, wantBinding, err := kube.InitialBootstrapCopyAdmission(d, claim)
	if err != nil {
		t.Fatal("fixed original tombstone contract", err)
	}
	p, err := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, want.Name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, wantBinding.Name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pr, err := contracts.DecodeInitialBootstrapCopyReceipt(strings.NewReader(seed.Annotations["asservat.io/bootstrap-copy-policy"]))
	if err != nil {
		t.Fatal(err)
	}
	br, err := contracts.DecodeInitialBootstrapCopyReceipt(strings.NewReader(seed.Annotations["asservat.io/bootstrap-copy-binding"]))
	if err != nil {
		t.Fatal(err)
	}
	if string(p.UID) != pr.UID || p.Generation != 1 || p.Status.ObservedGeneration != 1 || p.Status.TypeChecking == nil || len(p.Status.TypeChecking.ExpressionWarnings) != 0 || string(b.UID) != br.UID || b.ResourceVersion != br.ResourceVersion || !equalJSONForBootstrap(p.Spec.Validations, want.Spec.Validations) || !equalJSONForBootstrap(p.Spec.MatchConditions, want.Spec.MatchConditions) || b.Spec.PolicyName != want.Name {
		t.Fatal("exact original permanent tombstone differs")
	}
	for _, pair := range []struct {
		ref     contracts.WorkerObjectReference
		receipt string
	}{{claim.SQL, "asservat.io/bootstrap-copy-sql-removed"}, {claim.Provider, "asservat.io/bootstrap-copy-provider-removed"}} {
		receipt, e := contracts.DecodeInitialBootstrapCopyReceipt(strings.NewReader(seed.Annotations[pair.receipt]))
		if e != nil || receipt.UID != pair.ref.UID || receipt.ResourceVersion == "" {
			t.Fatal("original positive removal receipt missing")
		}
		if _, e = api.CoreV1().Secrets(d.BootstrapNamespace).Get(ctx, pair.ref.Name, meta.GetOptions{}); !apierrors.IsNotFound(e) {
			t.Fatal("managed setup copy remains or lookup unknown", e)
		}
		_, e = api.CoreV1().Secrets(d.BootstrapNamespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: pair.ref.Name}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"synthetic": []byte("recreation-must-fail")}}, meta.CreateOptions{DryRun: []string{meta.DryRunAll}})
		if !bootstrapCopyNativeDenial(e, want.Name) {
			t.Fatal("original names lack exact permanent recreation denial", e)
		}
	}
	// The bootstrap guard admits this exact dry-run only for its observation
	// account. An administrator probe matches both denials and therefore cannot
	// independently establish which policy the API chooses to report first.
	probe := initialBootstrapCopyObserver(t, ctx, api, connection, d, original)
	marker, e := probe.CoreV1().ConfigMaps(d.BootstrapNamespace).Get(ctx, d.Name+"-copy-closure-probe", meta.GetOptions{})
	if e != nil || original.State.Prelude.CopyMarker == nil || string(marker.UID) != original.State.Prelude.CopyMarker.UID {
		t.Fatal("original copy marker unavailable or replaced")
	}
	marker.Data["synthetic-closure-probe"] = "must-deny"
	if _, e = probe.CoreV1().ConfigMaps(d.BootstrapNamespace).Update(ctx, marker, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); !bootstrapCopyNativeDenial(e, want.Name) {
		t.Fatal("copy tombstone marker lacks exact independent denial", e)
	}
	// Unrelated administrator work is outside the fixed two-copy protection.
	if _, e = api.CoreV1().Secrets(d.BootstrapNamespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: d.Name + "-unrelated-copy-check"}, Data: map[string][]byte{"synthetic": []byte("bounded-dry-run")}}, meta.CreateOptions{DryRun: []string{meta.DryRunAll}}); e != nil {
		t.Fatal("copy tombstone broadened to unrelated names", e)
	}
	// Even the trusted administrator cannot recreate data inside the immutable
	// original seed.
	changed := seed.DeepCopy()
	changed.Data = map[string][]byte{"state.json": []byte("must-not-return")}
	if _, e := api.CoreV1().Secrets(d.BootstrapNamespace).Update(ctx, changed, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); e == nil {
		t.Fatal("sanitized seed was mutable")
	}
	return seed
}

// Test-owned observer authentication uses the original occupied account and
// immutable token anchor. It never inherits the administrator's client key,
// impersonation, exec plugin or credential wrapper.
func initialBootstrapCopyObserver(t *testing.T, ctx context.Context, api kubernetes.Interface, connection *rest.Config, d contracts.InitialBootstrap, original bootstrapRetirementEvidence) kubernetes.Interface {
	t.Helper()
	account := original.State.Prelude.Account
	anchor := original.State.Prelude.TokenAnchor
	actual, err := api.CoreV1().ServiceAccounts(d.BootstrapNamespace).Get(ctx, account.Name, meta.GetOptions{})
	if err != nil || string(actual.UID) != account.UID {
		t.Fatal("original observation account unavailable or replaced")
	}
	bound, err := api.CoreV1().Secrets(d.BootstrapNamespace).Get(ctx, anchor.Name, meta.GetOptions{})
	if err != nil || string(bound.UID) != anchor.UID || bound.Immutable == nil || !*bound.Immutable {
		t.Fatal("original observation anchor unavailable or replaced")
	}
	token, err := api.CoreV1().ServiceAccounts(d.BootstrapNamespace).CreateToken(ctx, account.Name, &auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: []string{d.ProbeAudience}, ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: anchor.Name, UID: bound.UID}}}, meta.CreateOptions{})
	if err != nil || token.Status.Token == "" {
		t.Fatal("original observation token unavailable")
	}
	probe, err := kubernetes.NewForConfig(&rest.Config{Host: connection.Host, BearerToken: token.Status.Token, TLSClientConfig: rest.TLSClientConfig{CAData: connection.CAData, CAFile: connection.CAFile, ServerName: connection.ServerName}})
	if err != nil {
		t.Fatal("observation client unavailable")
	}
	self, err := probe.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil || self.Status.UserInfo.Username != "system:serviceaccount:"+d.BootstrapNamespace+":"+account.Name || self.Status.UserInfo.UID != account.UID {
		t.Fatal("original observation identity differs")
	}
	return probe
}
func bootstrapCopyNativeDenial(err error, name string) bool {
	var status apierrors.APIStatus
	if !errors.As(err, &status) || status.Status().Details == nil {
		return false
	}
	expected := "ValidatingAdmissionPolicy '" + name + "' with binding '" + name + "' denied request: Asservat retired setup-copy names remain permanently occupied."
	for _, cause := range status.Status().Details.Causes {
		if cause.Message == expected {
			return true
		}
	}
	return false
}

// Actual API authorizer checks use the existing observation account's retained
// identity. They test RBAC, not token authentication or invented runtime roles.
func initialBootstrapCopyGuardRBAC(t *testing.T, ctx context.Context, api kubernetes.Interface, d contracts.InitialBootstrap, original bootstrapRetirementEvidence) {
	t.Helper()
	probe := original.State.Prelude.Account
	for _, resource := range []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"} {
		for _, verb := range []string{"create", "update", "patch", "delete"} {
			review, err := api.AuthorizationV1().SubjectAccessReviews().Create(ctx, &access.SubjectAccessReview{Spec: access.SubjectAccessReviewSpec{User: "system:serviceaccount:" + d.BootstrapNamespace + ":" + probe.Name, UID: probe.UID, Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + d.BootstrapNamespace, "system:authenticated"}, ResourceAttributes: &access.ResourceAttributes{Group: "admissionregistration.k8s.io", Version: "v1", Resource: resource, Name: d.BootstrapNamespace + "-" + d.Name + "-copy-tombstone", Verb: verb}}}, meta.CreateOptions{})
			if err != nil || review.Status.Allowed || review.Status.EvaluationError != "" {
				t.Fatal("observation account has admission mutation authority or unknown RBAC", resource, verb, err)
			}
		}
	}
}

// Kubernetes administrators remain the admission trust boundary. VAP explicitly
// excludes VAP/binding resources, so no second VAP can make these self-protecting.
// After completed replay, an actual administrator removal must stop any further
// product observation; the product must not adopt or recreate missing protection.
func initialBootstrapCopyAdministratorBoundary(t *testing.T, ctx context.Context, api kubernetes.Interface, config *rest.Config, d contracts.InitialBootstrap) {
	t.Helper()
	producer, err := kube.OpenInitialBootstrap(ctx, config, d)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	before, err := producer.ReadPassiveHistory(ctx)
	if err != nil || before == nil || !before.Copies.CopiesClosed() {
		t.Fatal("current exact copy protection unavailable", err)
	}
	name := d.BootstrapNamespace + "-" + d.Name + "-copy-tombstone"
	binding, err := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &binding.UID, ResourceVersion: &binding.ResourceVersion}}); err != nil {
		t.Fatal("trusted administrator trust-boundary exercise", err)
	}
	if after, err := producer.ReadPassiveHistory(ctx); err == nil || after != nil {
		t.Fatal("removed permanent guard still accepted for completed replay")
	}
	if _, err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, name, meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("product recreated missing original protection", err)
	}
}
