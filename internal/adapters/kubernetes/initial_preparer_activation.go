package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
)

func (s *InitialPreparer) ActivationPreparationEnabled() bool {
	return s != nil && s.plan.Continuation == contracts.InitialPreparationActivationProtocol
}
func preparationDigest(v any) string {
	b, _ := json.Marshal(v)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
func preparationDigestValid(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == v
}
func (s *InitialPreparer) validActivation(w contracts.InitialPreparationRoot) bool {
	a := w.Activation
	if a == nil {
		return true
	}
	if !s.validPublicInputs(w) || !s.validHandover(w) {
		return false
	}
	if !s.ActivationPreparationEnabled() || w.Phase == "declaring" || a.Pod == nil || !authorization.UUID(a.Pod.OperationID) {
		return false
	}
	want, e := BuildInitialInstallerWorkload(preparerWorkload(s.plan))
	if e != nil || a.Pod.TemplateDigest != preparationDigest(want.Pod) || !validPreparationPodRequests(*a.Pod) {
		return false
	}
	for _, v := range w.Creates {
		if v.OperationID == a.Pod.OperationID {
			return false
		}
	}
	if a.Pod.Receipt == nil {
		return a.Pod.SpecDigest == "" && a.Credentials == nil && a.Inputs == nil
	}
	if !validPreparerReceipt(a.Pod.Receipt) || !preparationDigestValid(a.Pod.SpecDigest) {
		return false
	}
	if c := a.Credentials; c != nil {
		if len(validation.IsDNS1123Subdomain(c.Material.Name)) != 0 || !authorization.UUID(c.Material.UID) || !preparationDigestValid(c.StartupDigest) || c.NotBefore.Location() != time.UTC || c.NotAfter.Location() != time.UTC || c.NotBefore.Year() < 2020 || !c.NotBefore.Equal(c.NotBefore.Truncate(time.Second)) || c.NotAfter.Sub(c.NotBefore) != 15*time.Minute {
			return false
		}
	}
	return true
}

// Normalize only the known optional defaults of the qualified Kubernetes Pod
// profile. Every remaining field must equal the closed compiled template.
// Admission-added sidecars, init containers, volumes, tokens, privileges,
// selectors, accounts and scheduling decisions are never accepted as defaults.
func normalizeInitialPodDefaults(s *core.PodSpec) {
	if s.DNSPolicy == core.DNSClusterFirst {
		s.DNSPolicy = ""
	}
	if s.SchedulerName == "default-scheduler" {
		s.SchedulerName = ""
	}
	if s.DeprecatedServiceAccount == s.ServiceAccountName {
		s.DeprecatedServiceAccount = ""
	}
	if s.Priority != nil && *s.Priority == 0 {
		s.Priority = nil
	}
	if s.PreemptionPolicy != nil && *s.PreemptionPolicy == core.PreemptLowerPriority {
		s.PreemptionPolicy = nil
	}
	if len(s.Tolerations) == 2 {
		found := map[string]bool{}
		for _, t := range s.Tolerations {
			if (t.Key == "node.kubernetes.io/not-ready" || t.Key == "node.kubernetes.io/unreachable") && t.Operator == core.TolerationOpExists && t.Value == "" && t.Effect == core.TaintEffectNoExecute && t.TolerationSeconds != nil && *t.TolerationSeconds == 300 {
				found[t.Key] = true
			}
		}
		if len(found) == 2 {
			s.Tolerations = nil
		}
	}
	for i := range s.Containers {
		if s.Containers[i].TerminationMessagePath == core.TerminationMessagePathDefault {
			s.Containers[i].TerminationMessagePath = ""
		}
		if s.Containers[i].TerminationMessagePolicy == core.TerminationMessageReadFile {
			s.Containers[i].TerminationMessagePolicy = ""
		}
	}
}
func (s *InitialPreparer) verifiedGatedPod(raw []byte, intent contracts.InitialPreparationPod) (contracts.InitialPreparationReceipt, string, error) {
	var zero contracts.InitialPreparationReceipt
	var pod core.Pod
	if permissionJSON(raw, 64<<10, 16384) != nil || strictGuardJSON(raw, &pod) != nil || pod.APIVersion != "v1" || pod.Kind != "Pod" || !s.creator.owns(pod.ObjectMeta, s.plan.Workload.Name) || pod.Namespace != s.plan.Workload.Namespace || len(pod.Annotations) != 3 || pod.Annotations[initialPreparationOperationAnnotation] != intent.OperationID || len(pod.Finalizers) != 0 || len(pod.OwnerReferences) != 0 || intent.Receipt != nil && intent.Receipt.UID != string(pod.UID) || pod.Spec.NodeName != "" || len(pod.Spec.SchedulingGates) != 1 || pod.Spec.SchedulingGates[0].Name != InitialInstallerSchedulingGate || pod.Status.Phase != "" && pod.Status.Phase != core.PodPending || pod.Status.StartTime != nil || len(pod.Status.ContainerStatuses) != 0 || len(pod.Status.InitContainerStatuses) != 0 || len(pod.Status.EphemeralContainerStatuses) != 0 {
		return zero, "", cfg.ErrChanged
	}
	want, e := BuildInitialInstallerWorkload(preparerWorkload(s.plan))
	if e != nil || !equalJSON(pod.Labels, want.Pod.Labels) {
		return zero, "", cfg.ErrChanged
	}
	actual := pod.Spec.DeepCopy()
	expected := want.Pod.Spec.DeepCopy()
	normalizeInitialPodDefaults(actual)
	normalizeInitialPodDefaults(expected)
	if !equalJSON(actual, expected) {
		return zero, "", cfg.ErrChanged
	}
	d := InstallationPodSpecDigest(pod.Spec)
	digest := hex.EncodeToString(d[:])
	if intent.Receipt != nil && intent.SpecDigest != digest {
		return zero, "", cfg.ErrChanged
	}
	return contracts.InitialPreparationReceipt{UID: string(pod.UID), ResourceVersion: pod.ResourceVersion}, digest, nil
}

// PrepareGatedPod is a separately opted-in initial-installation effect. The
// original continuity guard includes this Pod key before any POST. Repetition
// is possible only before a UID is recorded and only for the identical inert
// template/operation; a recorded UID, unknown mutation or changed plan is never
// replaced. This does not launch, issue credentials, consume a witness or prove
// that the namespace was historically clean.
func (s *InitialPreparer) PrepareGatedPod(ctx context.Context) (contracts.InitialPreparationRoot, error) {
	var zero contracts.InitialPreparationRoot
	if !s.ActivationPreparationEnabled() || ctx == nil {
		return zero, cfg.ErrInvalid
	}
	owned, joined, e := s.ownPodRequest(ctx)
	if e != nil {
		return zero, e
	}
	defer joined()
	ctx, end := context.WithTimeout(owned, 5*time.Second)
	defer end()
	if _, e := s.VerifyDeclared(ctx); e != nil {
		return zero, e
	}
	until, e := s.current(ctx)
	if e != nil {
		return zero, e
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	cm, w, e := s.read(ctx)
	if e != nil || w.Phase != "declared" || w.RootUID == "" {
		return zero, cfg.ErrChanged
	}
	want, e := BuildInitialInstallerWorkload(preparerWorkload(s.plan))
	if e != nil {
		return zero, e
	}
	if w.Activation == nil {
		operation, e := prepUUID()
		if e != nil {
			return zero, e
		}
		w.Activation = &contracts.InitialPreparationActivation{Pod: &contracts.InitialPreparationPod{OperationID: operation, TemplateDigest: preparationDigest(want.Pod), Requests: []contracts.InitialPreparationPodRequest{}}}
		if e = s.write(ctx, cm, w, until); e != nil {
			return zero, e
		}
		cm, w, e = s.read(ctx)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
	}
	intent := *w.Activation.Pod
	path := "/api/v1/namespaces/" + s.plan.Workload.Namespace + "/pods"
	raw, e := s.creator.raw(ctx, path+"/"+s.plan.Workload.Name, nil)
	if apierrors.IsNotFound(e) && intent.Receipt == nil {
		if createErr := s.createGatedPod(ctx, *want.Pod, until); createErr == cfg.ErrDenied || createErr == ErrInitialPreparationRequestsUnresolved {
			return zero, createErr
		}
		// Request claims/completions may have advanced the root. Never overwrite
		// a peer's records or issue a second CREATE from this stale snapshot.
		cm, w, e = s.read(ctx)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
		intent = *w.Activation.Pod
		raw, e = s.creator.raw(ctx, path+"/"+s.plan.Workload.Name, nil)
	}
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	receipt, digest, e := s.verifiedGatedPod(raw, intent)
	if e != nil {
		return zero, e
	}
	if e = s.finish(ctx, until); e != nil {
		return zero, e
	}
	if intent.Receipt != nil {
		return w, nil
	}
	w.Activation.Pod.Receipt = &receipt
	w.Activation.Pod.SpecDigest = digest
	if e = s.write(ctx, cm, w, until); e != nil {
		return zero, e
	}
	return w, nil
}
